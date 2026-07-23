"""Scan storage abstraction for RedOPS web API.

Supports in-memory (default) and Redis backends for multi-instance deployments.
"""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from typing import Any

try:
    from redis.exceptions import ConnectionError as RedisConnectionError, TimeoutError as RedisTimeoutError
    _REDIS_ERRORS = (RedisConnectionError, RedisTimeoutError)
except ImportError:
    _REDIS_ERRORS = ()

logger = logging.getLogger(__name__)


class ScanStoreBackend(ABC):
    """Abstract backend for scan storage."""

    @abstractmethod
    def get_scan(self, scan_id: str):
        ...

    @abstractmethod
    def list_scans(self):
        ...

    @abstractmethod
    def set_scan(self, scan_id: str, status) -> None:
        ...

    @abstractmethod
    def get_results(self, scan_id: str):
        ...

    @abstractmethod
    def set_results(self, scan_id: str, results: dict) -> None:
        ...

    @abstractmethod
    def get_triage(self, key: str):
        ...

    @abstractmethod
    def set_triage(self, key: str, triage: dict) -> None:
        ...

    @abstractmethod
    def get_baseline(self, target: str) -> str | None:
        ...

    @abstractmethod
    def set_baseline(self, target: str, scan_id: str) -> None:
        ...

    @abstractmethod
    def get_ai_costs(self) -> dict[str, Any]:
        ...

    @abstractmethod
    def increment_ai_costs(self, costs: dict[str, Any]) -> None:
        ...

    @abstractmethod
    def clear(self) -> None:
        """Clear all stored data. Useful for testing."""
        ...

class MemoryScanStore(ScanStoreBackend):
    """In-memory scan storage backend."""

    def __init__(self) -> None:
        self._scans = {}
        self._scan_results = {}
        self._finding_triage = {}
        self._baselines = {}
        self._ai_cost_tracker = {
            "calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "estimated_cost_usd": 0.0,
        }

    def get_scan(self, scan_id: str):
        return self._scans.get(scan_id)

    def list_scans(self):
        return list(self._scans.values())

    def set_scan(self, scan_id: str, status) -> None:
        self._scans[scan_id] = status

    def get_results(self, scan_id: str):
        return self._scan_results.get(scan_id)

    def set_results(self, scan_id: str, results: dict) -> None:
        self._scan_results[scan_id] = results

    def get_triage(self, key: str):
        return self._finding_triage.get(key)

    def set_triage(self, key: str, triage: dict) -> None:
        self._finding_triage[key] = triage

    def get_baseline(self, target: str) -> str | None:
        return self._baselines.get(target)

    def set_baseline(self, target: str, scan_id: str) -> None:
        self._baselines[target] = scan_id

    def get_ai_costs(self) -> dict[str, Any]:
        return self._ai_cost_tracker.copy()

    def increment_ai_costs(self, costs: dict[str, Any]) -> None:
        self._ai_cost_tracker["calls"] += costs.get("calls", 0)
        self._ai_cost_tracker["input_tokens"] += costs.get("input_tokens", 0)
        self._ai_cost_tracker["output_tokens"] += costs.get("output_tokens", 0)
        self._ai_cost_tracker["estimated_cost_usd"] += costs.get("estimated_cost_usd", 0.0)

    def clear(self) -> None:
        self._scans.clear()
        self._scan_results.clear()
        self._finding_triage.clear()
        self._baselines.clear()
        self._ai_cost_tracker.update(
            {"calls": 0, "input_tokens": 0, "output_tokens": 0, "estimated_cost_usd": 0.0}
        )

class RedisScanStore(ScanStoreBackend):
    """Redis-backed scan storage backend.

    Requires redis-py package and a running Redis server.
    Falls back to memory if Redis is unavailable.
    """

    PREFIX = "redops:scanstore:"
    SCANS_KEY = PREFIX + "scans"
    RESULTS_KEY = PREFIX + "results"
    TRIAGE_KEY = PREFIX + "triage"
    BASELINES_KEY = PREFIX + "baselines"
    AI_COSTS_KEY = PREFIX + "ai_costs"

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        redis_auth: str | None = None,
    ) -> None:
        self._client = None
        try:
            import redis as redis_lib

            kwargs = dict(host=host, port=port, db=db, decode_responses=True, socket_connect_timeout=2)
            if redis_auth:
                kwargs["password"] = redis_auth
            self._client = redis_lib.Redis(**kwargs)
            self._client.ping()
            logger.info("RedisScanStore connected to %s:%s", host, port)
        except ImportError:
            logger.warning("redis package not installed, falling back to memory store")
            self._client = None
        except (ConnectionError, TimeoutError, OSError) + _REDIS_ERRORS as e:
            logger.warning("Redis connection failed (%s), falling back to memory store", e)
            self._client = None

        if self._client is None:
            self._fallback = MemoryScanStore()
        else:
            self._fallback = None

    def get_scan(self, scan_id: str):
        if self._fallback:
            return self._fallback.get_scan(scan_id)
        data = self._client.hget(self.SCANS_KEY, scan_id)
        if data is None:
            return None
        from redops.web.app import ScanStatus
        return ScanStatus.model_validate_json(data)

    def list_scans(self):
        if self._fallback:
            return self._fallback.list_scans()
        data = self._client.hgetall(self.SCANS_KEY)
        from redops.web.app import ScanStatus
        return [ScanStatus.model_validate_json(v) for v in data.values()]

    def set_scan(self, scan_id: str, status) -> None:
        if self._fallback:
            self._fallback.set_scan(scan_id, status)
            return
        self._client.hset(self.SCANS_KEY, scan_id, status.model_dump_json())

    def get_results(self, scan_id: str):
        if self._fallback:
            return self._fallback.get_results(scan_id)
        data = self._client.hget(self.RESULTS_KEY, scan_id)
        if data is None:
            return None
        return json.loads(data)

    def set_results(self, scan_id: str, results: dict) -> None:
        if self._fallback:
            self._fallback.set_results(scan_id, results)
            return
        self._client.hset(self.RESULTS_KEY, scan_id, json.dumps(results))

    def get_triage(self, key: str):
        if self._fallback:
            return self._fallback.get_triage(key)
        data = self._client.hget(self.TRIAGE_KEY, key)
        if data is None:
            return None
        return json.loads(data)

    def set_triage(self, key: str, triage: dict) -> None:
        if self._fallback:
            self._fallback.set_triage(key, triage)
            return
        self._client.hset(self.TRIAGE_KEY, key, json.dumps(triage))

    def get_baseline(self, target: str) -> str | None:
        if self._fallback:
            return self._fallback.get_baseline(target)
        return self._client.hget(self.BASELINES_KEY, target)

    def set_baseline(self, target: str, scan_id: str) -> None:
        if self._fallback:
            self._fallback.set_baseline(target, scan_id)
            return
        self._client.hset(self.BASELINES_KEY, target, scan_id)

    def get_ai_costs(self) -> dict[str, Any]:
        if self._fallback:
            return self._fallback.get_ai_costs()
        data = self._client.get(self.AI_COSTS_KEY)
        if data is None:
            return {"calls": 0, "input_tokens": 0, "output_tokens": 0, "estimated_cost_usd": 0.0}
        return json.loads(data)

    def increment_ai_costs(self, costs: dict[str, Any]) -> None:
        if self._fallback:
            self._fallback.increment_ai_costs(costs)
            return
        pipe = self._client.pipeline()
        pipe.hincrbyfloat(self.AI_COSTS_KEY + ":hash", "estimated_cost_usd", costs.get("estimated_cost_usd", 0.0))
        pipe.hincrby(self.AI_COSTS_KEY + ":hash", "calls", costs.get("calls", 0))
        pipe.hincrby(self.AI_COSTS_KEY + ":hash", "input_tokens", costs.get("input_tokens", 0))
        pipe.hincrby(self.AI_COSTS_KEY + ":hash", "output_tokens", costs.get("output_tokens", 0))
        pipe.execute()

    def clear(self) -> None:
        if self._fallback:
            self._fallback.clear()
            return
        for key in (
            self.SCANS_KEY,
            self.RESULTS_KEY,
            self.TRIAGE_KEY,
            self.BASELINES_KEY,
            self.AI_COSTS_KEY,
            self.AI_COSTS_KEY + ":hash",
        ):
            self._client.delete(key)

class ScanStore:
    """Unified scan storage interface.

    Automatically selects Redis if REDIS_HOST is set and reachable,
    otherwise falls back to in-memory storage.
    """

    _instance = None

    def __init__(self, backend=None) -> None:
        if backend is None:
            backend = self._create_backend()
        self._backend = backend

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        cls._instance = None

    @staticmethod
    def _create_backend():
        redis_host = os.environ.get("REDIS_HOST")
        if redis_host:
            return RedisScanStore(
                host=redis_host,
                port=int(os.environ.get("REDIS_PORT", "6379")),
                db=int(os.environ.get("REDIS_DB", "0")),
                redis_auth=os.environ.get("REDIS_AUTH"),
            )
        return MemoryScanStore()

    def get_scan(self, scan_id: str):
        return self._backend.get_scan(scan_id)

    def list_scans(self):
        return self._backend.list_scans()

    def set_scan(self, scan_id: str, status) -> None:
        self._backend.set_scan(scan_id, status)

    def get_results(self, scan_id: str):
        return self._backend.get_results(scan_id)

    def set_results(self, scan_id: str, results: dict) -> None:
        self._backend.set_results(scan_id, results)

    def get_triage(self, key: str):
        return self._backend.get_triage(key)

    def set_triage(self, key: str, triage: dict) -> None:
        self._backend.set_triage(key, triage)

    def get_baseline(self, target: str) -> str | None:
        return self._backend.get_baseline(target)

    def set_baseline(self, target: str, scan_id: str) -> None:
        self._backend.set_baseline(target, scan_id)

    def get_ai_costs(self) -> dict[str, Any]:
        return self._backend.get_ai_costs()

    def increment_ai_costs(self, costs: dict[str, Any]) -> None:
        self._backend.increment_ai_costs(costs)

    def clear(self) -> None:
        self._backend.clear()
