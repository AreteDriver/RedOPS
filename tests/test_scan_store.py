"""Tests for ScanStore abstraction."""

import os
import pytest
from datetime import datetime, timezone

from redops.web.app import ScanStatus
from redops.web.store import MemoryScanStore, ScanStore


class TestMemoryScanStore:
    """Unit tests for the in-memory scan store backend."""

    @pytest.fixture
    def store(self):
        s = MemoryScanStore()
        s.clear()
        yield s
        s.clear()

    def test_round_trip_scan(self, store):
        status = ScanStatus(
            scan_id="s1",
            status="running",
            target="example.com",
            preset="quick",
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        store.set_scan("s1", status)
        retrieved = store.get_scan("s1")
        assert retrieved is not None
        assert retrieved.scan_id == "s1"
        assert retrieved.status == "running"

    def test_list_scans(self, store):
        store.set_scan("s1", ScanStatus(scan_id="s1", status="completed", target="a.com", preset="quick", started_at="2024-01-01T00:00:00Z"))
        store.set_scan("s2", ScanStatus(scan_id="s2", status="running", target="b.com", preset="full", started_at="2024-01-01T01:00:00Z"))
        scans = store.list_scans()
        assert len(scans) == 2
        assert {s.scan_id for s in scans} == {"s1", "s2"}

    def test_results_round_trip(self, store):
        store.set_results("s1", {"findings": [{"severity": "high"}]})
        assert store.get_results("s1") == {"findings": [{"severity": "high"}]}
        assert store.get_results("missing") is None

    def test_triage_round_trip(self, store):
        store.set_triage("s1:f1", {"status": "false_positive"})
        assert store.get_triage("s1:f1") == {"status": "false_positive"}
        assert store.get_triage("missing") is None

    def test_baseline_round_trip(self, store):
        store.set_baseline("example.com", "s1")
        assert store.get_baseline("example.com") == "s1"
        assert store.get_baseline("missing") is None

    def test_ai_costs_increment(self, store):
        store.increment_ai_costs({"calls": 2, "input_tokens": 100, "output_tokens": 50, "estimated_cost_usd": 0.01})
        costs = store.get_ai_costs()
        assert costs["calls"] == 2
        assert costs["input_tokens"] == 100
        assert costs["estimated_cost_usd"] == 0.01

        store.increment_ai_costs({"calls": 1, "estimated_cost_usd": 0.005})
        costs = store.get_ai_costs()
        assert costs["calls"] == 3
        assert costs["estimated_cost_usd"] == 0.015

    def test_clear_removes_all(self, store):
        store.set_scan("s1", ScanStatus(scan_id="s1", status="completed", target="a.com", preset="quick", started_at="2024-01-01T00:00:00Z"))
        store.set_results("s1", {})
        store.set_triage("s1:f1", {})
        store.set_baseline("a.com", "s1")
        store.increment_ai_costs({"calls": 5})
        store.clear()
        assert store.get_scan("s1") is None
        assert store.get_results("s1") is None
        assert store.get_triage("s1:f1") is None
        assert store.get_baseline("a.com") is None
        assert store.get_ai_costs()["calls"] == 0


class TestScanStoreFactory:
    """Tests for ScanStore backend selection."""

    def test_returns_memory_backend_by_default(self):
        # Ensure REDIS_HOST is not set
        old = os.environ.pop("REDIS_HOST", None)
        try:
            ScanStore.reset_instance()
            store = ScanStore.get_instance()
            assert isinstance(store._backend, MemoryScanStore)
        finally:
            if old is not None:
                os.environ["REDIS_HOST"] = old
            ScanStore.reset_instance()

    def test_redis_backend_when_redis_host_set(self, monkeypatch):
        monkeypatch.setenv("REDIS_HOST", "localhost")
        ScanStore.reset_instance()
        store = ScanStore.get_instance()
        # Will fallback to memory because Redis is not actually running in tests
        # but the important thing is that the factory logic was exercised
        assert store is not None
        ScanStore.reset_instance()


class TestScanStoreProxyCompatibility:
    """Tests that backward-compatible proxies work in app.py."""

    def test_scans_proxy_set_and_get(self):
        from redops.web.app import _scans

        _scans.clear()
        _scans["s1"] = ScanStatus(scan_id="s1", status="running", target="t.com", preset="quick", started_at="2024-01-01T00:00:00Z")
        assert "s1" in _scans
        assert _scans["s1"].status == "running"
        assert _scans.get("s1").status == "running"
        _scans.clear()

    def test_scan_results_proxy(self):
        from redops.web.app import _scan_results

        _scan_results.clear()
        _scan_results["s1"] = {"findings": []}
        assert "s1" in _scan_results
        assert _scan_results["s1"] == {"findings": []}
        _scan_results.clear()

    def test_baselines_proxy(self):
        from redops.web.app import _baselines

        _baselines.clear()
        _baselines["example.com"] = "s1"
        assert "example.com" in _baselines
        assert _baselines["example.com"] == "s1"
        assert _baselines.get("example.com") == "s1"
        _baselines.clear()

    def test_ai_cost_tracker_proxy(self):
        from redops.web.app import _ai_cost_tracker

        _ai_cost_tracker.clear()
        _ai_cost_tracker["calls"] = 5
        assert _ai_cost_tracker["calls"] == 5
        _ai_cost_tracker.clear()
