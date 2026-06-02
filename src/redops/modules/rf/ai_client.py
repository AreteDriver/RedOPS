"""
AI Client for RF Operations Module.

Async client that sends RF analysis requests to a remote
Ollama instance (desktop) or falls back to OpenRouter.
Never transmits raw capture data — only metadata and patterns.
"""

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_OLLAMA_HOST = "http://localhost:11434"
_ENV_FILE = Path.home() / ".config" / "ollama-remote.env"
_BATCH_WINDOW_SECONDS = 5.0
_DEFAULT_MODEL = "llama3.1:8b"


def _load_ollama_host() -> str:
    """Load OLLAMA_HOST from environment or config file.

    Resolution order:
        1. OLLAMA_HOST environment variable
        2. ~/.config/ollama-remote.env file
        3. Default localhost
    """
    host = os.environ.get("OLLAMA_HOST")
    if host:
        return host.rstrip("/")

    if _ENV_FILE.exists():
        try:
            for line in _ENV_FILE.read_text().splitlines():
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip("\"'")
                if key == "OLLAMA_HOST" and value:
                    return value.rstrip("/")
        except OSError as exc:
            logger.warning(
                "Failed to read ollama env file %s: %s",
                _ENV_FILE,
                exc,
            )

    return _DEFAULT_OLLAMA_HOST


def _load_openrouter_config() -> tuple[str | None, str | None]:
    """Load OpenRouter fallback credentials from environment.

    Returns:
        Tuple of (base_url, api_key). Either may be None.
    """
    base_url = os.environ.get("OPENROUTER_BASE_URL")
    api_key = os.environ.get("OPENROUTER_API_KEY")
    return base_url, api_key


class AIClientError(Exception):
    """Raised when an AI request fails irrecoverably."""


class AIClient:
    """Async AI client for RF analysis via Ollama or OpenRouter.

    Sends structured metadata — never raw pcap data — to a remote
    LLM endpoint for prioritisation, anomaly detection, and attack
    strategy recommendations.

    Attributes:
        base_url: Resolved Ollama API base URL.
        timeout: HTTP request timeout in seconds.
        model: LLM model identifier.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: int = 30,
        model: str = _DEFAULT_MODEL,
    ) -> None:
        """Initialise the AI client.

        Args:
            base_url: Ollama API base URL. Resolved from env/config
                      if not provided.
            timeout: HTTP timeout in seconds.
            model: Model name for generation requests.
        """
        self.base_url: str = base_url or _load_ollama_host()
        self.timeout: int = timeout
        self.model: str = model

        self._client: httpx.AsyncClient = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout, connect=10.0),
        )

        # Fallback provider
        or_base, or_key = _load_openrouter_config()
        self._openrouter_base_url: str | None = or_base
        self._openrouter_api_key: str | None = or_key
        self._openrouter_client: httpx.AsyncClient | None = None

        # Batch queue
        self._batch_queue: asyncio.Queue[tuple[str, str, asyncio.Future[str]]] = (
            asyncio.Queue()
        )
        self._batch_task: asyncio.Task[None] | None = None

        logger.info(
            "AIClient initialised — base_url=%s model=%s",
            self.base_url,
            self.model,
        )

    # ------------------------------------------------------------------
    # Public analysis methods
    # ------------------------------------------------------------------

    async def analyze_scan(
        self,
        targets: list[dict[str, Any]],
        objective: str = "identify_priority_targets",
    ) -> dict[str, Any]:
        """Analyse discovered scan targets and prioritise them.

        Args:
            targets: List of target dicts containing keys such as
                     essid, bssid, encryption, signal, channel,
                     wps, clients.
            objective: Analysis objective string.

        Returns:
            Dict with ``recommendations`` list and ``confidence``
            scores from the LLM.
        """
        prompt = (
            "You are an expert RF security analyst.\n"
            f"Objective: {objective}\n\n"
            "Analyse the following wireless targets and return a "
            "JSON object with a 'recommendations' array. Each "
            "recommendation must include: bssid, priority (1-5), "
            "rationale, suggested_attack, and confidence (0.0-1.0)."
            "\n\nTargets:\n"
            f"{json.dumps(targets, indent=2)}"
        )
        system = (
            "You are a wireless security assessment AI. "
            "Respond ONLY with valid JSON. "
            "Never include raw capture data in your response."
        )

        raw = await self._send_request(prompt, system=system)
        return self._parse_json_response(raw)

    async def analyze_capture(
        self,
        capture_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyse capture metadata for attack strategy.

        Args:
            capture_info: Dict with keys such as type, target,
                          handshake_frames, pmkid_found, duration,
                          packet_count. Must NOT contain raw pcap.

        Returns:
            Dict with ``strategy``, ``next_steps``, and
            ``confidence`` fields.
        """
        prompt = (
            "You are an expert RF security analyst.\n"
            "Analyse this capture metadata and recommend an "
            "attack strategy. Return a JSON object with keys: "
            "strategy, next_steps (array), estimated_time, "
            "confidence (0.0-1.0), and notes.\n\n"
            "Capture metadata:\n"
            f"{json.dumps(capture_info, indent=2)}"
        )
        system = (
            "You are a wireless security assessment AI. "
            "Respond ONLY with valid JSON. "
            "Never request or include raw packet captures."
        )

        raw = await self._send_request(prompt, system=system)
        return self._parse_json_response(raw)

    async def analyze_anomaly(
        self,
        rf_patterns: dict[str, Any],
    ) -> dict[str, Any]:
        """Detect anomalies in RF pattern data.

        Args:
            rf_patterns: Dict with signal_history, channel_usage,
                         client_behaviour, deauth_counts, etc.

        Returns:
            Dict with ``anomalies`` list, each containing type,
            severity, description, and confidence.
        """
        prompt = (
            "You are an expert RF anomaly detection analyst.\n"
            "Analyse the following RF environment patterns and "
            "identify anomalies. Return a JSON object with an "
            "'anomalies' array. Each anomaly must include: type, "
            "severity (critical/high/medium/low/info), description, "
            "confidence (0.0-1.0), and recommended_action.\n\n"
            "RF patterns:\n"
            f"{json.dumps(rf_patterns, indent=2)}"
        )
        system = (
            "You are an RF environment anomaly detector. Respond ONLY with valid JSON."
        )

        raw = await self._send_request(prompt, system=system)
        return self._parse_json_response(raw)

    # ------------------------------------------------------------------
    # Health / availability
    # ------------------------------------------------------------------

    async def is_available(self) -> bool:
        """Quick health check against the remote Ollama API.

        Returns:
            True if the API responds within a short timeout.
        """
        try:
            resp = await self._client.get(
                "/api/tags",
                timeout=httpx.Timeout(5.0),
            )
            return resp.status_code == 200
        except (httpx.HTTPError, OSError):
            return False

    # ------------------------------------------------------------------
    # Batch support
    # ------------------------------------------------------------------

    async def enqueue_request(
        self,
        prompt: str,
        system: str = "",
    ) -> str:
        """Enqueue a request for batching within the batch window.

        Requests submitted within a ``_BATCH_WINDOW_SECONDS`` window
        are coalesced and sent sequentially to reduce connection churn.

        Args:
            prompt: User prompt text.
            system: Optional system prompt.

        Returns:
            LLM response text.
        """
        loop = asyncio.get_running_loop()
        future: asyncio.Future[str] = loop.create_future()
        await self._batch_queue.put((prompt, system, future))

        if self._batch_task is None or self._batch_task.done():
            self._batch_task = asyncio.create_task(self._process_batch())

        return await future

    async def _process_batch(self) -> None:
        """Drain the batch queue after the batch window elapses."""
        await asyncio.sleep(_BATCH_WINDOW_SECONDS)

        pending: list[tuple[str, str, asyncio.Future[str]]] = []
        while not self._batch_queue.empty():
            try:
                item = self._batch_queue.get_nowait()
                pending.append(item)
            except asyncio.QueueEmpty:
                break

        for prompt, system, future in pending:
            if future.cancelled():
                continue
            try:
                result = await self._send_request(prompt, system)
                future.set_result(result)
            except Exception as exc:
                future.set_exception(exc)

    # ------------------------------------------------------------------
    # Core request plumbing
    # ------------------------------------------------------------------

    async def _send_request(
        self,
        prompt: str,
        system: str = "",
    ) -> str:
        """Send a generation request to Ollama or fallback provider.

        Args:
            prompt: The user prompt.
            system: Optional system prompt prepended to the request.

        Returns:
            Raw response text from the LLM.

        Raises:
            AIClientError: If both primary and fallback fail.
        """
        # --- Try Ollama first ---
        try:
            return await self._send_ollama(prompt, system)
        except (httpx.HTTPError, OSError, httpx.TimeoutException) as exc:
            logger.warning(
                "Ollama request failed (%s), attempting fallback",
                exc,
            )

        # --- Fallback to OpenRouter ---
        if self._openrouter_base_url and self._openrouter_api_key:
            try:
                return await self._send_openrouter(prompt, system)
            except (httpx.HTTPError, OSError) as exc:
                logger.error("OpenRouter fallback also failed: %s", exc)

        raise AIClientError(
            "All AI providers unavailable. Check OLLAMA_HOST and "
            "OPENROUTER_BASE_URL / OPENROUTER_API_KEY."
        )

    async def _send_ollama(
        self,
        prompt: str,
        system: str,
    ) -> str:
        """POST to Ollama /api/generate endpoint.

        Args:
            prompt: User prompt.
            system: System prompt.

        Returns:
            Generated text.
        """
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system

        resp = await self._client.post(
            "/api/generate",
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("response", "")

    async def _send_openrouter(
        self,
        prompt: str,
        system: str,
    ) -> str:
        """POST to OpenRouter /api/v1/chat/completions.

        Args:
            prompt: User prompt.
            system: System prompt.

        Returns:
            Generated text.
        """
        if self._openrouter_client is None:
            self._openrouter_client = httpx.AsyncClient(
                base_url=self._openrouter_base_url or "",
                timeout=httpx.Timeout(self.timeout, connect=10.0),
            )

        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        resp = await self._openrouter_client.post(
            "/api/v1/chat/completions",
            json={
                "model": self.model,
                "messages": messages,
            },
            headers={
                "Authorization": f"Bearer {self._openrouter_api_key}",
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "")
        return ""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_json_response(raw: str) -> dict[str, Any]:
        """Best-effort parse of LLM JSON output.

        Strips markdown fences and attempts ``json.loads``.
        Falls back to wrapping raw text in a dict.

        Args:
            raw: Raw text from the LLM.

        Returns:
            Parsed dict.
        """
        text = raw.strip()
        # Strip markdown code fences
        if text.startswith("```"):
            lines = text.splitlines()
            lines = [line for line in lines if not line.strip().startswith("```")]
            text = "\n".join(lines).strip()

        try:
            result = json.loads(text)
            if isinstance(result, dict):
                return result
            return {"data": result}
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM JSON; returning raw")
            return {"raw_response": text}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close underlying HTTP clients."""
        await self._client.aclose()
        if self._openrouter_client is not None:
            await self._openrouter_client.aclose()
        logger.info("AIClient closed")

    async def __aenter__(self) -> "AIClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Async context manager exit."""
        await self.close()
