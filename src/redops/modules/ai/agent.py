"""
Ollama ReAct agent — autonomous attack chain orchestration.

Reasons over attack surface, selects tools, executes, observes, repeats.
Runs entirely local via Ollama. No cloud calls.
"""

import json
import logging
import re
from typing import Any

from redops.core.context import Context
from redops.modules.active.authorization import assert_active_authorized
from redops.modules.active.egress import block_external_egress
from redops.modules.ai.planner import build_attack_surface_summary
from redops.modules.ai.tools import TOOL_REGISTRY, get_tool_descriptions

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger(__name__)

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_TIMEOUT = 120
MAX_ITERATIONS_DEFAULT = 10

SYSTEM_PROMPT = """You are an autonomous red team agent operating on an authorized home lab network.
Your job is to identify and chain vulnerabilities on the target network.

You operate in a ReAct loop:
1. THINK: Reason about the current attack surface
2. ACT: Choose one tool to call
3. OBSERVE: Review updated findings
4. Repeat until the chain is complete or no further actions are possible

Available tools:
{tools}

Response format (strict JSON, one action per turn):
{{
  "thought": "your reasoning about current state and next move",
  "action": "tool_name",
  "params": {{"param_key": "param_value"}}
}}

Or when complete:
{{
  "thought": "reasoning for completion",
  "action": "COMPLETE",
  "summary": "what was accomplished"
}}

Rules:
- Always start with scan_access_points if no APs are known
- Prioritize high-value targets (CVSS >= 9.0)
- Do not repeat actions already taken
- Maximum {max_iterations} iterations
"""


def run_agent(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Run the Ollama ReAct agent over current attack surface.

    Params:
        preset: Name of an AI_PRESETS entry (e.g. "qwen-uncensored").
            Resolves model/temperature/options; explicit params override.
        model: Ollama model name. Default: 'llama3.1:8b'
        temperature: Sampling temperature. Default: 0.7
        options: Extra Ollama runtime options (num_ctx, top_p, ...).
        max_iterations: Max agent steps. Default: 10

    Adds to context:
        agent_log: list of thought/action/observation entries
        agent_complete: bool
        agent_summary: str
    """
    assert_active_authorized(ctx)

    if not HAS_REQUESTS:
        ctx.log("requests library not installed", level="ERROR")
        ctx.add("agent_complete", False)
        return ctx

    params = params or {}

    preset_model: str | None = None
    preset_temperature: float | None = None
    preset_options: dict[str, Any] = {}
    preset_name = params.get("preset")
    if preset_name:
        try:
            from redops.modules.ai.presets import get_preset

            preset = get_preset(preset_name)
            preset_model = preset.get("model")
            preset_temperature = preset.get("temperature")
            preset_options = dict(preset.get("options", {}))
            ctx.log(f"Agent using preset: {preset_name}", level="INFO")
        except KeyError as exc:
            ctx.log(str(exc), level="ERROR")
            ctx.add("agent_complete", False)
            return ctx

    model = params.get("model") or preset_model or "llama3.1:8b"
    temperature = params.get(
        "temperature", preset_temperature if preset_temperature is not None else 0.7
    )
    options = {**preset_options, **params.get("options", {})}
    max_iterations = params.get("max_iterations", MAX_ITERATIONS_DEFAULT)

    agent_log: list[dict] = []
    system = SYSTEM_PROMPT.format(
        tools=get_tool_descriptions(),
        max_iterations=max_iterations,
    )

    ctx.log(
        f"Agent starting. Model: {model}, max iterations: {max_iterations}",
        level="INFO",
    )

    with block_external_egress():
        for iteration in range(max_iterations):
            attack_surface = build_attack_surface_summary(ctx)
            user_message = f"Iteration {iteration + 1}/{max_iterations}\n\n{attack_surface}"

            ctx.log(f"Agent iteration {iteration + 1}", level="INFO")

            response = _call_ollama(
                model, system, user_message, temperature=temperature, options=options
            )
            if not response:
                ctx.log("Ollama returned empty response", level="ERROR")
                break

            parsed = _parse_agent_response(response)
            if not parsed:
                ctx.log(
                    f"Could not parse agent response: {response[:200]}",
                    level="ERROR",
                )
                break

            thought = parsed.get("thought", "")
            action = parsed.get("action", "")
            action_params = parsed.get("params", {})

            ctx.log(f"Agent thought: {thought}", level="INFO")
            ctx.log(f"Agent action: {action} | params: {action_params}", level="INFO")

            agent_log.append(
                {
                    "iteration": iteration + 1,
                    "thought": thought,
                    "action": action,
                    "params": action_params,
                }
            )

            if action == "COMPLETE":
                ctx.add("agent_complete", True)
                ctx.add(
                    "agent_summary",
                    parsed.get("summary", "Agent completed chain."),
                )
                ctx.log(f"Agent complete: {parsed.get('summary')}", level="INFO")
                break

            if action in TOOL_REGISTRY:
                tool_fn = TOOL_REGISTRY[action]["fn"]
                ctx = tool_fn(ctx, action_params)
                ctx.log(f"Tool {action} executed", level="INFO")
            else:
                ctx.log(f"Unknown tool: {action}", level="WARNING")

    ctx.add("agent_log", agent_log)
    if not ctx.get("agent_complete"):
        ctx.add("agent_complete", False)
        ctx.add("agent_summary", "Max iterations reached.")

    return ctx


def _call_ollama(
    model: str,
    system: str,
    user_message: str,
    temperature: float = 0.7,
    options: dict[str, Any] | None = None,
) -> str:
    """Call local Ollama API and return raw response text."""
    try:
        merged_options = {"temperature": temperature, **(options or {})}
        payload = {
            "model": model,
            "system": system,
            "prompt": user_message,
            "stream": False,
            "format": "json",
            "options": merged_options,
        }
        response = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        return data.get("response", "")
    except requests.RequestException as exc:
        logger.error("Ollama request failed: %s", exc)
        return ""


def _parse_agent_response(response: str) -> dict | None:
    """Parse JSON from agent response, handle malformed output."""
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", response)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                return None
    return None
