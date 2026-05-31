"""AI configuration presets for RedOPS workloads.

Lives under modules/ai/ (not cli/) so the ReAct agent can resolve a preset
without dragging in click/httpx via the cli package's __init__. The CLI
settings menu re-exports these symbols for its menu.

Each preset bundles provider + model + sampling/runtime params tuned for
a specific task. The "qwen-uncensored*" presets target huihui_ai's
abliterated Qwen builds — useful on authorized red-team engagements where
aligned models refuse to draft payloads, phishing pretexts, or full
exploit chains. Authorization is enforced upstream (target allowlist,
tenant scope); the preset itself applies no guardrail.

The "qwen3.6-aggressive" preset points at the HauhauCS abliterated
Qwen3.6 35B-A3B build that ships pulled on the reference workstation; the
"huihui_ai/*" presets are an aspirational catalog and require an
`ollama pull` before first use.

Sampling rationale:
  temperature 0.2-0.3  abliterated Qwen drifts off the strict ReAct JSON
                       format at higher temps; low temp keeps tool calls
                       parseable while still varying payload content.
  top_p 0.9            standard nucleus sampling.
  repeat_penalty 1.1   discourages the loop-on-itself failure mode the
                       agent hits at max_iterations.
  num_ctx 16384        fits a deep attack-surface summary + ReAct history.
  num_predict 2048     one ReAct step (thought+action+params) fits well
                       under this; large enough for a full payload body.
"""

from typing import Any


AI_PRESETS: dict[str, dict[str, Any]] = {
    "qwen-uncensored": {
        "name": "Qwen Uncensored (default, 14B)",
        "description": (
            "Abliterated Qwen 2.5 14B via Ollama. Balanced VRAM/quality "
            "pick for the ReAct agent, payload generation, and pretext "
            "drafting on authorized engagements."
        ),
        "provider": "ollama",
        "model": "huihui_ai/qwen2.5-abliterated:14b",
        "temperature": 0.3,
        "max_tokens": 2048,
        "options": {
            "num_ctx": 16384,
            "top_p": 0.9,
            "repeat_penalty": 1.1,
        },
    },
    "qwen-uncensored-small": {
        "name": "Qwen Uncensored (7B, laptop)",
        "description": (
            "Abliterated Qwen 2.5 7B. Runs on ~8GB VRAM; lower tool-call "
            "fidelity, expect more ReAct retries."
        ),
        "provider": "ollama",
        "model": "huihui_ai/qwen2.5-abliterated:7b",
        "temperature": 0.2,
        "max_tokens": 1536,
        "options": {
            "num_ctx": 8192,
            "top_p": 0.9,
            "repeat_penalty": 1.1,
        },
    },
    "qwen-uncensored-large": {
        "name": "Qwen Uncensored (32B, workstation)",
        "description": (
            "Abliterated Qwen 2.5 32B. Best tool-use adherence and "
            "exploit-chain reasoning; needs ~24GB VRAM."
        ),
        "provider": "ollama",
        "model": "huihui_ai/qwen2.5-abliterated:32b",
        "temperature": 0.3,
        "max_tokens": 4096,
        "options": {
            "num_ctx": 32768,
            "top_p": 0.9,
            "repeat_penalty": 1.05,
        },
    },
    "qwen3-uncensored": {
        "name": "Qwen3 Uncensored (14B)",
        "description": (
            "Abliterated Qwen3 14B. Stronger reasoning than Qwen2.5 at "
            "the same size; preferred for attack-path inference."
        ),
        "provider": "ollama",
        "model": "huihui_ai/qwen3-abliterated:14b",
        "temperature": 0.3,
        "max_tokens": 2048,
        "options": {
            "num_ctx": 16384,
            "top_p": 0.9,
            "repeat_penalty": 1.1,
        },
    },
    "qwen3.6-aggressive": {
        "name": "Qwen3.6 Aggressive (35B-A3B, installed)",
        "description": (
            "HauhauCS abliterated Qwen3.6 35B-A3B (Q6_K_P). The locally "
            "pulled, preferred red-team model — A3B MoE keeps inference "
            "fast despite the 35B total (~31GB). Strongest exploit-chain "
            "and pretext reasoning of the presets; the only one that "
            "resolves out-of-the-box on the reference workstation."
        ),
        "provider": "ollama",
        "model": (
            "hf.co/HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive:Q6_K_P"
        ),
        "temperature": 0.3,
        "max_tokens": 2048,
        "options": {
            "num_ctx": 16384,
            "top_p": 0.9,
            "repeat_penalty": 1.1,
        },
    },
}


def get_preset(name: str) -> dict[str, Any]:
    """Return preset config by name. Raises KeyError if unknown."""
    if name not in AI_PRESETS:
        raise KeyError(
            f"Unknown AI preset: {name!r}. Available: {', '.join(sorted(AI_PRESETS))}"
        )
    return AI_PRESETS[name]
