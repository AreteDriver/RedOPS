"""Canonical model identifiers shared across RedOPS AI workloads.

Single source of truth for the default abliterated (open-weights, safety-
stripped) model. Both the RF analysis client (modules/rf/ai_client.py) and
the ReAct agent presets (modules/ai/presets.py) resolve their default from
here so the two paths can never silently diverge again.

Kept dependency-free (stdlib only) so modules/rf can import it without
dragging in click/httpx, matching why presets.py lives under modules/ai/.

Sizing note (single 24GB card): the 14B abliterated quant is ~9GB and
leaves ample headroom for the KV cache at num_ctx 16384. The 32B variant
is ~20GB and is a workstation opt-in, not a safe default. The HauhauCS
Qwen3.6 35B-A3B build is ~31GB total and exceeds a single 24GB card; it
remains an explicit, separately-named preset only.
"""

from __future__ import annotations

import os

# Canonical abliterated default. Qwen3 14B chosen over Qwen2.5 14B: same
# VRAM (~9GB), stronger reasoning / attack-path inference.
ABLITERATED_DEFAULT_SLUG = "huihui_ai/qwen3-abliterated:14b"

# Canonical override env var for the abliterated default, used everywhere.
ABLITERATED_MODEL_ENV = "REDOPS_ABLITERATED_MODEL"


def default_abliterated_model() -> str:
    """Resolve the default abliterated model slug.

    Resolution order:
        1. REDOPS_ABLITERATED_MODEL  (canonical override)
        2. ABLITERATED_DEFAULT_SLUG  (built-in default)
    """
    return os.environ.get(ABLITERATED_MODEL_ENV, ABLITERATED_DEFAULT_SLUG)
