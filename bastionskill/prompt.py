"""Prompt-layer check (optional, off by default).

v0.1 owns the code-layer. The prompt-layer (malicious SKILL.md instructions,
injection templates) is bastionsupply's job — it already ships those detectors and
the shared bastioncorpus. Hidden / zero-width / bidi / tag characters in SKILL.md are
checked on EVERY scan (checks.scan_hidden_unicode, since 0.11); this module only
points at bastionsupply for the richer prompt-injection scan.

Enable with `bastionskill scan --prompt <path>`.
"""

from __future__ import annotations

from .models import Finding, Skill


def scan_prompt_layer(skill: Skill) -> list[Finding]:
    # Deeper injection detection lives in bastionsupply; use it if present.
    try:
        import bastionsupply  # noqa: F401
    except ImportError:
        return [Finding(
            check="prompt-layer-note", severity="low", file="SKILL.md",
            message="install bastionsupply for full prompt-layer injection scanning",
        )]
    return []
