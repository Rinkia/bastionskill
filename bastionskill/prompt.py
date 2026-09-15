"""Prompt-layer check (optional, off by default).

v0.1 owns the code-layer. The prompt-layer (malicious SKILL.md instructions,
injection templates) is bastionsupply's job — it already ships those detectors and
the shared bastioncorpus. This module keeps only the one prompt-layer check that is
trivial in the stdlib — hidden / zero-width / bidi unicode in the SKILL.md text —
and defers everything richer to bastionsupply when it is installed.

Enable with `bastionskill scan --prompt <path>`.
"""

from __future__ import annotations

import unicodedata

from .models import Finding, Skill

# Zero-width and bidi-control code points used to hide or reorder text.
_HIDDEN = {
    "​", "‌", "‍", "﻿",  # zero-width space/joiner/BOM
    "‪", "‫", "‬", "‭", "‮",  # bidi overrides
    "⁦", "⁧", "⁨", "⁩",  # isolates
}


def scan_prompt_layer(skill: Skill) -> list[Finding]:
    text = skill.description
    out: list[Finding] = []
    hits = sorted({c for c in text if c in _HIDDEN})
    if hits:
        names = ", ".join(unicodedata.name(c, repr(c)) for c in hits)
        out.append(Finding(
            check="hidden-unicode", severity="high", file="SKILL.md",
            message=f"hidden/bidi unicode in description: {names}",
            evidence=text[:160],
        ))
    # Deeper injection detection lives in bastionsupply; use it if present.
    try:
        import bastionsupply  # noqa: F401
    except ImportError:
        out.append(Finding(
            check="prompt-layer-note", severity="low", file="SKILL.md",
            message="install bastionsupply for full prompt-layer injection scanning",
        ))
    return out
