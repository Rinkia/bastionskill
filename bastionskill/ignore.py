"""`.bastionskillignore` — skip files and suppress findings.

Format (gitignore-ish), one rule per line, blank lines and `#` comments skipped:

    scripts/vendor/*        # a bare glob: skip these files entirely
    suppress obfuscation    # drop every 'obfuscation' finding
    suppress network-egress scripts/known_client.py   # drop only for a path glob

Suppression is deliberately coarse — a vetted skill or a noisy check, not a
per-line waiver. Keep the file in the skill root (or pass a path).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding


@dataclass(frozen=True)
class _Suppress:
    check: str
    glob: str  # "" = all paths


@dataclass
class IgnoreRules:
    skip_globs: list[str] = field(default_factory=list)
    suppress: list[_Suppress] = field(default_factory=list)

    def skip_file(self, rel_path: str) -> bool:
        return any(fnmatch.fnmatch(rel_path, g) for g in self.skip_globs)

    def suppressed(self, f: Finding) -> bool:
        for s in self.suppress:
            if s.check != f.check:
                continue
            if not s.glob or fnmatch.fnmatch(f.file, s.glob):
                return True
        return False


def load(path: str | Path | None) -> IgnoreRules:
    rules = IgnoreRules()
    if path is None:
        return rules
    p = Path(path)
    if not p.is_file():
        return rules
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0] == "suppress" and len(parts) >= 2:
            rules.suppress.append(_Suppress(check=parts[1], glob=parts[2] if len(parts) > 2 else ""))
        else:
            rules.skip_globs.append(line)
    return rules
