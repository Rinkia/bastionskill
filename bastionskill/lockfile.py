"""`lock` / `verify`: pin a folder of skills, fail CI when one changes.

`lock` records, per skill, the `tree_digest` of every file it ships (the same digest
`install` and `harden` use) plus its scan verdict at lock time, into a committed
`skill.lock`. `verify` recomputes the digests and reports skills that were added,
removed or changed since: any of those fails, so an update can't land unreviewed
(re-scan, then `lock` again to accept it). Same shape as bastionsupply's tool lock.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

SCHEMA = "bastionskill.lock/1"


def make_lock(entries: dict[str, tuple[str, str]]) -> dict:
    """entries: key -> (digest, verdict). Keys are sorted so the file diffs cleanly."""
    return {"schema": SCHEMA,
            "skills": {k: {"digest": d, "verdict": v} for k, (d, v) in sorted(entries.items())}}


def write_lock(lock: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(lock, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_lock(path: str | Path) -> dict:
    lock = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(lock, dict) or lock.get("schema") != SCHEMA or not isinstance(lock.get("skills"), dict):
        raise ValueError(f"{path}: not a {SCHEMA} file")
    return lock


@dataclass(frozen=True)
class Drift:
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[str, ...]

    @property
    def clean(self) -> bool:
        return not (self.added or self.removed or self.changed)


def verify(current: dict[str, str], lock: dict) -> Drift:
    """current: key -> digest now."""
    old = {k: v.get("digest") for k, v in lock["skills"].items()}
    return Drift(
        added=tuple(sorted(k for k in current if k not in old)),
        removed=tuple(sorted(k for k in old if k not in current)),
        changed=tuple(sorted(k for k in current if k in old and current[k] != old[k])),
    )
