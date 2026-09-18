"""Local scan ledger — an append-only record of what was scanned, when.

One JSONL line per recorded scan at `~/.bastionskill/ledger.jsonl`. It answers
"have I scanned this before, and did it change since?" — the rug-pull signal:
same source, different content hash = the skill was modified after you vetted it.

Local and dependency-free. The line schema is deliberately flat so a remote sink
(e.g. Supabase) can later replay it without transformation.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import ScanReport, Skill

LEDGER_SCHEMA = "bastionskill.ledger/1"


def ledger_path() -> Path:
    return Path.home() / ".bastionskill" / "ledger.jsonl"


def _entries(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # tolerate a partially written / corrupt line
    return out


def last_for_source(source: str, path: Path | None = None) -> dict | None:
    """Most recent ledger entry for a source, or None."""
    p = path or ledger_path()
    match = [e for e in _entries(p) if e.get("source") == source]
    return match[-1] if match else None


def record(rep: ScanReport, skill: Skill, path: Path | None = None) -> dict:
    """Append a scan to the ledger. Returns the entry written."""
    p = path or ledger_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "schema": LEDGER_SCHEMA,
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": skill.source,
        "skill": rep.skill,
        "content_hash": skill.content_hash(),
        "verdict": "allow" if rep.ok else "deny",
        "risk": rep.risk,
        "counts": rep.counts(),
    }
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def drift(skill: Skill, path: Path | None = None) -> dict | None:
    """If this source was scanned before with a DIFFERENT hash, return the prior
    entry (a rug-pull signal). None if unseen or unchanged."""
    prev = last_for_source(skill.source, path)
    if prev and prev.get("content_hash") != skill.content_hash():
        return prev
    return None


def summary(path: Path | None = None) -> list[dict]:
    """Latest entry per source, most-recent first — the 'scanned skills' table."""
    p = path or ledger_path()
    latest: dict[str, dict] = {}
    for e in _entries(p):
        latest[e.get("source", "")] = e
    return sorted(latest.values(), key=lambda e: e.get("ts", ""), reverse=True)
