"""Load a skill directory into a `Skill` model.

Reads SKILL.md (frontmatter `description`) and collects the bundled source files
that would execute when the skill runs. No network, no code execution — pure read.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import Skill, SourceFile

# Extensions we treat as executable code worth scanning, mapped to a language tag.
_LANG_BY_EXT = {
    ".py": "python",
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "bash",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",  # close enough for regex heuristics
    ".ps1": "other",
    ".rb": "other",
    ".pl": "other",
}

# Skip obvious non-code and heavy dirs.
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}

_FRONTMATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_DESC = re.compile(r"^description:\s*(.+?)\s*$", re.MULTILINE)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _parse_description(skill_md: str) -> str:
    m = _FRONTMATTER.match(skill_md)
    if not m:
        return ""
    d = _DESC.search(m.group(1))
    return d.group(1).strip() if d else ""


def load_skill(root: str | Path, name: str | None = None) -> Skill:
    """Load the skill rooted at `root`.

    `root` may be the dir holding SKILL.md, or a parent — the first SKILL.md
    found (breadth-first) wins.
    """
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"no such path: {root}")

    skill_md = _find_skill_md(root)
    description = _parse_description(_read(skill_md)) if skill_md else ""
    base = skill_md.parent if skill_md else root

    files: list[SourceFile] = []
    for p in sorted(base.rglob("*")):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        lang = _LANG_BY_EXT.get(p.suffix.lower())
        if lang is None:
            continue
        rel = p.relative_to(base).as_posix()
        files.append(SourceFile(path=rel, text=_read(p), lang=lang))

    return Skill(
        name=name or base.name,
        description=description,
        files=tuple(files),
        source=str(root),
    )


def _find_skill_md(root: Path) -> Path | None:
    if (root / "SKILL.md").is_file():
        return root / "SKILL.md"
    matches = sorted(
        p for p in root.rglob("SKILL.md")
        if p.is_file() and not any(part in _SKIP_DIRS for part in p.parts)
    )
    return matches[0] if matches else None
