"""Load a skill directory into a `Skill` model.

Reads SKILL.md (frontmatter `description`), collects bundled source files, and
records bundled *opaque* files (compiled or binary artifacts we cannot statically
read — a common poisoning bypass). No network, no code execution — pure read.
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

# Bundled artifacts that execute/load but cannot be read as source -> flagged.
_OPAQUE_EXTS = {
    ".exe", ".dll", ".so", ".dylib", ".pyc", ".pyd", ".wasm", ".bin",
    ".o", ".a", ".jar", ".class", ".node", ".msi", ".apk", ".deb", ".dmg",
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


# Magic bytes of executable/loadable formats. Catches a binary even when it has
# been renamed to look benign, while NOT flagging images/fonts/data (which carry
# their own magic and legitimately appear in skills).
_EXEC_MAGIC = (
    b"\x7fELF",          # ELF (Linux)
    b"MZ",               # PE / DOS (Windows .exe/.dll)
    b"\xfe\xed\xfa\xce",  # Mach-O 32
    b"\xfe\xed\xfa\xcf",  # Mach-O 64
    b"\xcf\xfa\xed\xfe",  # Mach-O 64 LE
    b"\xca\xfe\xba\xbe",  # Java class / Mach-O fat
    b"\x00asm",          # WebAssembly
    b"dex\n",            # Android dex
)


def _is_executable_blob(path: Path) -> bool:
    """True if the file's magic bytes mark it as a compiled/loadable binary."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return False
    return any(head.startswith(m) for m in _EXEC_MAGIC)


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
    opaque: list[str] = []
    for p in sorted(base.rglob("*")):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        rel = p.relative_to(base).as_posix()
        lang = _LANG_BY_EXT.get(p.suffix.lower())
        if lang is not None:
            files.append(SourceFile(path=rel, text=_read(p), lang=lang))
        elif p.suffix.lower() in _OPAQUE_EXTS or _is_executable_blob(p):
            opaque.append(rel)

    return Skill(
        name=name or base.name,
        description=description,
        files=tuple(files),
        source=str(root),
        opaque=tuple(opaque),
    )


def discover_skills(root: str | Path) -> list[Path]:
    """Return the directory of every skill under `root` (each holds a SKILL.md).

    Falls back to `[root]` when no SKILL.md exists, so a bare script dir still
    scans as one skill.
    """
    root = Path(root)
    if (root / "SKILL.md").is_file():
        return [root]
    dirs = sorted({
        p.parent for p in root.rglob("SKILL.md")
        if p.is_file() and not any(part in _SKIP_DIRS for part in p.parts)
    })
    return dirs or [root]


def _find_skill_md(root: Path) -> Path | None:
    if (root / "SKILL.md").is_file():
        return root / "SKILL.md"
    matches = sorted(
        p for p in root.rglob("SKILL.md")
        if p.is_file() and not any(part in _SKIP_DIRS for part in p.parts)
    )
    return matches[0] if matches else None
