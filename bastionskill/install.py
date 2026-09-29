"""`bastionskill install`: the reader that enforces the skill verdict.

Installing a skill means copying its directory into a skills dir (for Claude Code,
`~/.claude/skills/` or a project's `.claude/skills/`). This does that copy only when
the skill passes:

1. The skill is copied into a staging dir inside the destination first. The scan and
   the digest run on that copy, so the verdict is about exactly the bytes installed
   (nothing can change between check and use).
2. With `--policy` (a `harden` verdict file), a `deny` matching the skill's name or
   digest refuses it outright. An `allow` counts only through its `digest`: a reviewer
   can approve a skill the scanner rates `review`, but only those exact bytes, under
   any name. A changed skill (rug-pull) or an unpinned allow falls back to the scan.
3. Otherwise the fresh scan decides at `--fail-on` (default `review`).

The skill's own `.bastionskillignore` is NOT honored here: the author must not be able
to hide files from the check that admits their skill. Symlinks are refused (they could
pull files from outside the skill into the install).
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

from .loader import install_files, load_skill, tree_digest
from .models import ScanReport, Skill
from .scanner import scan
from .verdicts import SkillVerdict


@dataclass(frozen=True)
class Decision:
    name: str
    ok: bool
    why: str
    scan_verdict: str
    digest: str


def check_name(name: str) -> None:
    """An install name is one plain path component: it can't climb out of --to."""
    if not name or name in (".", "..") or any(c in name for c in "/\\:\0") or name.startswith("."):
        raise ValueError(f"unsafe skill name {name!r}: use --name")


def stage(src: Path, dest_root: Path) -> Path:
    """Copy the skill at `src` into a fresh staging dir NEXT TO `dest_root` (same
    filesystem, so the final rename is atomic), never inside it: an agent loading
    skills from `dest_root` must not see an unvetted copy, even after a crash."""
    links = [p for p in src.rglob("*") if p.is_symlink()]
    if links:
        raise ValueError(f"refusing symlinks in the skill: {links[0].relative_to(src).as_posix()}")
    dest_root.mkdir(parents=True, exist_ok=True)
    staged = Path(tempfile.mkdtemp(prefix=".bastionskill-stage-", dir=dest_root.resolve().parent))
    for p in install_files(src):
        out = staged / p.relative_to(src)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, out)
    return staged


def decide(staged: Path, name: str, policy: dict[str, SkillVerdict],
           fails: Callable[[ScanReport], bool]) -> tuple[Decision, ScanReport, Skill]:
    skill = load_skill(staged, name=name)
    rep = scan(skill)  # no ignore rules: see module docstring
    digest = tree_digest(staged)
    # The digest is the identity: an allow covers these exact bytes under any name.
    # A deny also matches by name, so renaming a denied skill doesn't slip it past.
    entry = policy.get(name)
    pinned = next((v for v in policy.values() if v.digest == digest), None)
    if any(v is not None and v.verdict == "deny" for v in (entry, pinned)):
        return Decision(name, False, "denied by policy", rep.verdict, digest), rep, skill
    if pinned is not None:
        why = "allowed by policy (digest matches"
        why += ")" if pinned.name == name else f" entry {pinned.name!r})"
        if rep.verdict != "allow":
            why += f"; scan alone says {rep.verdict}"
        return Decision(name, True, why, rep.verdict, digest), rep, skill
    note = ""
    if entry is not None:  # an allow for this name, but not for these bytes
        note = ("policy allow ignored: not pinned to a digest; " if entry.digest is None
                else "policy allow ignored: files changed since they were vetted; ")
    ok = not fails(rep)
    why = note + f"scan verdict {rep.verdict}"
    return Decision(name, ok, why, rep.verdict, digest), rep, skill


def commit(staged: Path, final: Path, force: bool) -> None:
    """Move a staged skill into place (same filesystem, so the rename is atomic)."""
    if final.exists():
        if not force:
            raise FileExistsError(f"{final} already exists (use --force to replace it)")
        shutil.rmtree(final)
    os.replace(staged, final)


def installed_skill(skill: Skill, final: Path) -> Skill:
    """The scanned skill, re-labelled with where it now lives (for the ledger)."""
    return replace(skill, source=str(final))
