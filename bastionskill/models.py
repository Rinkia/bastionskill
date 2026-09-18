"""Immutable data model for skill-poisoning scanning.

A `Skill` holds a SKILL.md declaration plus the bundled `SourceFile`s that run
when the skill is invoked. Checks read a `Skill` and emit `Finding`s; a
`ScanReport` collects them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # 0 = worst

# Capabilities a bundled script can exercise. The shadow check compares these
# against what SKILL.md declares.
CAPABILITIES = ("network", "secrets", "persistence", "destructive", "exec")

# A finding's kind drives the verdict (v0.2). `capability` describes what the code
# can do — informational, never blocks on its own. `malice` and `shadow` are the
# poisoning signals that do.
KINDS = ("capability", "malice", "shadow")

# Verdict tiers, worst first.
VERDICTS = ("block", "review", "allow")
_VRANK = {v: i for i, v in enumerate(VERDICTS)}


@dataclass(frozen=True)
class SourceFile:
    """One bundled file that ships with the skill."""

    path: str  # relative to the skill root
    text: str
    lang: str  # "python" | "bash" | "javascript" | "other"


@dataclass(frozen=True)
class Skill:
    """A named skill: its SKILL.md declaration and bundled source files."""

    name: str
    description: str = ""  # SKILL.md frontmatter description (the declared intent)
    files: tuple[SourceFile, ...] = ()
    source: str = ""  # dir or url it came from
    opaque: tuple[str, ...] = ()  # bundled files we cannot statically read

    def content_hash(self) -> str:
        """Stable sha256 over every bundled file's path + bytes.

        Drives ledger drift / rug-pull detection: same source, changed hash =
        the skill was modified since the last scan.
        """
        import hashlib

        h = hashlib.sha256()
        for f in sorted(self.files, key=lambda x: x.path):
            h.update(f.path.encode("utf-8"))
            h.update(b"\0")
            h.update(f.text.encode("utf-8", "replace"))
            h.update(b"\0")
        for name in sorted(self.opaque):
            h.update(b"opaque:")
            h.update(name.encode("utf-8"))
            h.update(b"\0")
        return h.hexdigest()


@dataclass(frozen=True)
class Finding:
    """One risk detected by a check."""

    check: str  # check id, e.g. "hook-install"
    severity: str  # one of SEVERITIES (display ordering; verdict uses `kind`)
    file: str  # relative path, or "" for skill-level
    message: str
    evidence: str = ""
    line: int = 0
    capability: str = ""  # one of CAPABILITIES, or "" (drives shadow detection)
    kind: str = "capability"  # one of KINDS — drives the verdict

    def __post_init__(self) -> None:
        if self.severity not in _RANK:
            raise ValueError(f"bad severity {self.severity!r}")
        if self.kind not in KINDS:
            raise ValueError(f"bad kind {self.kind!r}")


@dataclass(frozen=True)
class ScanReport:
    """Result of scanning one skill."""

    skill: str
    file_count: int
    findings: tuple[Finding, ...] = ()

    @property
    def risk(self) -> str:
        """Worst severity present, or 'clean' (display hint; verdict is authoritative)."""
        if not self.findings:
            return "clean"
        return min((f.severity for f in self.findings), key=lambda s: _RANK[s])

    @property
    def verdict(self) -> str:
        """block | review | allow — the authoritative call (v0.2).

        block: a staged-exec (decode piped to an interpreter) — no honest use.
        review: any other malice signal or a shadow (undeclared capability) — a
                human should look, but it is not auto-malware.
        allow: clean, or capability the code legitimately has.
        """
        if any(f.check == "staged-exec" for f in self.findings):
            return "block"
        if any(f.kind in ("malice", "shadow") for f in self.findings):
            return "review"
        return "allow"

    @property
    def ok(self) -> bool:
        """True when the skill is cleared to install (verdict allow)."""
        return self.verdict == "allow"

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.severity] += 1
        return out

    def sorted_findings(self) -> tuple[Finding, ...]:
        """Findings worst-first, then by file/line for stable output."""
        return tuple(
            sorted(self.findings, key=lambda f: (_RANK[f.severity], f.file, f.line))
        )
