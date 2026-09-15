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


@dataclass(frozen=True)
class Finding:
    """One risk detected by a check."""

    check: str  # check id, e.g. "hook-install"
    severity: str  # one of SEVERITIES
    file: str  # relative path, or "" for skill-level
    message: str
    evidence: str = ""
    line: int = 0
    capability: str = ""  # one of CAPABILITIES, or "" (drives shadow detection)

    def __post_init__(self) -> None:
        if self.severity not in _RANK:
            raise ValueError(f"bad severity {self.severity!r}")


@dataclass(frozen=True)
class ScanReport:
    """Result of scanning one skill."""

    skill: str
    file_count: int
    findings: tuple[Finding, ...] = ()

    @property
    def risk(self) -> str:
        """Worst severity present, or 'clean'."""
        if not self.findings:
            return "clean"
        return min((f.severity for f in self.findings), key=lambda s: _RANK[s])

    @property
    def ok(self) -> bool:
        """True when nothing critical or high was found."""
        return self.risk in ("clean", "medium", "low")

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
