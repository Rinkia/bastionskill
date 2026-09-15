"""Scan a `Skill`: run code-layer checks, then compute the shadow.

The shadow is the product's whole point: capabilities the bundled code exercises
(network, secrets, persistence, destructive) that SKILL.md never declared.
"""

from __future__ import annotations

from .checks import scan_python_ast, scan_regex
from .models import Finding, ScanReport, Skill

# Words in a SKILL.md description that count as declaring a capability.
_DECLARES: dict[str, tuple[str, ...]] = {
    "network": ("network", "http", "https", "download", "upload", "fetch",
                "online", "api", "url", "web", "request", "internet"),
    "secrets": ("credential", "secret", "token", "api key", "api-key",
                "password", "auth", "keychain", "ssh"),
    "persistence": ("hook", "background", "daemon", "startup", "cron",
                    "persist", "install a hook"),
    "destructive": ("delete", "remove", "wipe", "erase", "clean up", "purge"),
}

# Phrases that explicitly DISCLAIM a capability. A disclaimer over code that does
# the thing is the strongest shadow, so it always beats a bare keyword mention
# (e.g. "no network" contains "network" but declares the opposite).
_NEGATES: dict[str, tuple[str, ...]] = {
    "network": ("no network", "offline", "no internet", "without network",
                "no connection", "runs locally", "fully local"),
    "secrets": ("no credential", "no secret", "reads no", "touches nothing"),
    "persistence": ("no hook", "installs nothing", "no persistence"),
    "destructive": ("read-only", "read only", "never deletes", "non-destructive"),
}

# Only these capabilities drive shadow detection ("exec" is generic and always
# present in a script; it is not a declared-intent signal on its own).
_SHADOW_CAPS = ("network", "secrets", "persistence", "destructive")


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.check, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def shadow_findings(skill: Skill, code_findings: list[Finding]) -> list[Finding]:
    desc = skill.description.lower()
    exercised = {f.capability for f in code_findings if f.capability in _SHADOW_CAPS}
    out: list[Finding] = []
    for cap in _SHADOW_CAPS:
        if cap not in exercised:
            continue
        disclaimed = any(p in desc for p in _NEGATES.get(cap, ()))
        if not disclaimed and any(word in desc for word in _DECLARES[cap]):
            continue  # declared and not disclaimed: code and description agree
        out.append(Finding(
            check="shadow", severity="critical", file="SKILL.md",
            capability=cap,
            message=(f"undeclared {cap}: the code exercises {cap} but SKILL.md "
                     f"never says so"),
            evidence=(skill.description[:160] or "(no description)"),
        ))
    return out


def scan(skill: Skill) -> ScanReport:
    code: list[Finding] = []
    for f in skill.files:
        code.extend(scan_regex(f))
        if f.lang == "python":
            code.extend(scan_python_ast(f))
    code = _dedupe(code)
    findings = code + shadow_findings(skill, code)
    return ScanReport(
        skill=skill.name, file_count=len(skill.files), findings=tuple(findings)
    )
