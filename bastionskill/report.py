"""Render a `ScanReport` as text or JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .models import ScanReport, Skill

MANIFEST_SCHEMA = "bastionskill.manifest/1"

_MARK = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW "}


def _capability_summary(findings) -> str:
    """One line: which capabilities the code exercises and how many hits each."""
    counts: dict[str, int] = {}
    for f in findings:
        if f.kind == "capability" and f.capability:
            counts[f.capability] = counts.get(f.capability, 0) + 1
    if not counts:
        return ""
    order = ["network", "secrets", "persistence", "destructive", "exec"]
    parts = [f"{cap}×{counts[cap]}" for cap in order if cap in counts]
    return ", ".join(parts)


def to_text(rep: ScanReport) -> str:
    lines: list[str] = []
    head = f"skill: {rep.skill}  files: {rep.file_count}  VERDICT: {rep.verdict.upper()}"
    lines.append(head)
    lines.append("-" * len(head))

    findings = rep.sorted_findings()
    reasons = [f for f in findings if f.kind in ("malice", "shadow")]

    if rep.verdict == "allow":
        cap = _capability_summary(findings)
        lines.append("allow: no poisoning signals." +
                     (f"  capabilities: {cap}" if cap else " no notable capabilities."))
        return "\n".join(lines)

    # Why it isn't allowed — the malice + shadow signals, up top.
    lines.append(f"why {rep.verdict}:")
    for f in reasons:
        loc = f" ({f.file}:{f.line})" if f.line else (f" ({f.file})" if f.file else "")
        lines.append(f"  ! [{f.kind}] {f.check}: {f.message}{loc}")

    cap = _capability_summary(findings)
    if cap:
        lines.append(f"\ncapabilities (informational): {cap}")

    # Full detail, kind-tagged.
    lines.append("\nfindings:")
    for f in findings:
        loc = f.file + (f":{f.line}" if f.line else "")
        lines.append(f"  [{f.kind[:3]}|{_MARK[f.severity]}] {f.check:<14} {loc}")
        if f.evidence:
            lines.append(f"        > {f.evidence}")
    return "\n".join(lines)


def to_manifest(rep: ScanReport, skill: Skill, tool_version: str) -> dict:
    """A stable, signable record of one scan.

    Deterministic except `generated_at`; carries per-file sha256 and the skill
    content hash so a signature (future) or a Supabase sink can pin exactly what
    was scanned. This is the schema a certification/registry layer would build on.
    """
    import hashlib

    files = [
        {"path": f.path, "lang": f.lang,
         "sha256": hashlib.sha256(f.text.encode("utf-8", "replace")).hexdigest()}
        for f in sorted(skill.files, key=lambda x: x.path)
    ]
    return {
        "schema": MANIFEST_SCHEMA,
        "tool_version": tool_version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "skill": rep.skill,
        "source": skill.source,
        "content_hash": skill.content_hash(),
        "verdict": rep.verdict,
        "risk": rep.risk,
        "counts": rep.counts(),
        "files": files,
        "opaque": list(skill.opaque),
        "findings": json.loads(to_json(rep))["findings"],
    }


def to_json(rep: ScanReport) -> str:
    obj = {
        "skill": rep.skill,
        "file_count": rep.file_count,
        "verdict": rep.verdict,
        "risk": rep.risk,
        "ok": rep.ok,
        "counts": rep.counts(),
        "findings": [
            {
                "check": f.check,
                "kind": f.kind,
                "severity": f.severity,
                "capability": f.capability,
                "file": f.file,
                "line": f.line,
                "message": f.message,
                "evidence": f.evidence,
            }
            for f in rep.sorted_findings()
        ],
    }
    return json.dumps(obj, indent=2, ensure_ascii=False)
