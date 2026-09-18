"""Render a `ScanReport` as text or JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .models import ScanReport, Skill

MANIFEST_SCHEMA = "bastionskill.manifest/1"

_MARK = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW "}


def to_text(rep: ScanReport) -> str:
    lines: list[str] = []
    c = rep.counts()
    head = (f"skill: {rep.skill}  files: {rep.file_count}  risk: {rep.risk.upper()}"
            f"  (crit {c['critical']} / high {c['high']} /"
            f" med {c['medium']} / low {c['low']})")
    lines.append(head)
    lines.append("-" * len(head))

    findings = rep.sorted_findings()
    if not findings:
        lines.append("clean: no code-layer risks found.")
        return "\n".join(lines)

    # Shadow first, called out — it is the headline.
    shadows = [f for f in findings if f.check == "shadow"]
    if shadows:
        lines.append("SHADOW (declared intent != actual behavior):")
        for f in shadows:
            lines.append(f"  ! {f.message}")
        lines.append("")

    for f in findings:
        if f.check == "shadow":
            continue
        loc = f.file + (f":{f.line}" if f.line else "")
        lines.append(f"[{_MARK[f.severity]}] {f.check:<14} {loc}")
        lines.append(f"        {f.message}")
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
        "verdict": "allow" if rep.ok else "deny",
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
        "risk": rep.risk,
        "ok": rep.ok,
        "counts": rep.counts(),
        "findings": [
            {
                "check": f.check,
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
