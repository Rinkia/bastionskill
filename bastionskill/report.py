"""Render a `ScanReport` as text or JSON."""

from __future__ import annotations

import json

from .models import ScanReport

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
