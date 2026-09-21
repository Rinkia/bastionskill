"""Emit a ScanReport as SARIF 2.1.0 (PRP Part 2 [next]).

`bastionskill scan --sarif` uploads bundled-code findings to GitHub code scanning
(github/codeql-action/upload-sarif). Skill findings carry a real file + line, so
each result gets a physicalLocation region (omitted when line is unknown, e.g. an
opaque binary). `kind`/`capability` ride along as result properties.
"""

from __future__ import annotations

import json

from . import __version__
from .models import ScanReport

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/Rinkia/bastionskill"

# bastionskill severity -> SARIF result level.
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def to_sarif(report: ScanReport) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in report.findings:
        rules.setdefault(f.check, {
            "id": f.check,
            "shortDescription": {"text": f.check.replace("-", " ")},
            "helpUri": f"{_INFO_URI}#checks",
        })
        physical = {"artifactLocation": {"uri": f.file or report.skill}}
        if f.line:
            physical["region"] = {"startLine": f.line}
        results.append({
            "ruleId": f.check,
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{"physicalLocation": physical}],
            "properties": {"kind": f.kind, "capability": f.capability},
        })

    doc = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "bastionskill",
                "version": __version__,
                "informationUri": _INFO_URI,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)
