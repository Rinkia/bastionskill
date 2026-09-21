"""SARIF 2.1.0 output for bastionskill (PRP Part 2 [next]).

`bastionskill scan --sarif` emits SARIF so bundled-code findings upload to GitHub
code scanning. Unlike bastionsupply, skill findings carry a real file + line, so
each result gets a physicalLocation region.
"""

from __future__ import annotations

import json

from bastionskill.models import Finding, ScanReport
from bastionskill.sarif import to_sarif


def _report():
    findings = (
        Finding(check="hook-install", severity="critical", file="scripts/setup.sh",
                message="installs a shell hook", line=12, capability="hook", kind="malice"),
        Finding(check="network-egress", severity="high", file="scripts/run.py",
                message="posts data to a remote host", line=3, capability="network", kind="capability"),
    )
    return ScanReport(skill="evil-skill", file_count=2, findings=findings)


def test_sarif_envelope():
    doc = json.loads(to_sarif(_report()))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert doc["runs"][0]["tool"]["driver"]["name"] == "bastionskill"


def test_results_carry_file_line_and_level():
    doc = json.loads(to_sarif(_report()))
    by_rule = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    hook = by_rule["hook-install"]
    assert hook["level"] == "error"  # critical
    loc = hook["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "scripts/setup.sh"
    assert loc["region"]["startLine"] == 12
    assert by_rule["network-egress"]["level"] == "error"  # high -> error


def test_kind_and_capability_surface_as_properties():
    doc = json.loads(to_sarif(_report()))
    hook = next(r for r in doc["runs"][0]["results"] if r["ruleId"] == "hook-install")
    assert hook["properties"]["kind"] == "malice"
    assert hook["properties"]["capability"] == "hook"


def test_line_zero_omits_region():
    rep = ScanReport(skill="s", file_count=1, findings=(
        Finding(check="opaque-binary", severity="medium", file="bin/x", message="binary", line=0),
    ))
    loc = json.loads(to_sarif(rep))["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "bin/x"
    assert "region" not in loc  # no line -> no region


def test_clean_report_has_no_results():
    doc = json.loads(to_sarif(ScanReport(skill="s", file_count=0, findings=())))
    assert doc["runs"][0]["results"] == []
