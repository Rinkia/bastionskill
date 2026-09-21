"""Skill-policy format contract (producer lock, PRP §1.3).

`bastionskill harden` emits a *skill* policy — `default:` + a `skills:` block of
per-skill verdict / reasons / block_capabilities. This is a DIFFERENT format from
the tool allow/deny policy that bastionsupply/probe/trace emit (locked separately);
it has no consumer in the suite yet, so this is a producer-only lock: it freezes the
emitted shape so a drift is loud, ready for a consumer to rely on.

Regenerate the golden deliberately (from the fixed report below), read the diff.
"""

from __future__ import annotations

from pathlib import Path

from bastionskill.harden import to_policy_yaml
from bastionskill.models import Finding, ScanReport

GOLDEN = Path(__file__).parent / "fixtures" / "skill_policy_golden.yaml"


def _report() -> ScanReport:
    return ScanReport(skill="demo-skill", file_count=2, findings=(
        Finding(check="hook-install", severity="critical", file="scripts/setup.sh",
                message="installs a persistent shell hook", line=4, capability="hook", kind="malice"),
        Finding(check="network-egress", severity="high", file="scripts/run.py",
                message="posts data to a remote host", line=9, capability="network", kind="shadow"),
        Finding(check="reads-env", severity="medium", file="scripts/run.py",
                message="reads environment variables", line=2, capability="secrets", kind="capability"),
    ))


def test_harden_output_matches_golden():
    produced = to_policy_yaml(_report())
    golden = GOLDEN.read_text(encoding="utf-8")
    assert produced == golden, (
        "skill-policy output drifted from golden — regenerate deliberately, read the diff"
    )


def test_skill_policy_contract_keys():
    y = to_policy_yaml(_report())
    # The vocabulary a future consumer will parse.
    for key in ("default: allow", "skills:", "verdict: deny", "reasons:", "block_capabilities:"):
        assert key in y, f"skill-policy missing contract key: {key!r}"


def test_only_malice_and_shadow_trip_the_verdict():
    # capability-kind findings (reads-env) are informational: not a reason, not blocked.
    y = to_policy_yaml(_report())
    assert "reads-env" not in y and "secrets" not in y
    assert "hook-install" in y and "network-egress" in y


def test_clean_skill_allows():
    y = to_policy_yaml(ScanReport(skill="ok", file_count=1, findings=(
        Finding(check="reads-file", severity="low", file="a.py", message="reads a file",
                capability="filesystem", kind="capability"),
    )))
    assert "verdict: allow" in y
