"""bastionskill command line.

    bastionskill scan ./some-skill              # scan a skill dir (code-layer)
    bastionskill scan ./some-skill --prompt     # also run the prompt-layer check
    bastionskill scan ./some-skill --json       # machine-readable output
    bastionskill harden ./some-skill -o skill-policy.yaml  # agentbastion policy
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import harden, prompt, report
from .loader import load_skill
from .models import ScanReport
from .scanner import scan


def _make_output_unicode_safe() -> None:
    # evidence can carry non-ASCII (hidden-unicode is a thing we report); a cp1252
    # console must not crash printing it.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


def _scan_target(args) -> ScanReport:
    skill = load_skill(args.target, name=args.name)
    rep = scan(skill)
    if getattr(args, "prompt", False):
        rep = ScanReport(
            skill=rep.skill,
            file_count=rep.file_count,
            findings=rep.findings + tuple(prompt.scan_prompt_layer(skill)),
        )
    return rep


def main(argv=None) -> int:
    _make_output_unicode_safe()
    ap = argparse.ArgumentParser(prog="bastionskill", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="scan a skill for code-layer poisoning")
    ps.add_argument("target", help="path to a skill dir (holding SKILL.md)")
    ps.add_argument("--name", help="override skill name label")
    ps.add_argument("--prompt", action="store_true",
                    help="also run the prompt-layer check (hidden unicode)")
    ps.add_argument("--json", action="store_true", help="emit JSON")

    ph = sub.add_parser("harden", help="emit an agentbastion/bastiongate skill policy")
    ph.add_argument("target", help="path to a skill dir (holding SKILL.md)")
    ph.add_argument("--name", help="override skill name label")
    ph.add_argument("-o", "--out", help="write policy.yaml (default: stdout)")

    args = ap.parse_args(argv)

    if args.cmd == "scan":
        return _cmd_scan(args)
    if args.cmd == "harden":
        return _cmd_harden(args)
    return 2


def _cmd_scan(args) -> int:
    rep = _scan_target(args)
    print(report.to_json(rep) if args.json else report.to_text(rep))
    return 0 if rep.ok else 1


def _cmd_harden(args) -> int:
    skill = load_skill(args.target, name=args.name)
    yaml = harden.to_policy_yaml(scan(skill))
    if args.out:
        Path(args.out).write_text(yaml, encoding="utf-8")
        print(f"wrote policy -> {args.out}")
    else:
        sys.stdout.write(yaml)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
