"""bastionskill command line.

    bastionskill scan ./some-skill                # scan a local skill dir
    bastionskill scan ~/.claude/skills            # batch-scan every skill under a dir
    bastionskill scan owner/repo                  # pre-flight a remote skill (shallow clone)
    bastionskill scan https://github.com/o/r      #   ... by full URL
    bastionskill scan ./skill --json              # machine-readable
    bastionskill scan ./skill --report out.json   # signable manifest (hashes, verdict)
    bastionskill scan ./skill --record            # append result to the local ledger
    bastionskill scan ./skill --fail-on critical  # CI gate threshold (default: high)
    bastionskill harden ./skill -o skill-policy.yaml
    bastionskill ledger                           # list previously scanned skills + dates
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, harden, ledger as ledger_mod, prompt, remote, report
from .ignore import load as load_ignore
from .loader import discover_skills, load_skill
from .models import VERDICTS, ScanReport, Skill
from .scanner import scan

_VRANK = {v: i for i, v in enumerate(VERDICTS)}  # block=0 (worst) .. allow=2
_FAIL_CHOICES = ("block", "review", "none")


def _make_output_unicode_safe() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


def _resolve_ignore(skill_dir: Path, args):
    if getattr(args, "no_ignore", False):
        return None
    path = args.ignore if getattr(args, "ignore", None) else skill_dir / ".bastionskillignore"
    return load_ignore(path)


def _fails(rep: ScanReport, threshold: str) -> bool:
    """Exit non-zero when the verdict is at `threshold` or worse.

    threshold 'block' fails only on block; 'review' fails on review+block; 'none'
    never fails.
    """
    if threshold == "none":
        return False
    return _VRANK[rep.verdict] <= _VRANK[threshold]


def _scan_one(skill_dir: Path, args) -> tuple[ScanReport, Skill]:
    skill = load_skill(skill_dir, name=args.name)
    rep = scan(skill, ignore=_resolve_ignore(skill_dir, args))
    if getattr(args, "prompt", False):
        rep = ScanReport(
            skill=rep.skill, file_count=rep.file_count,
            findings=rep.findings + tuple(prompt.scan_prompt_layer(skill)),
        )
    return rep, skill


def main(argv=None) -> int:
    _make_output_unicode_safe()
    ap = argparse.ArgumentParser(
        prog="bastionskill", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"bastionskill {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="scan a skill (local dir, dir of skills, or remote)")
    ps.add_argument("target", help="skill dir, a dir of skills, or a remote url/owner-repo")
    ps.add_argument("--name", help="override skill name label")
    ps.add_argument("--prompt", action="store_true",
                    help="also run the prompt-layer check (hidden unicode)")
    ps.add_argument("--json", action="store_true", help="emit JSON")
    ps.add_argument("--report", help="write a signable scan manifest to this path")
    ps.add_argument("--record", action="store_true", help="append result to the local ledger")
    ps.add_argument("--fail-on", default="review", choices=list(_FAIL_CHOICES),
                    help="exit non-zero at this verdict or worse: block|review|none (default: review)")
    ps.add_argument("--ignore", help="path to a .bastionskillignore (default: in the skill dir)")
    ps.add_argument("--no-ignore", action="store_true", help="ignore any .bastionskillignore")

    ph = sub.add_parser("harden", help="emit an agentbastion/bastiongate skill policy")
    ph.add_argument("target", help="skill dir (or remote url/owner-repo)")
    ph.add_argument("--name", help="override skill name label")
    ph.add_argument("-o", "--out", help="write policy.yaml (default: stdout)")

    pl = sub.add_parser("ledger", help="list previously scanned skills and dates")
    pl.add_argument("--json", action="store_true", help="emit JSON")

    args = ap.parse_args(argv)
    if args.cmd == "scan":
        return _cmd_scan(args)
    if args.cmd == "harden":
        return _cmd_harden(args)
    if args.cmd == "ledger":
        return _cmd_ledger(args)
    return 2


def _with_target(target: str):
    """Yield a local base path for a target, remote or local, with cleanup.

    Returns (base_path, checkout_or_None); caller must close the checkout.
    """
    # A local path always wins over remote heuristics, so "skills/mytool" (which
    # also looks like owner/repo shorthand) scans the local dir when it exists.
    p = Path(target)
    if p.exists():
        return p, None
    if remote.is_remote(target):
        checkout = remote.RemoteCheckout(target)
        return checkout.__enter__(), checkout
    _die(f"no such path (and not a recognized remote): {target}")


def _cmd_scan(args) -> int:
    base, checkout = _with_target(args.target)
    manifests = []
    worst_fail = False
    try:
        skill_dirs = discover_skills(base)
        multi = len(skill_dirs) > 1
        for i, d in enumerate(skill_dirs):
            rep, skill = _scan_one(d, args)
            # rug-pull drift is read-only; always surface it.
            prior = ledger_mod.drift(skill)
            if prior:
                print(f"! DRIFT: {skill.source} changed since last scan "
                      f"({prior.get('ts', '?')}, was {prior.get('verdict', '?')})",
                      file=sys.stderr)
            if args.json:
                print(report.to_json(rep))
            else:
                if i:
                    print()
                print(report.to_text(rep))
            if args.record:
                ledger_mod.record(rep, skill)
            if args.report:
                manifests.append(report.to_manifest(rep, skill, __version__))
            worst_fail = worst_fail or _fails(rep, args.fail_on)
        if multi and not args.json:
            print(f"\nscanned {len(skill_dirs)} skills; "
                  f"{'FAIL' if worst_fail else 'pass'} at --fail-on {args.fail_on}")
        if args.report:
            Path(args.report).write_text(
                json.dumps({"schema": "bastionskill.report/1", "scans": manifests},
                           indent=2, ensure_ascii=False),
                encoding="utf-8")
            print(f"wrote report -> {args.report}", file=sys.stderr)
    finally:
        if checkout:
            checkout.__exit__(None, None, None)
    return 1 if worst_fail else 0


def _cmd_harden(args) -> int:
    base, checkout = _with_target(args.target)
    try:
        d = discover_skills(base)[0]
        skill = load_skill(d, name=args.name)
        yaml = harden.to_policy_yaml(scan(skill))
    finally:
        if checkout:
            checkout.__exit__(None, None, None)
    if args.out:
        Path(args.out).write_text(yaml, encoding="utf-8")
        print(f"wrote policy -> {args.out}")
    else:
        sys.stdout.write(yaml)
    return 0


def _cmd_ledger(args) -> int:
    rows = ledger_mod.summary()
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    if not rows:
        print("ledger empty — scan with --record to populate it.")
        return 0
    print(f"{'last scan':<26} {'verdict':<7} {'risk':<8} source")
    print("-" * 70)
    for e in rows:
        print(f"{e.get('ts', '?'):<26} {e.get('verdict', '?'):<7} "
              f"{e.get('risk', '?'):<8} {e.get('source', '?')}")
    return 0


def _die(msg: str) -> None:
    print(f"bastionskill: {msg}", file=sys.stderr)
    raise SystemExit(2)


if __name__ == "__main__":
    raise SystemExit(main())
