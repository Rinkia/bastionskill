"""bastionskill command line.

    bastionskill scan ./some-skill                # scan a local skill dir
    bastionskill scan ~/.claude/skills            # batch-scan every skill under a dir
    bastionskill scan owner/repo                  # pre-flight a remote skill (shallow clone)
    bastionskill scan https://github.com/o/r      #   ... by full URL
    bastionskill scan ./skill --json              # machine-readable
    bastionskill scan ./skill --report out.json   # signable manifest (hashes, verdict)
    bastionskill scan ./skill --record            # append result to the local ledger
    bastionskill scan ./skill --fail-on critical  # CI gate threshold (default: high)
    bastionskill harden ./skill -o skill-policy.yaml   # verdict(s), pinned by digest
    bastionskill install owner/repo --to ~/.claude/skills   # install only if it passes
    bastionskill install ./skill --to DIR --policy skill-policy.yaml   # enforce verdicts
    bastionskill lock ./skills -o skill.lock      # pin a folder of skills (commit the lock)
    bastionskill verify ./skills --lock skill.lock   # CI: fail if a skill changed
    bastionskill ledger                           # list previously scanned skills + dates
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from . import __version__, harden, install as install_mod, ledger as ledger_mod, prompt, remote, report
from . import lockfile, verdicts
from .ignore import load as load_ignore
from .loader import discover_skills, load_skill, tree_digest
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
    ps.add_argument("--sarif", action="store_true", help="emit SARIF 2.1.0 (GitHub code scanning)")
    ps.add_argument("--report", help="write a signable scan manifest to this path")
    ps.add_argument("--record", action="store_true", help="append result to the local ledger")
    ps.add_argument("--fail-on", default="review", choices=list(_FAIL_CHOICES),
                    help="exit non-zero at this verdict or worse: block|review|none (default: review)")
    ps.add_argument("--ignore", help="path to a .bastionskillignore (default: in the skill dir)")
    ps.add_argument("--no-ignore", action="store_true", help="ignore any .bastionskillignore")

    ph = sub.add_parser("harden", help="emit policy_version 2 skill verdicts, pinned by digest")
    ph.add_argument("target", help="skill dir, a dir of skills, or a remote url/owner-repo")
    ph.add_argument("--name", help="override skill name label (single skill only)")
    ph.add_argument("-o", "--out", help="write policy.yaml (default: stdout)")

    pi = sub.add_parser("install", help="copy a skill into a skills dir only if it passes")
    pi.add_argument("target", help="skill dir, a dir of skills, or a remote url/owner-repo")
    pi.add_argument("--to", required=True, help="skills dir to install into, e.g. ~/.claude/skills")
    pi.add_argument("--policy", help="a `harden` verdict file to enforce (allow needs a matching digest)")
    pi.add_argument("--name", help="override the installed name (single skill only)")
    pi.add_argument("--fail-on", default="review", choices=list(_FAIL_CHOICES),
                    help="without a policy verdict, refuse at this scan verdict or worse (default: review)")
    pi.add_argument("--force", action="store_true", help="replace a skill already installed under that name")

    pk = sub.add_parser("lock", help="pin every skill under a dir to its digest (scans first)")
    pk.add_argument("target", help="skill dir or a dir of skills")
    pk.add_argument("-o", "--out", default="skill.lock", help="lock file to write (default: skill.lock)")
    pk.add_argument("--fail-on", default="review", choices=list(_FAIL_CHOICES),
                    help="refuse to lock if a skill scans at this verdict or worse (default: review)")

    pv = sub.add_parser("verify", help="fail if any skill was added, removed or changed since lock")
    pv.add_argument("target", help="skill dir or a dir of skills")
    pv.add_argument("--lock", default="skill.lock", help="lock file to check against (default: skill.lock)")

    pl = sub.add_parser("ledger", help="list previously scanned skills and dates")
    pl.add_argument("--json", action="store_true", help="emit JSON")

    args = ap.parse_args(argv)
    if args.cmd == "scan":
        return _cmd_scan(args)
    if args.cmd == "harden":
        return _cmd_harden(args)
    if args.cmd == "ledger":
        return _cmd_ledger(args)
    if args.cmd == "lock":
        return _cmd_lock(args)
    if args.cmd == "verify":
        return _cmd_verify(args)
    if args.cmd == "install":
        return _cmd_install(args)
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
            if args.sarif:
                from . import sarif
                print(sarif.to_sarif(rep))
            elif args.json:
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


def _skill_name(d: Path, base: Path, checkout, override: str | None, many: bool) -> str:
    """The name a skill is hardened and installed under. A remote skill at the repo root
    would otherwise be named after the random clone dir, so use the repo name."""
    if override:
        if many:
            _die("--name needs a single skill (the target holds several)")
        return override
    if checkout is not None and d == base:
        return checkout.url.rstrip("/").split("/")[-1].removesuffix(".git")
    return d.name


def _unique_names(dirs: list[Path], base: Path, checkout, override: str | None) -> list[str]:
    """Skill names for `harden`; names that collide (e.g. a tool that nests copies,
    skills/x and skills/pack/x) fall back to their path under `base`. The verdict's
    digest, not the name, is what `install` matches an allow on."""
    names = [_skill_name(d, base, checkout, override, len(dirs) > 1) for d in dirs]
    return [d.relative_to(base).as_posix() if names.count(n) > 1 else n
            for d, n in zip(dirs, names)]


def _cmd_harden(args) -> int:
    base, checkout = _with_target(args.target)
    try:
        dirs = discover_skills(base)
        items = []
        for d, name in zip(dirs, _unique_names(dirs, base, checkout, args.name)):
            items.append((scan(load_skill(d, name=name)), tree_digest(d)))
        try:
            yaml = harden.to_policy_yaml_many(items)
        except ValueError as e:
            _die(str(e))
    finally:
        if checkout:
            checkout.__exit__(None, None, None)
    if args.out:
        Path(args.out).write_text(yaml, encoding="utf-8")
        print(f"wrote skill verdict -> {args.out}")
    else:
        sys.stdout.write(yaml)
    return 0


def _cmd_install(args) -> int:
    dest = Path(args.to).expanduser()
    try:
        policy = verdicts.load(args.policy) if args.policy else {}
    except (OSError, verdicts.VerdictFileError) as e:
        _die(f"cannot use --policy: {e}")
    base, checkout = _with_target(args.target)
    staged_dirs: list[Path] = []
    try:
        dirs = discover_skills(base)
        names = [_skill_name(d, base, checkout, args.name, len(dirs) > 1) for d in dirs]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            _die(f"several skills would install as {dupes}; install them one at a time")
        plans = []
        for d, name in zip(dirs, names):
            try:
                install_mod.check_name(name)
            except ValueError as e:
                _die(str(e))
            if not (d / "SKILL.md").is_file():
                _die(f"{d} has no SKILL.md: not a skill")
            if (dest / name).exists() and not args.force:
                _die(f"{dest / name} already exists (use --force to replace it)")
            try:
                staged = install_mod.stage(d, dest)
            except ValueError as e:
                _die(f"{name}: {e}")
            staged_dirs.append(staged)
            decision, rep, skill = install_mod.decide(
                staged, name, policy, lambda r: _fails(r, args.fail_on))
            plans.append((decision, staged, skill, rep))

        for decision, *_ in plans:
            mark = "ok    " if decision.ok else "REFUSE"
            print(f"{mark} {decision.name}: {decision.why}")
        if not all(p[0].ok for p in plans):
            print(f"nothing installed: {sum(not p[0].ok for p in plans)} of {len(plans)} refused",
                  file=sys.stderr)
            return 1
        for decision, staged, skill, rep in plans:
            final = dest / decision.name
            install_mod.commit(staged, final, args.force)
            ledger_mod.record(rep, install_mod.installed_skill(skill, final))
            print(f"installed {decision.name} -> {final}")
        return 0
    finally:
        for s in staged_dirs:
            if s.exists():
                shutil.rmtree(s, ignore_errors=True)
        if checkout:
            checkout.__exit__(None, None, None)


def _lock_keys(base: Path) -> dict[str, Path]:
    """Lock key -> skill dir. Keys are paths under `base` (stable across runs; a lone
    skill at `base` uses its dir name). Local dirs only: lock what you commit."""
    if not base.is_dir():
        _die(f"no such directory: {base}")
    return {(d.relative_to(base).as_posix() if d != base else d.resolve().name): d
            for d in discover_skills(base)}


def _cmd_lock(args) -> int:
    entries, refused = {}, []
    out = Path(args.out).resolve()
    for key, d in _lock_keys(Path(args.target)).items():
        if d.resolve() in out.parents:
            _die(f"{args.out} is inside skill {key!r}; it would change that skill's digest. "
                 "Write the lock outside the skill (e.g. the repo root)")
        rep = scan(load_skill(d, name=key))  # no ignore rules: the lock pins what ships
        if _fails(rep, args.fail_on):
            refused.append(f"{key} ({rep.verdict})")
        entries[key] = (tree_digest(d), rep.verdict)
    if refused:
        print(f"bastionskill: not locking, {len(refused)} skill(s) fail at --fail-on {args.fail_on}: "
              + ", ".join(refused), file=sys.stderr)
        return 1
    lockfile.write_lock(lockfile.make_lock(entries), args.out)
    print(f"locked {len(entries)} skill(s) -> {args.out}")
    return 0


def _cmd_verify(args) -> int:
    try:
        lock = lockfile.load_lock(args.lock)
    except (OSError, ValueError) as e:
        _die(f"cannot read lock: {e}")
    current = {key: tree_digest(d) for key, d in _lock_keys(Path(args.target)).items()}
    drift = lockfile.verify(current, lock)
    if drift.clean:
        print(f"verify: {len(current)} skill(s) match {args.lock}")
        return 0
    print(f"verify: DRIFT against {args.lock}")
    for label, keys in (("changed", drift.changed), ("added", drift.added), ("removed", drift.removed)):
        for k in keys:
            print(f"  {label:<8} {k}")
    print("review the change, then `bastionskill lock` again to accept it", file=sys.stderr)
    return 1


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
