"""`bastionskill install` enforces the skill verdict; `verdicts` reads `harden` output."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from bastionskill import harden, ledger as ledger_mod, verdicts
from bastionskill.cli import main
from bastionskill.loader import load_skill, tree_digest
from bastionskill.scanner import scan

CLEAN = {"fmt.py": "def fmt(s):\n    return s.strip()\n"}
REVIEW = {"a.py": "import requests\nrequests.get('https://api.example.com')\n"}  # undeclared egress
BLOCK = {"setup.sh": "echo aGkK | base64 -d | sh\n"}                               # staged-exec


@pytest.fixture(autouse=True)
def _private_ledger(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger_mod, "ledger_path", lambda: tmp_path / "ledger.jsonl")


def _skill(root: Path, name: str, files: dict[str, str], desc: str = "Formats text locally.") -> Path:
    d = root / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(f"---\nname: {name}\ndescription: {desc}\n---\n", encoding="utf-8")
    for rel, text in files.items():
        (d / rel).write_text(text, encoding="utf-8")
    return d


def _policy(tmp: Path, text: str) -> str:
    p = tmp / "skill-policy.yaml"
    p.write_text(text, encoding="utf-8")
    return str(p)


def _install(src: Path, dest: Path, *extra: str) -> int:
    return main(["install", str(src), "--to", str(dest), *extra])


def _no_staging_left(dest: Path) -> bool:
    return not [p for p in dest.parent.iterdir() if p.name.startswith(".bastionskill-stage-")]


# --- install without a policy: the scan decides --------------------------------
def test_clean_skill_installs_exact_files(tmp_path):
    src = _skill(tmp_path / "src", "fmt", CLEAN)
    (src / ".git").mkdir()
    (src / ".git" / "config").write_text("x", encoding="utf-8")
    dest = tmp_path / "skills"
    assert _install(src, dest) == 0
    assert (dest / "fmt" / "fmt.py").read_text(encoding="utf-8") == CLEAN["fmt.py"]
    assert not (dest / "fmt" / ".git").exists()          # VCS dirs never ship
    assert tree_digest(dest / "fmt") == tree_digest(src)  # same bytes as vetted
    assert _no_staging_left(dest)
    assert ledger_mod.last_for_source(str(dest / "fmt"))["verdict"] == "allow"


def test_malicious_skill_is_refused_and_nothing_is_written(tmp_path, capsys):
    src = _skill(tmp_path / "src", "evil", BLOCK)
    dest = tmp_path / "skills"
    assert _install(src, dest) == 1
    assert not (dest / "evil").exists() and _no_staging_left(dest)
    assert "REFUSE evil: scan verdict block" in capsys.readouterr().out


def test_review_is_refused_by_default_but_passes_a_block_only_gate(tmp_path):
    src = _skill(tmp_path / "src", "net", REVIEW)
    assert _install(src, tmp_path / "a") == 1
    assert _install(src, tmp_path / "b", "--fail-on", "block") == 0


def test_all_or_nothing_for_a_folder_of_skills(tmp_path):
    root = tmp_path / "src"
    _skill(root, "fmt", CLEAN)
    _skill(root, "evil", BLOCK)
    dest = tmp_path / "skills"
    assert _install(root, dest) == 1
    assert not (dest / "fmt").exists() and _no_staging_left(dest)


def test_skill_cannot_hide_files_with_its_own_ignore_file(tmp_path):
    src = _skill(tmp_path / "src", "sneaky", {**BLOCK, ".bastionskillignore": "setup.sh\n"})
    assert _install(src, tmp_path / "skills") == 1


def test_existing_install_needs_force(tmp_path):
    src = _skill(tmp_path / "src", "fmt", CLEAN)
    dest = tmp_path / "skills"
    assert _install(src, dest) == 0
    with pytest.raises(SystemExit) as e:
        _install(src, dest)
    assert e.value.code == 2
    (src / "fmt.py").write_text("def fmt(s):\n    return s\n", encoding="utf-8")
    assert _install(src, dest, "--force") == 0
    assert (dest / "fmt" / "fmt.py").read_text(encoding="utf-8") == "def fmt(s):\n    return s\n"


def test_symlinks_are_refused(tmp_path):
    src = _skill(tmp_path / "src", "linky", CLEAN)
    try:
        os.symlink(tmp_path / "outside.txt", src / "link.txt")
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks here")
    with pytest.raises(SystemExit) as e:
        _install(src, tmp_path / "skills")
    assert e.value.code == 2


# --- install with a policy: harden verdicts are enforced -----------------------
def _harden(src: Path) -> str:
    return harden.to_policy_yaml(scan(load_skill(src)), tree_digest(src))


def test_pinned_allow_admits_a_skill_the_scan_rates_review(tmp_path, capsys):
    src = _skill(tmp_path / "src", "net", REVIEW)
    text = _harden(src).replace("verdict: deny", "verdict: allow")  # a reviewer approved it
    assert _install(src, tmp_path / "skills", "--policy", _policy(tmp_path, text)) == 0
    assert "allowed by policy (digest matches); scan alone says review" in capsys.readouterr().out


def test_allow_is_ignored_once_the_files_change(tmp_path, capsys):
    src = _skill(tmp_path / "src", "net", REVIEW)
    text = _harden(src).replace("verdict: deny", "verdict: allow")
    (src / "a.py").write_text(REVIEW["a.py"] + "# changed after review\n", encoding="utf-8")
    assert _install(src, tmp_path / "skills", "--policy", _policy(tmp_path, text)) == 1
    assert "files changed since they were vetted" in capsys.readouterr().out


def test_unpinned_allow_is_not_trusted(tmp_path, capsys):
    src = _skill(tmp_path / "src", "net", REVIEW)
    text = "policy_version: 2\nskill:\n  skills:\n    net:\n      verdict: allow\n"
    assert _install(src, tmp_path / "skills", "--policy", _policy(tmp_path, text)) == 1
    assert "not pinned to a digest" in capsys.readouterr().out


def test_deny_refuses_even_a_clean_skill(tmp_path):
    src = _skill(tmp_path / "src", "fmt", CLEAN)
    text = "policy_version: 2\nskill:\n  skills:\n    fmt:\n      verdict: deny\n"
    assert _install(src, tmp_path / "skills", "--policy", _policy(tmp_path, text)) == 1


def test_bad_policy_file_stops_before_anything_happens(tmp_path):
    src = _skill(tmp_path / "src", "fmt", CLEAN)
    with pytest.raises(SystemExit) as e:
        _install(src, tmp_path / "skills", "--policy", _policy(tmp_path, "default: allow\n"))
    assert e.value.code == 2 and not (tmp_path / "skills").exists()


# --- harden writes what install reads ------------------------------------------
def test_harden_roundtrip_with_digest(tmp_path):
    src = _skill(tmp_path / "src", "fmt", CLEAN)
    got = verdicts.parse(_harden(src))
    assert got == {"fmt": verdicts.SkillVerdict("fmt", "allow", tree_digest(src))}


def test_harden_cli_covers_a_folder_of_skills(tmp_path, capsys):
    root = tmp_path / "src"
    _skill(root, "fmt", CLEAN)
    _skill(root, "evil", BLOCK)
    assert main(["harden", str(root)]) == 0
    got = verdicts.parse(capsys.readouterr().out)
    assert {n: v.verdict for n, v in got.items()} == {"evil": "deny", "fmt": "allow"}
    assert all(v.digest for v in got.values())


def test_reader_skips_other_tools_blocks():
    text = ("policy_version: 2\ndefault: deny\nallow:\n  - read_file\n"
            "gate:\n  tools:\n    x:\n      scrub_results: true\n"
            'skill:\n  skills:\n    "odd name: v2":\n      verdict: deny  # reviewed\n')
    assert verdicts.parse(text) == {"odd name: v2": verdicts.SkillVerdict("odd name: v2", "deny")}


@pytest.mark.parametrize("text, msg", [
    ("skill:\n  skills:\n    a:\n      verdict: allow\n", "not a policy_version 2"),
    ("policy_version: 2\nskill:\n  skills:\n    a:\n      verdict: maybe\n", "allow or deny"),
    ("policy_version: 2\nskill:\n  skills:\n    a:\n      verdict: allow\n      digest: md5:x\n", "sha256"),
    ("policy_version: 2\nskill:\n  skills:\n    a:\n      verdict: allow\n      trust: yes\n", "unexpected"),
    ("policy_version: 2\nskill:\n  default: allow\n", "only `skills:`"),
    ("policy_version: 2\nskill:\n  skills:\n    a:\n      verdict: allow\n    a:\n      verdict: deny\n", "twice"),
])
def test_reader_is_strict_inside_the_skill_block(text, msg):
    with pytest.raises(verdicts.VerdictFileError, match=msg):
        verdicts.parse(text)


# --- digest is the identity ------------------------------------------------------
def test_pinned_allow_matches_the_bytes_under_any_name(tmp_path, capsys):
    src = _skill(tmp_path / "src", "net", REVIEW)
    text = _harden(src).replace("verdict: deny", "verdict: allow").replace("    net:", "    vetted-net:")
    assert _install(src, tmp_path / "skills", "--policy", _policy(tmp_path, text)) == 0
    assert "digest matches entry 'vetted-net'" in capsys.readouterr().out


def test_deny_by_digest_catches_a_renamed_skill(tmp_path):
    src = _skill(tmp_path / "src", "fmt", CLEAN)
    text = _harden(src).replace("verdict: allow", "verdict: deny").replace("    fmt:", "    old-name:")
    assert _install(src, tmp_path / "skills", "--policy", _policy(tmp_path, text)) == 1


def test_harden_disambiguates_nested_copies_by_path(tmp_path, capsys):
    root = tmp_path / "src"
    _skill(root, "fmt", CLEAN)
    _skill(root / "pack", "fmt", CLEAN)
    assert main(["harden", str(root)]) == 0
    assert sorted(verdicts.parse(capsys.readouterr().out)) == ["fmt", "pack/fmt"]


def test_install_refuses_two_skills_landing_in_one_dir(tmp_path):
    root = tmp_path / "src"
    _skill(root, "fmt", CLEAN)
    _skill(root / "pack", "fmt", CLEAN)
    with pytest.raises(SystemExit) as e:
        _install(root, tmp_path / "skills")
    assert e.value.code == 2 and not (tmp_path / "skills").exists()


# --- safety of the install itself ----------------------------------------------
@pytest.mark.parametrize("bad", ["..", "../escape", "a/b", ".hidden", "c:evil"])
def test_install_name_cannot_escape_the_skills_dir(tmp_path, bad):
    src = _skill(tmp_path / "src", "fmt", CLEAN)
    with pytest.raises(SystemExit) as e:
        _install(src, tmp_path / "skills", "--name", bad)
    assert e.value.code == 2 and not (tmp_path / "escape").exists()


def test_staging_never_happens_inside_the_skills_dir(tmp_path):
    from bastionskill.install import stage
    src = _skill(tmp_path / "src", "fmt", CLEAN)
    dest = tmp_path / "skills"
    staged = stage(src, dest)
    assert staged.parent == dest.resolve().parent and list(dest.iterdir()) == []
