"""`lock` pins a folder of skills; `verify` fails CI when one is added, removed or changed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bastionskill.cli import main
from bastionskill.loader import tree_digest

CLEAN = {"fmt.py": "def fmt(s):\n    return s.strip()\n"}
REVIEW = {"a.py": "import requests\nrequests.get('https://api.example.com')\n"}  # undeclared egress


def _skill(root: Path, name: str, files: dict[str, str]) -> Path:
    d = root / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(f"---\nname: {name}\ndescription: Formats text locally.\n---\n",
                                encoding="utf-8")
    for rel, text in files.items():
        (d / rel).write_text(text, encoding="utf-8")
    return d


@pytest.fixture
def repo(tmp_path):
    skills = tmp_path / "skills"
    _skill(skills, "fmt", CLEAN)
    _skill(skills, "trim", CLEAN)
    return tmp_path


def _lock(repo: Path, *extra: str) -> int:
    return main(["lock", str(repo / "skills"), "-o", str(repo / "skill.lock"), *extra])


def _verify(repo: Path) -> int:
    return main(["verify", str(repo / "skills"), "--lock", str(repo / "skill.lock")])


def test_lock_pins_every_skill_by_path_with_its_digest(repo):
    assert _lock(repo) == 0
    lock = json.loads((repo / "skill.lock").read_text(encoding="utf-8"))
    assert lock["schema"] == "bastionskill.lock/1"
    assert lock["skills"] == {
        "fmt": {"digest": tree_digest(repo / "skills" / "fmt"), "verdict": "allow"},
        "trim": {"digest": tree_digest(repo / "skills" / "trim"), "verdict": "allow"},
    }


def test_verify_passes_when_nothing_changed(repo, capsys):
    assert _lock(repo) == 0
    assert _verify(repo) == 0
    assert "2 skill(s) match" in capsys.readouterr().out


@pytest.mark.parametrize("change, label", [
    (lambda s: (s / "fmt" / "fmt.py").write_text("import os\n", encoding="utf-8"), "changed  fmt"),
    (lambda s: (s / "fmt" / "SKILL.md").write_text("---\nname: fmt\ndescription: x\n---\n", encoding="utf-8"),
     "changed  fmt"),                                 # SKILL.md is pinned too, not just code
    (lambda s: (s / "fmt" / "data.json").write_text("{}", encoding="utf-8"), "changed  fmt"),
    (lambda s: _skill(s, "new", CLEAN), "added    new"),
    (lambda s: [p.unlink() for p in (s / "trim").iterdir()] and (s / "trim").rmdir(), "removed  trim"),
])
def test_verify_fails_on_any_drift(repo, capsys, change, label):
    assert _lock(repo) == 0
    change(repo / "skills")
    assert _verify(repo) == 1
    assert label in capsys.readouterr().out


def test_lock_refuses_a_skill_that_fails_the_scan(repo, capsys):
    _skill(repo / "skills", "net", REVIEW)
    assert _lock(repo) == 1
    assert not (repo / "skill.lock").exists()
    assert "net (review)" in capsys.readouterr().err
    assert _lock(repo, "--fail-on", "block") == 0  # an explicit, reviewed acceptance


def test_nested_skills_are_keyed_by_path(tmp_path):
    _skill(tmp_path / "skills", "fmt", CLEAN)
    _skill(tmp_path / "skills" / "pack", "fmt", CLEAN)
    assert main(["lock", str(tmp_path / "skills"), "-o", str(tmp_path / "skill.lock")]) == 0
    keys = json.loads((tmp_path / "skill.lock").read_text(encoding="utf-8"))["skills"]
    assert sorted(keys) == ["fmt", "pack/fmt"]


def test_single_skill_target_uses_its_name(tmp_path):
    d = _skill(tmp_path, "fmt", CLEAN)
    assert main(["lock", str(d), "-o", str(tmp_path / "skill.lock")]) == 0
    assert list(json.loads((tmp_path / "skill.lock").read_text(encoding="utf-8"))["skills"]) == ["fmt"]
    assert main(["verify", str(d), "--lock", str(tmp_path / "skill.lock")]) == 0


def test_lock_inside_a_skill_is_refused(tmp_path):
    d = _skill(tmp_path, "fmt", CLEAN)
    with pytest.raises(SystemExit) as e:
        main(["lock", str(d), "-o", str(d / "skill.lock")])
    assert e.value.code == 2 and not (d / "skill.lock").exists()


def test_bad_lock_file_is_a_usage_error(repo):
    (repo / "skill.lock").write_text('{"tools": {}}', encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        _verify(repo)
    assert e.value.code == 2
