"""Tests for the before-GH cut: opaque detection, comment stripping, ignore
rules, ledger + drift, manifest, fail-on threshold, batch discovery, remote URL
parsing (no network)."""

from __future__ import annotations

from pathlib import Path

import pytest

from bastionskill import __version__, scan
from bastionskill.cli import _fails
from bastionskill.ignore import load as load_ignore
from bastionskill.loader import discover_skills, load_skill
from bastionskill.models import ScanReport, Skill, SourceFile
from bastionskill import ledger as ledger_mod
from bastionskill import remote, report


def _skill(tmp: Path, name: str, files: dict[str, str], desc: str = "does a thing") -> Path:
    d = tmp / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(f"---\nname: {name}\ndescription: {desc}\n---\n", encoding="utf-8")
    for rel, text in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return d


# --- opaque / binary --------------------------------------------------------
def test_opaque_binary_flagged(tmp_path: Path):
    d = _skill(tmp_path, "withso", {"run.py": "print(1)\n"})
    (d / "payload.so").write_bytes(b"\x7fELF\x00\x00 binary blob")
    skill = load_skill(d)
    assert "payload.so" in skill.opaque
    rep = scan(skill)
    assert any(f.check == "opaque-binary" and f.severity == "high" for f in rep.findings)


def test_opaque_detected_inside_dist_but_source_noise_skipped(tmp_path: Path):
    d = _skill(tmp_path, "distskill", {"run.py": "print(1)\n"})
    (d / "dist").mkdir()
    (d / "dist" / "payload.so").write_bytes(b"\x7fELF payload")   # dropped binary
    (d / "dist" / "bundle.js").write_text("import socket\n", encoding="utf-8")  # build noise
    skill = load_skill(d)
    assert "dist/payload.so" in skill.opaque              # binary in dist IS caught
    assert not any(f.path == "dist/bundle.js" for f in skill.files)  # source noise skipped


def test_opaque_magic_catches_renamed_binary_not_images(tmp_path: Path):
    d = _skill(tmp_path, "magic", {"run.py": "print(1)\n"})
    (d / "sneaky.txt").write_bytes(b"\x7fELF hidden payload")   # renamed ELF
    (d / "icon.png").write_bytes(b"\x89PNG\r\n\x1a\n imagedata")  # real image
    skill = load_skill(d)
    assert "sneaky.txt" in skill.opaque
    assert "icon.png" not in skill.opaque


# --- comment stripping (the known FP) --------------------------------------
def test_comment_only_match_is_not_flagged(tmp_path: Path):
    d = _skill(tmp_path, "commented", {
        "a.py": "# this file could eval(x) but does not\nx = 1\n",
        "b.js": "// fetch('http://x') is only mentioned here\nconst y = 2;\n",
        "c.sh": "#!/usr/bin/env bash\n# rm -rf described, not run\necho hi\n",
    })
    rep = scan(load_skill(d))
    assert rep.ok and rep.risk == "clean", [f.check for f in rep.findings]


def test_real_code_still_flagged_with_comments_present(tmp_path: Path):
    d = _skill(tmp_path, "mixed", {"a.py": "# safe note\nexec(open('x').read())\n"})
    rep = scan(load_skill(d))
    assert any(f.check == "dynamic-exec" for f in rep.findings)


# --- ignore rules -----------------------------------------------------------
def test_ignore_skip_glob(tmp_path: Path):
    d = _skill(tmp_path, "ign", {"scripts/bad.py": "import socket\ns=socket.socket()\n"})
    (d / ".bastionskillignore").write_text("scripts/bad.py\n", encoding="utf-8")
    rep = scan(load_skill(d), ignore=load_ignore(d / ".bastionskillignore"))
    assert not any(f.check == "network-egress" for f in rep.findings)


def test_ignore_suppress_check(tmp_path: Path):
    d = _skill(tmp_path, "sup", {"scripts/bad.py": "import socket\ns=socket.socket()\ns.sendall(b'x')\n"})
    (d / ".bastionskillignore").write_text("suppress network-egress\n", encoding="utf-8")
    rep = scan(load_skill(d), ignore=load_ignore(d / ".bastionskillignore"))
    assert not any(f.check == "network-egress" for f in rep.findings)


# --- ledger + drift ---------------------------------------------------------
def _mk_skill(source: str, body: str) -> Skill:
    return Skill(name="s", description="offline formatter",
                 files=(SourceFile(path="a.py", text=body, lang="python"),),
                 source=source)


def test_ledger_record_and_summary(tmp_path: Path):
    led = tmp_path / "ledger.jsonl"
    sk = _mk_skill("src://one", "print(1)\n")
    rep = scan(sk)
    ledger_mod.record(rep, sk, path=led)
    rows = ledger_mod.summary(path=led)
    assert len(rows) == 1 and rows[0]["source"] == "src://one"


def test_ledger_drift_detects_change(tmp_path: Path):
    led = tmp_path / "ledger.jsonl"
    sk1 = _mk_skill("src://x", "print(1)\n")
    ledger_mod.record(scan(sk1), sk1, path=led)
    assert ledger_mod.drift(sk1, path=led) is None  # unchanged
    sk2 = _mk_skill("src://x", "import socket  # changed!\n")
    prior = ledger_mod.drift(sk2, path=led)
    assert prior is not None and prior["source"] == "src://x"


def test_ledger_tolerates_corrupt_line(tmp_path: Path):
    led = tmp_path / "ledger.jsonl"
    led.write_text("not json\n", encoding="utf-8")
    assert ledger_mod.summary(path=led) == []


# --- manifest ---------------------------------------------------------------
def test_manifest_shape(tmp_path: Path):
    d = _skill(tmp_path, "man", {"a.py": "import socket\ns=socket.socket()\n"},
               desc="offline, no network")
    skill = load_skill(d)
    m = report.to_manifest(scan(skill), skill, __version__)
    assert m["schema"] == "bastionskill.manifest/1"
    assert m["verdict"] == "deny"
    assert len(m["content_hash"]) == 64
    assert m["files"] and all(len(f["sha256"]) == 64 for f in m["files"])


# --- fail-on threshold ------------------------------------------------------
def _rep(sev: str | None) -> ScanReport:
    from bastionskill.models import Finding
    findings = () if sev is None else (Finding(check="x", severity=sev, file="a", message="m"),)
    return ScanReport(skill="s", file_count=1, findings=findings)


def test_fail_on_threshold():
    assert _fails(_rep("critical"), "high") is True
    assert _fails(_rep("medium"), "high") is False
    assert _fails(_rep("medium"), "medium") is True
    assert _fails(_rep("critical"), "none") is False
    assert _fails(_rep(None), "low") is False


# --- batch discovery --------------------------------------------------------
def test_discover_multiple_skills(tmp_path: Path):
    _skill(tmp_path, "one", {"a.py": "print(1)\n"})
    _skill(tmp_path, "two", {"b.py": "print(2)\n"})
    dirs = discover_skills(tmp_path)
    assert len(dirs) == 2


def test_discover_single_skill_at_root(tmp_path: Path):
    d = _skill(tmp_path, "solo", {"a.py": "print(1)\n"})
    assert discover_skills(d) == [d]


# --- remote parsing (no network) -------------------------------------------
@pytest.mark.parametrize("target,expected", [
    ("owner/repo", True),
    ("https://github.com/o/r", True),
    ("github.com/o/r", True),
    ("git@github.com:o/r.git", True),
    ("./local/dir", False),
    ("C:/Projects/x", False),
])
def test_is_remote(target, expected):
    assert remote.is_remote(target) is expected


def test_shorthand_to_url():
    assert remote._to_clone_url("owner/repo") == "https://github.com/owner/repo"
    assert remote._to_clone_url("github.com/o/r") == "https://github.com/o/r"
