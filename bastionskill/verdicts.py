"""Read a skill-verdict file (the `harden` output) so `install` can enforce it.

A stdlib-only reader for the shape `harden` writes: a `policy_version: 2` file whose
`skill:` block maps skill names to a verdict and, since 0.5.0, the `digest` of the
exact files that were vetted. Other top-level blocks (a tool policy, `gate:`, ...) are
skipped, the way every v2 consumer skips blocks that aren't its own. Inside `skill:`
the reader is strict: an unknown key or an unreadable line fails loudly instead of
being half-understood, since a misread verdict file is a security bug.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

VERDICTS = ("allow", "deny")
_KEY = re.compile(r'^(?P<ind> *)(?P<key>"(?:[^"\\]|\\.)*"|[^\s:#][^:#]*?):(?:\s+(?P<val>\S.*?))?\s*$')
_ITEM = re.compile(r"^ {8}- \S")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ENTRY_KEYS = {"verdict", "digest", "reasons", "block_capabilities"}
_LIST_KEYS = {"reasons", "block_capabilities"}


class VerdictFileError(ValueError):
    """The file is not a skill-verdict file this version can read."""


@dataclass(frozen=True)
class SkillVerdict:
    name: str
    verdict: str                 # allow | deny
    digest: str | None = None    # sha256:<hex> of the vetted files, if pinned


def load(path: str | Path) -> dict[str, SkillVerdict]:
    return parse(Path(path).read_text(encoding="utf-8"), str(path))


def parse(text: str, where: str = "<verdicts>") -> dict[str, SkillVerdict]:
    version, top = None, None
    skills_seen = False
    entries: dict[str, dict] = {}
    current = None
    in_list = False

    for n, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise VerdictFileError(f"{where}:{n}: tab indentation")
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0:
            m = _KEY.match(raw)
            if not m:
                raise VerdictFileError(f"{where}:{n}: unreadable line")
            top = m["key"]
            if top == "policy_version":
                version = _plain(m["val"])
            continue
        if top != "skill":
            continue  # another tool's block: not ours to read

        if in_list and _ITEM.match(raw):
            continue
        in_list = False
        m = _KEY.match(raw)
        if not m:
            raise VerdictFileError(f"{where}:{n}: unreadable line in the skill: block")
        key, val = m["key"], _plain(m["val"])
        if indent == 2:
            if key != "skills" or val is not None:
                raise VerdictFileError(f"{where}:{n}: `skill:` holds only `skills:` (got {key!r})")
            skills_seen = True
        elif indent == 4 and skills_seen and val is None:
            current = _unquote(key)
            if current in entries:
                raise VerdictFileError(f"{where}:{n}: skill {current!r} listed twice")
            entries[current] = {}
        elif indent == 6 and current is not None and key in _ENTRY_KEYS:
            if key in _LIST_KEYS:
                in_list = val is None
                if val not in (None, "[]"):
                    raise VerdictFileError(f"{where}:{n}: `{key}` must be a list")
            else:
                entries[current][key] = val
        else:
            raise VerdictFileError(f"{where}:{n}: unexpected {key!r} in the skill: block")

    if version != "2":
        raise VerdictFileError(f"{where}: not a policy_version 2 file")
    return {name: _entry(name, e, where) for name, e in entries.items()}


def _entry(name: str, e: dict, where: str) -> SkillVerdict:
    verdict, digest = e.get("verdict"), e.get("digest")
    if verdict not in VERDICTS:
        raise VerdictFileError(f"{where}: skill {name!r}: verdict must be allow or deny, got {verdict!r}")
    if digest is not None and not _DIGEST.match(digest):
        raise VerdictFileError(f"{where}: skill {name!r}: digest must be sha256:<64 hex>")
    return SkillVerdict(name, verdict, digest)


def _plain(val: str | None) -> str | None:
    if val is None:
        return None
    if not val.startswith('"'):
        val = re.sub(r"\s+#.*$", "", val)
    return _unquote(val)


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] == s[-1] == '"':
        return re.sub(r"\\(.)", r"\1", s[1:-1])
    return s
