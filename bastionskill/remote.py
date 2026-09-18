"""Fetch a remote skill to a temp dir for pre-flight scanning.

The wedge: scan a skill *before* you clone it into your agent. We shallow-clone
into a throwaway dir and hand back the path; the caller scans it (static — the
skill's own code is never executed) and cleans up.

`git clone` fetches files; it does not run repository code. We still never invoke
anything inside the cloned tree.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

# owner/repo  (letters, digits, dot, dash, underscore) — GitHub shorthand
_SHORTHAND = re.compile(r"^[\w.-]+/[\w.-]+$")


def is_remote(target: str) -> bool:
    t = target.strip()
    return (
        t.startswith(("http://", "https://", "git@", "ssh://"))
        or t.endswith(".git")
        or t.startswith("github.com/")
        or bool(_SHORTHAND.match(t))
    )


def _to_clone_url(target: str) -> str:
    t = target.strip()
    if t.startswith(("http://", "https://", "git@", "ssh://")) or t.endswith(".git"):
        return t
    if t.startswith("github.com/"):
        return "https://" + t
    if _SHORTHAND.match(t):
        return f"https://github.com/{t}"
    return t


class RemoteCheckout:
    """Context manager: shallow-clone a remote skill, clean up on exit."""

    def __init__(self, target: str) -> None:
        self.url = _to_clone_url(target)
        self._dir: str | None = None

    def __enter__(self) -> Path:
        if shutil.which("git") is None:
            raise RuntimeError("git not found on PATH — needed to scan a remote skill")
        self._dir = tempfile.mkdtemp(prefix="bastionskill-")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet", self.url, self._dir],
                check=True, capture_output=True, text=True, timeout=120,
            )
        except subprocess.CalledProcessError as e:
            self._cleanup()
            raise RuntimeError(f"git clone failed: {e.stderr.strip() or e}") from e
        except subprocess.TimeoutExpired:
            self._cleanup()
            raise RuntimeError("git clone timed out") from None
        return Path(self._dir)

    def __exit__(self, *exc) -> None:
        self._cleanup()

    def _cleanup(self) -> None:
        if self._dir:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir = None
