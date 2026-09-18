"""Code-layer detectors.

Two tiers, both static (source is read, never executed — so payloads hidden
behind dead-code or `if False:` / env-flag guards are flagged like any other):

* a language-agnostic regex table applied line-by-line to every bundled file, and
* a Python-only AST tier (`ast` is stdlib) that catches dynamic exec / import /
  attribute-built calls that reflowed regex can miss.

Each detector carries a `capability`; `scanner.shadow_findings` compares the set
of capabilities the code exercises against what SKILL.md declared.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Callable

from .models import Finding, SourceFile


@dataclass(frozen=True)
class Detector:
    check: str
    severity: str
    capability: str
    pattern: re.Pattern
    message: str


def _d(check, severity, capability, regex, message, flags=0) -> Detector:
    return Detector(check, severity, capability, re.compile(regex, flags), message)


# --- regex tier -------------------------------------------------------------
# Ordered worst-first only for readability; scanner sorts output itself.
_REGEX: tuple[Detector, ...] = (
    # persistence / hook install — the lead finding
    _d("hook-install", "critical", "persistence",
       r"\b(Post|Pre|User(Prompt|)|Stop|Notification)ToolUse\b|\bPostToolUse\b|\bPreToolUse\b",
       "installs an agent hook (runs after this skill, persistence)"),
    _d("hook-install", "high", "persistence",
       r"settings\.json|\.claude[\\/](settings|hooks)|[\\/]hooks[\\/]",
       "writes to agent settings/hooks (persistence surface)"),
    _d("lateral-tamper", "high", "persistence",
       r"CLAUDE\.md|mcp\.json|claude_desktop_config|[\\/]skills[\\/]|\.mcp\.json",
       "writes to agent config / other skills (lateral tampering)"),
    _d("persistence", "high", "persistence",
       r"\bcrontab\b|LaunchAgents|LaunchDaemons|\bHKCU\b|\bHKLM\b|systemctl\s+enable",
       "installs OS-level persistence (cron/launchd/registry/systemd)"),
    # network egress
    _d("network-egress", "critical", "network",
       r"\bsocket\.socket\b|\.connect\(\s*\(|\.sendall\(|\.sendto\(",
       "raw socket network egress"),
    _d("network-egress", "high", "network",
       r"\brequests\.(get|post|put|patch|delete)\b|\burllib\.request\b|\bhttp\.client\b|\bfetch\(|\baxios\b",
       "HTTP client call (possible exfiltration)"),
    _d("network-egress", "high", "network",
       r"\bcurl\b|\bwget\b|Invoke-WebRequest|Invoke-RestMethod",
       "shells out to a network client (curl/wget/Invoke-WebRequest)"),
    # secret read
    _d("secret-read", "critical", "secrets",
       r"\.aws[\\/]credentials|id_rsa|id_ed25519|\.ssh[\\/]|\.git-credentials|\.npmrc|KUBECONFIG|keychain",
       "reads credential/secret material"),
    _d("secret-read", "high", "secrets",
       r"(^|[\s\"'/=@])\.env\b",
       "reads a .env secrets file"),
    # obfuscation
    _d("obfuscation", "high", "exec",
       r"base64\s+(-d|--decode)|b64decode|atob\(|FromBase64String",
       "base64-decoded payload (obfuscation)"),
    _d("obfuscation", "critical", "exec",
       r"base64\s+(-d|--decode)[^\n|]*\|\s*(sh|bash|python|node)\b",
       "decodes then pipes to an interpreter (staged exec)"),
    # dynamic exec (regex catch; AST tier confirms for python)
    _d("dynamic-exec", "critical", "exec",
       r"\beval\(|\bexec\(|\bsystem\(|subprocess\.(Popen|call|run|check_output)|os\.popen",
       "dynamic / shell execution"),
    # destructive
    _d("destructive", "high", "destructive",
       r"\brm\s+-rf\b|Remove-Item\b[^\n]*-Recurse|\bmkfs\b|\bdd\s+if=|\bshred\b",
       "destructive filesystem/disk command"),
)


_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def _strip_comments(text: str, lang: str) -> str:
    """Blank out comment lines so regex doesn't match code described in prose.

    Line count is preserved (line numbers stay valid). Conservative: only removes
    FULL-LINE comments (and JS block comments) — trailing comments are left so a
    `#` inside a string is never mistaken for a comment and a real finding hidden.
    ponytail: trailing-comment false positives remain; upgrade to a real tokenizer
    only if they prove noisy on real skills.
    """
    if lang == "javascript":
        text = _BLOCK_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), text)
        prefix = "//"
    elif lang in ("python", "bash", "other"):
        prefix = "#"
    else:
        return text
    out = []
    for line in text.split("\n"):
        out.append("" if line.lstrip().startswith(prefix) else line)
    return "\n".join(out)


def scan_regex(f: SourceFile) -> list[Finding]:
    out: list[Finding] = []
    original = f.text.splitlines()
    scanned = _strip_comments(f.text, f.lang).splitlines()
    for i, line in enumerate(scanned, start=1):
        for det in _REGEX:
            if det.pattern.search(line):
                evidence = original[i - 1].strip() if i - 1 < len(original) else line.strip()
                out.append(Finding(
                    check=det.check, severity=det.severity, file=f.path,
                    message=det.message, evidence=evidence[:200],
                    line=i, capability=det.capability,
                ))
    return out


def scan_opaque(opaque_paths: tuple[str, ...]) -> list[Finding]:
    """One HIGH finding per bundled file we cannot read as source.

    A compiled or binary artifact is an execution surface a static reader is blind
    to — treat "can't inspect" as "don't trust", not as clean.
    """
    return [
        Finding(
            check="opaque-binary", severity="high", file=path, capability="exec",
            message="opaque/compiled bundled file — cannot inspect, do not trust",
        )
        for path in opaque_paths
    ]


# --- python AST tier --------------------------------------------------------
def _is_name(node: ast.AST, names: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in names


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[Finding] = []

    def _add(self, check, severity, capability, message, node) -> None:
        self.findings.append(Finding(
            check=check, severity=severity, file=self.path, message=message,
            line=getattr(node, "lineno", 0), capability=capability,
        ))

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        # exec(...) / eval(...)
        if _is_name(func, {"exec", "eval"}):
            self._add("dynamic-exec", "critical", "exec",
                      f"AST: dynamic {func.id}() call", node)
        # __import__(...) / importlib.import_module(...)
        if _is_name(func, {"__import__"}) or (
            isinstance(func, ast.Attribute) and func.attr == "import_module"
        ):
            self._add("dynamic-import", "medium", "exec",
                      "AST: dynamic import", node)
        # getattr(x, name)(...) — attribute-built call
        if isinstance(func, ast.Call) and _is_name(func.func, {"getattr"}):
            self._add("dynamic-call", "medium", "exec",
                      "AST: getattr-built dynamic call", node)
        self.generic_visit(node)


def scan_python_ast(f: SourceFile) -> list[Finding]:
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        # unparseable or hostile-to-parse python: regex tier still covered it;
        # never let a crafted file crash the scan.
        return []
    v = _Visitor(f.path)
    v.visit(tree)
    return v.findings


def all_checks() -> tuple[Callable[[SourceFile], list[Finding]], ...]:
    return (scan_regex,)
