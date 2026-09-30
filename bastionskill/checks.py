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
    kind: str = "capability"


def _d(check, severity, capability, regex, message, flags=0, kind="capability") -> Detector:
    return Detector(check, severity, capability, re.compile(regex, flags), message, kind)


# --- regex tier -------------------------------------------------------------
# v0.2: most detectors report a CAPABILITY (what the code can do) — informational,
# it never blocks on its own. Only obfuscation / staged-exec are MALICE (no honest
# use). The verdict is driven by kind + the shadow/exfil correlation in scanner.py,
# not by raw capability count — a legit power-tool shouldn't read as malware.
_REGEX: tuple[Detector, ...] = (
    # persistence / hook install — capability (blocks only when undeclared -> shadow)
    _d("hook-install", "medium", "persistence",
       r"\b(Post|Pre|User(Prompt|)|Stop|Notification)ToolUse\b|\bPostToolUse\b|\bPreToolUse\b",
       "installs an agent hook (runs after this skill, persistence)"),
    _d("hook-install", "low", "persistence",
       r"settings\.json|\.claude[\\/](settings|hooks)|[\\/]hooks[\\/]",
       "writes to agent settings/hooks (persistence surface)"),
    _d("lateral-tamper", "medium", "persistence",
       r"CLAUDE\.md|mcp\.json|claude_desktop_config|[\\/]skills[\\/]|\.mcp\.json",
       "writes to agent config / other skills (lateral tampering)"),
    _d("persistence", "medium", "persistence",
       r"\bcrontab\b|LaunchAgents|LaunchDaemons|\bHKCU\b|\bHKLM\b|systemctl\s+enable",
       "installs OS-level persistence (cron/launchd/registry/systemd)"),
    # network egress — capability
    _d("network-egress", "medium", "network",
       r"\bsocket\.socket\b|\.connect\(\s*\(|\.sendall\(|\.sendto\(",
       "raw socket network egress"),
    _d("network-egress", "low", "network",
       r"\brequests\.(get|post|put|patch|delete)\b|\burllib\.request\b|\bhttp\.client\b|\bfetch\(|\baxios\b",
       "HTTP client call (possible exfiltration)"),
    _d("network-egress", "low", "network",
       r"\bcurl\b|\bwget\b|Invoke-WebRequest|Invoke-RestMethod",
       "shells out to a network client (curl/wget/Invoke-WebRequest)"),
    # secret read — capability
    _d("secret-read", "medium", "secrets",
       r"\.aws[\\/]credentials|id_rsa|id_ed25519|\.ssh[\\/]|\.git-credentials|\.npmrc|KUBECONFIG|keychain",
       "reads credential/secret material"),
    _d("secret-read", "low", "secrets",
       r"(^|[\s\"'/=@])\.env\b",
       "reads a .env secrets file"),
    # clipboard read / env dump — capability "secrets": the clipboard holds passwords and
    # tokens, the environment holds API keys. With egress they become exfil-combo.
    _d("clipboard-read", "medium", "secrets",
       r"\bpbpaste\b|\bxclip\b[^\n]*\s-o(?:ut)?\b|\bxsel\b[^\n]*(?:\s-o\b|--output)|\bwl-paste\b"
       r"|\bGet-Clipboard\b|pyperclip\.paste\(|\bclipboard\.read(?:Text)?\(|Clipboard\.GetText\(",
       "reads the clipboard (often holds passwords/tokens)", re.I),
    _d("env-dump", "medium", "secrets",
       # bare `env`/`printenv` only as a shell COMMAND (not `f(env)`, not `env X=1 cmd`);
       # iterating process.env to filter it for a child process is not a dump
       r"(?:^\s*|[;&|]\s*)(?:printenv|env)\s*(?:$|[|>;&])"
       r"|json\.dumps\([^\n]*\bos\.environ\b(?!\s*(?:\[|\.get\b))|\bstr\(\s*os\.environ\s*\)"
       r"|JSON\.stringify\(\s*process\.env\s*[,)]"
       r"|\b(?:Get-ChildItem|gci|ls|dir)\s+env:",
       "dumps the whole environment (API keys and tokens live there)", re.I),
    # git exfil — capability "network": pushing the repo (or anything committed to it)
    # to an explicit URL, directly or via a remote added on the same line. Adding a
    # remote alone sends nothing (test fixtures do it constantly). Honest deploys push
    # too, so it escalates only via shadow (undeclared network) or exfil-combo.
    # ponytail: per-line; a remote added in one command and pushed in another is missed.
    _d("git-exfil", "medium", "network",
       r"\bgit\b[^\n]*?\bpush\b[^\n]*?(?:https?://|ssh://|git@[\w.-]+:)"
       r"|\bgit\b[^\n]*?\bremote\s+(?:add|set-url)\b[^\n]*?(?:https?://|ssh://|git@[\w.-]+:)[^\n]*\bgit\b[^\n]*\bpush\b",
       "git push to an explicit external URL (repo contents leave the machine)"),
    # raw public IP — MALICE (review): a hardcoded public IPv4 destination skips DNS and
    # any domain allowlist. Loopback / private / link-local ranges are excluded.
    _d("raw-ip-egress", "high", "network",
       r"(?:\b(?:https?|wss?|ftp)://(?:[^/\s@]*@)?|\b(?:connect|connect_ex|create_connection)\(\s*\(\s*['\"])"
       r"(?!(?:127|10|0)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)"
       r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])",
       "network destination is a hardcoded public IP (skips DNS / domain allowlists)", kind="malice"),
    # keylogger — MALICE (review): keystroke capture has no honest use in a skill.
    _d("keylogger", "high", "secrets",
       r"\b(?:from|import)\s+pynput\b|\bkeyboard\.(?:Listener|on_press|on_release|hook|read_key|record)\b"
       r"|\bGetAsyncKeyState\b|\bSetWindowsHookEx\w*|\bWH_KEYBOARD_LL\b|\bu?iohook\b|\bCGEventTapCreate\b",
       "captures keystrokes (keylogger)", kind="malice"),
    # obfuscation — MALICE (staged-exec is the only auto-block: decode piped to a shell)
    _d("staged-exec", "critical", "exec",
       r"base64\s+(-d|--decode)[^\n|]*\|\s*(sh|bash|python|node)\b",
       "decodes then pipes to an interpreter (staged exec)", kind="malice"),
    _d("obfuscation", "high", "exec",
       r"base64\s+(-d|--decode)|b64decode|atob\(|FromBase64String",
       "base64-decoded payload (obfuscation)", kind="malice"),
    # remote exec — MALICE, review not block: code fetched at run time and executed
    # was never scanned (a blind spot by construction), but honest installers
    # (rustup, nvm, Homebrew) use the same shape, so a human decides.
    _d("remote-exec", "high", "exec",
       r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?"
       r"(?:sh|bash|zsh|dash|ksh|python\d?(?:\.\d+)?|perl|ruby|node|php|pwsh|powershell|source)\b"
       r"|\b(?:sh|bash|zsh|python\d?)\s+(?:-c\s+)?[\"']?\$\(\s*(?:curl|wget)\b"
       r"|(?:\b(?:bash|sh|zsh|source)|^\s*\.)\s+<\(\s*(?:curl|wget)\b"
       r"|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(?:iex|Invoke-Expression)\b"
       r"|\b(?:iex|Invoke-Expression)\b[^\n]*(?:\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b|DownloadString)"
       r"|\b(?:exec|eval)\(\s*(?:requests\.get|httpx\.get|(?:urllib\.request\.)?urlopen)\("
       r"|\b(?:eval|Function)\([^\n]*\bfetch\(",
       "fetches remote code and executes it (the code that runs was never scanned)",
       re.I, kind="malice"),
    # dynamic exec — capability (many legit tools shell out / exec)
    _d("dynamic-exec", "medium", "exec",
       r"\beval\(|\bexec\(|\bsystem\(|subprocess\.(Popen|call|run|check_output)|os\.popen",
       "dynamic / shell execution"),
    # destructive — capability
    _d("destructive", "medium", "destructive",
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
                    line=i, capability=det.capability, kind=det.kind,
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
            kind="malice",
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
