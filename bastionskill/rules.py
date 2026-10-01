"""Every check bastionskill can report: what it means and what to check by hand.

One entry per check name. `bastionskill rules` prints the table, and every finding
carries its rule's `why` / `what_to_check` in text, JSON and SARIF output.
tests/test_rules.py fails if a detector emits a check that has no entry here.

`verdict` is the check's effect on its own: `block`, `review`, or `informational`
(a capability the code has; it only matters through the correlations noted).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

_SHADOW = "informational; review if SKILL.md doesn't declare it (shadow)"
_SHADOW_EXFIL = _SHADOW + " or with a secret read (exfil-combo)"
_SECRET_EXFIL = _SHADOW + " or with network egress (exfil-combo)"


@dataclass(frozen=True)
class Rule:
    check: str
    kind: str          # capability | malice | shadow (as the finding is tagged)
    verdict: str
    why: str
    what_to_check: str


def _r(check, kind, verdict, why, what) -> Rule:
    return Rule(check, kind, verdict, why, what)


_ALL = (
    # --- block / review: malice -----------------------------------------------------
    _r("staged-exec", "malice", "block",
       "Decodes a hidden payload and pipes it straight into a shell or interpreter.",
       "Decode the payload by hand and read it; there is no honest reason to hide code this way."),
    _r("obfuscation", "malice", "review",
       "Ships base64-encoded content that is decoded at run time, hiding what runs.",
       "Decode it and confirm it's data (an icon, a fixture), not code that gets executed."),
    _r("remote-exec", "malice", "review",
       "Downloads code at run time and executes it, so the code that runs was never scanned.",
       "Open the URL's script; prefer a pinned version or a checksum-verified download."),
    _r("raw-ip-egress", "malice", "review",
       "Sends to a hardcoded public IP, bypassing DNS and any domain allowlist.",
       "Find out who owns the IP and why a hostname isn't used."),
    _r("keylogger", "malice", "review",
       "Captures keystrokes, which a skill has no honest reason to do.",
       "Find what the captured keys are used for and where they're sent; treat as hostile until explained."),
    _r("opaque-binary", "malice", "review",
       "Bundles a compiled or binary file the scanner can't read.",
       "Rebuild it from source you trust, or remove it."),
    _r("exfil-combo", "malice", "review",
       "Reads secrets and also has network egress: the shape of data theft.",
       "Trace each secret read to its use and confirm it never reaches the network call."),
    _r("shadow", "shadow", "review",
       "The code exercises a capability that SKILL.md never declares (or explicitly disclaims).",
       "Read the flagged files; either the description is incomplete or the code does something hidden."),
    # --- capabilities: informational, escalate through shadow / exfil-combo --------
    _r("network-egress", "capability", _SHADOW_EXFIL,
       "Makes network calls (HTTP clients, sockets, curl/wget).",
       "List the hosts it contacts and confirm each matches what the skill says it does."),
    _r("git-exfil", "capability", _SHADOW_EXFIL,
       "Pushes the repo to an explicit external URL or to a remote it just pointed elsewhere.",
       "Check the remote URL belongs to you and the push is part of the skill's declared job."),
    _r("secret-read", "capability", _SECRET_EXFIL,
       "Reads credential material (SSH keys, cloud credentials, .env, keychains).",
       "Confirm the skill needs this secret and where the value goes after it's read."),
    _r("clipboard-read", "capability", _SECRET_EXFIL,
       "Reads the clipboard, which often holds passwords and tokens.",
       "Confirm the clipboard read is the skill's purpose and the content stays local."),
    _r("env-dump", "capability", _SECRET_EXFIL,
       "Serializes or lists the whole environment, where API keys and tokens live.",
       "Replace with reads of the specific variables it needs; check where the dump is written or sent."),
    _r("hook-install", "capability", _SHADOW,
       "Registers an agent hook or writes agent settings, so code runs after this skill.",
       "Read the hook command and confirm installing it is the skill's declared job."),
    _r("persistence", "capability", _SHADOW,
       "Installs OS-level persistence (cron, launchd, registry Run keys, systemd).",
       "Confirm the skill must survive reboots, and what the persisted command runs."),
    _r("lateral-tamper", "capability", _SHADOW,
       "Writes to agent config, CLAUDE.md, MCP config or other skills.",
       "Diff those files before and after; a skill shouldn't rewrite other skills or agent config."),
    _r("destructive", "capability", _SHADOW,
       "Runs destructive filesystem or disk commands (rm -rf, mkfs, dd, shred).",
       "Check the target paths are fixed and scoped to the skill's own files."),
    _r("dynamic-exec", "capability", "informational",
       "Executes code or shell commands built at run time (eval, exec, subprocess).",
       "Check the executed string can't be influenced by fetched or user-controlled input."),
    _r("dynamic-import", "capability", "informational",
       "Imports a module whose name is computed at run time (Python).",
       "Check where the module name comes from; it can load code the scan never saw."),
    _r("dynamic-call", "capability", "informational",
       "Calls a function looked up by name at run time (getattr-built call, Python).",
       "Check the attribute name is a constant, not derived from input or fetched data."),
    # --- prompt layer (scan --prompt) ------------------------------------------------
    _r("hidden-unicode", "capability", "informational",
       "SKILL.md's description contains invisible or bidi-reordering characters.",
       "View the description with invisible characters shown; hidden text is a prompt-injection trick."),
    _r("prompt-layer-note", "capability", "informational",
       "Only the hidden-unicode prompt check ran; full prompt-injection scanning lives in bastionsupply.",
       "pip install bastionsupply to scan SKILL.md text for injection."),
)

RULES: dict[str, Rule] = {r.check: r for r in _ALL}


def as_dicts() -> list[dict]:
    return [asdict(r) for r in _ALL]


def why(check: str) -> str:
    r = RULES.get(check)
    return r.why if r else ""


def what_to_check(check: str) -> str:
    r = RULES.get(check)
    return r.what_to_check if r else ""
