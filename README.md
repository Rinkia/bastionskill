# bastionskill

Static scanner for **skill-poisoning**. Point it at an agent skill (a `SKILL.md`
plus its bundled scripts) and it inspects the *bundled executable code* for
malicious behavior — then reports the **shadow**: what the code does that the
skill's description never declared.

Agent skills bundle scripts that run when the skill is invoked, and can install
hooks that run afterward. That is an arbitrary-code-execution surface. bastionskill
is the code-layer leg of the bastion suite; the prompt-layer (malicious SKILL.md
text) is [bastionsupply](https://github.com/Rinkia/bastionsupply)'s job.

## Install

```bash
pip install bastionskill
# optional: full prompt-layer scanning via bastionsupply
pip install "bastionskill[prompt]"
```

Zero required dependencies. Python 3.10+.

## Use

```bash
bastionskill scan ./some-skill              # scan a local skill dir
bastionskill scan ~/.claude/skills          # batch-scan every skill under a dir
bastionskill scan owner/repo                # pre-flight a REMOTE skill (shallow clone, no exec)
bastionskill scan https://github.com/o/r    #   ... by full URL
bastionskill scan ./skill --prompt          # + hidden-unicode / prompt-layer
bastionskill scan ./skill --json            # machine-readable
bastionskill scan ./skill --report out.json # signable manifest (per-file hashes, verdict)
bastionskill scan ./skill --record          # append result to the local ledger
bastionskill scan ./skill --fail-on block   # CI gate: block|review|none (default: review)
bastionskill harden ./skill -o skill-policy.yaml   # agentbastion/bastiongate policy
bastionskill ledger                         # list previously scanned skills + dates
```

## Verdict, not a wall of severities

The scan ends in one of three verdicts, because capability is not malice — a legit
power-tool exercises network, secrets, and hooks too:

- **allow** — clean, or capability the skill legitimately has (even a lot of it).
- **review** — a poisoning *signal* a human should eyeball: a **shadow** (the code
  exercises a capability `SKILL.md` never declared), obfuscation, an opaque binary,
  or the exfil pattern (reads secrets *and* has egress).
- **block** — hard malice with no honest use: a staged-exec (decode piped to a shell).

Capability findings are reported as informational context, not as blockers.
`--fail-on` (`block|review|none`, default `review`) is the CI gate. See
[docs/github-action.md](docs/github-action.md).

**Remote pre-flight** shallow-clones the repo to a temp dir, scans statically, and
deletes it. The skill's own code is never executed.

**Ledger & rug-pull.** `--record` writes each scan to `~/.bastionskill/ledger.jsonl`
(source, content hash, date, verdict). Re-scan the same source after it changes and
you get a `! DRIFT` warning — the poisoned-update vector.

## What it catches (code-layer)

| Detector | Example |
|---|---|
| **hook-install (lead)** | a script that writes a `PostToolUse` hook into `settings.json` = persistence |
| network egress | `socket.connect`, `requests.post`, `curl`/`wget`, `fetch()` |
| secret read | `~/.aws/credentials`, `id_rsa`, `.env` |
| obfuscation | `base64 -d | sh`, `eval(atob(...))` |
| dynamic exec | `exec()`, `eval()`, `getattr(m,n)()` (Python AST tier) |
| destructive | `rm -rf`, `Remove-Item -Recurse` |
| lateral-tamper | writes to `CLAUDE.md`, MCP config, or other skills |
| **opaque-binary** | bundles a compiled/loadable file it can't inspect (incl. renamed binaries, magic-byte sniffed) |
| **shadow** | code exercises a capability SKILL.md never declared |

Python files get a real `ast` pass (stdlib) on top of regex, so dynamic exec /
import / attribute-built calls survive reflow. Bash and JS use regex heuristics.

Findings are reported **regardless of dead-code or `if False:` / env-flag guards** —
the scanner reads source, it never runs it, and malware hides behind guards too.

## How it fits the suite

- Prompt-layer → [bastionsupply](https://github.com/Rinkia/bastionsupply) (dependency, optional extra)
- Runtime gating → bastiongate
- `harden` emits an agentbastion / bastiongate skill policy (allow/deny + blocked capabilities)

## Test fixture

The inert, defanged demo skill this scanner is built against lives at
[Rinkia/poisoned-skill-demo](https://github.com/Rinkia/poisoned-skill-demo) — a
"markdown formatter" that actually exfiltrates and installs a hook. See its
`EXPECTED.md` for the findings oracle.

```bash
bastionskill scan Rinkia/poisoned-skill-demo   # scan the demo straight off GitHub
```

## License

MIT © 2026 Stefano Rizzello
