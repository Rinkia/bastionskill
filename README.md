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
bastionskill scan ./some-skill            # code-layer scan
bastionskill scan ./some-skill --prompt   # + hidden-unicode / prompt-layer
bastionskill scan ./some-skill --json     # machine-readable
bastionskill harden ./some-skill -o skill-policy.yaml   # agentbastion policy
```

Exit code is non-zero when a critical/high finding is present — drop it in CI as a
pre-install gate.

## What it catches (code-layer)

| Detector | Example |
|---|---|
| **hook-install (lead)** | a script that writes a `PostToolUse` hook into `settings.json` = persistence |
| network egress | `socket.connect`, `requests.post`, `curl`/`wget`, `fetch()` |
| secret read | `~/.aws/credentials`, `id_rsa`, `.env` |
| obfuscation | `base64 -d | sh`, `eval(atob(...))` |
| dynamic exec | `exec()`, `eval()`, `getattr(m,n)()` (Python AST tier) |
| destructive | `rm -rf`, `Remove-Item -Recurse` |
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

The inert, defanged demo skill this scanner is built against lives in
`poisoned-skill-demo/` — a "markdown formatter" that actually exfiltrates and
installs a hook. See its `EXPECTED.md` for the findings oracle.

## License

MIT © 2026 Stefano Rizzello
