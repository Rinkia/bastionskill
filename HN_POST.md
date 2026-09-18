# Launch blurbs

Pick per channel. All link to the repo / PyPI. Try-it line works with zero setup:
`pip install bastionskill && bastionskill scan Rinkia/poisoned-skill-demo`

---

## Hacker News (Show HN)

**Title:**
Show HN: bastionskill – scan an AI agent skill for malicious code before you install it

**Body:**

Agent "skills" (Claude Code skills, and the same shape elsewhere) are a SKILL.md
plus bundled scripts. When the agent invokes the skill, those scripts run — and a
skill can install a hook that keeps running after. So installing a skill off
GitHub is running a stranger's code, but people clone them the way they'd copy a
snippet: without looking.

bastionskill statically scans the *bundled code* — no LLM, no execution, and it
reads the source regardless of `if False:` / env-flag guards, because malware
hides behind those too. It flags:

- hook-install / persistence (a script writing a PostToolUse hook into settings.json) — the scariest vector, so it leads
- network egress, secret reads (~/.aws, id_rsa, .env), obfuscation (base64 | sh, eval(atob)), destructive commands
- opaque binaries — a bundled .so/.exe/.pyc, caught by magic bytes even when renamed to look benign (a static reader is blind to a compiled payload, so "can't inspect" = "don't trust")
- the shadow: capabilities the code exercises that SKILL.md never declared. A "markdown formatter" that opens a socket is the whole idea in one finding.

Python files get a real `ast` pass on top of regex; bash/JS are regex.

I dogfooded it on my own ~/.claude/skills — 642 skills — and it reshaped the tool.
A first pass flagged 12 on raw capability, but they were legit high-capability dev
tools, not malware. So capability isn't the verdict. The current model separates
what the code *can do* (informational) from poisoning *signals*: a skill either
`allow`s, needs `review` (a shadow = capability the code uses that SKILL.md never
declared, or obfuscation, or an opaque binary, or reads-secrets-plus-egress), or
hard-`block`s (a staged-exec: decode piped to a shell — no honest use). Same 642
skills now: 0 false blocks, 9 review, 633 allow. The poisoned demo still blocks.
It also caught bundled .exes I'd forgotten were there.

Try it on the intentionally-malicious (inert, defanged) demo skill straight off
GitHub:

    pip install bastionskill
    bastionskill scan Rinkia/poisoned-skill-demo

It scans a local dir, a whole skills folder, or a remote repo pre-flight (shallow
clone, never runs the skill). `--fail-on` makes it a CI gate; there's a GitHub
Action; `harden` emits a policy for the rest of my agent-security suite.

It's the 7th tool in that suite (scan / prevent / attack / investigate / gate) —
bastionskill is the code-layer sibling of bastionsupply, which does the same for
MCP servers.

Repo: https://github.com/Rinkia/bastionskill
Zero required dependencies, MIT. Feedback most welcome on the detector set and on
the verdict-model question above — where's the line between "powerful skill" and
"poisoned skill"?

---

## Reddit (r/netsec, r/LocalLLaMA, r/ClaudeAI)

**Title:**
bastionskill: open-source scanner for skill-poisoning — catch malicious code in an agent skill before you install it

**Body:**

Agent skills bundle scripts that execute when the skill runs (and can install
hooks that persist after). Installing one off GitHub is running someone else's
code, but there's no habit of scanning it first.

bastionskill is a static, offline, zero-dependency scanner for the *code layer*
of a skill. It flags hook-install/persistence, network egress, secret reads,
obfuscation (`base64 | sh`, `eval(atob())`), destructive commands, and opaque
bundled binaries (magic-byte sniff — catches a renamed .so/.exe). Python gets an
AST pass; bash/JS are regex. Findings fire even behind dead-code guards, since
it reads source instead of running it.

The differentiating check is the **shadow**: capabilities the code exercises that
SKILL.md never declared. A skill that says "formats markdown" but opens a socket
gets called out directly. Verdict is allow / review / block — capability alone is
informational (a legit power-tool has plenty), only poisoning signals (shadow,
obfuscation, opaque binary, secrets+egress, staged-exec) drive review/block.

I ran it against my own 642 installed skills: 0 false blocks, 9 review, 633 allow
(and it caught bundled .exes). An early capability-based pass flagged 12 legit
power-tools — which is exactly why the verdict model separates capability from
malice.

Try it on the inert malicious demo:

    pip install bastionskill
    bastionskill scan Rinkia/poisoned-skill-demo

Local dir / whole skills folder / remote repo pre-flight. `--fail-on` for CI,
GitHub Action included, `harden` emits an agentbastion/bastiongate policy. MIT.

Repo: https://github.com/Rinkia/bastionskill
Demo fixture: https://github.com/Rinkia/poisoned-skill-demo

---

## X / short

Shipped bastionskill: scan an AI agent skill for malicious code before you install it.

Skills bundle scripts that run on invoke (and can install hooks). bastionskill
statically flags hook-install, egress, secret theft, obfuscation, opaque
binaries — and the shadow: what the code does that SKILL.md never declared.

Try it on the inert malicious demo, zero setup:

    pip install bastionskill
    bastionskill scan Rinkia/poisoned-skill-demo

Dogfooded on my own 642 skills. Zero deps, MIT.
github.com/Rinkia/bastionskill

---

## X / thread version (optional)

1/ Installing an AI agent "skill" off GitHub = running a stranger's code. A skill
is a SKILL.md + bundled scripts that execute when invoked, and one can install a
hook that persists after. Nobody scans them first. So I built a scanner.

2/ bastionskill statically reads the bundled code (no LLM, no execution) and
flags: hook-install/persistence (the lead), network egress, secret reads,
obfuscation, destructive commands, and opaque/renamed binaries via magic bytes.

3/ The best check is the shadow: capabilities the code exercises that SKILL.md
never declared. "Formats markdown" + opens a socket = one finding that says what's
wrong.

4/ Dogfooded on my own 642 installed skills: 0 false blocks, 9 review, 633 allow,
caught bundled .exes. Verdict separates capability (informational) from poisoning
signals — capability isn't malice, the shadow is the tell.

5/ Try it on the inert, defanged malicious demo, zero setup:
   pip install bastionskill
   bastionskill scan Rinkia/poisoned-skill-demo
   MIT, zero deps. github.com/Rinkia/bastionskill

---

## One-liner (README badge / directory listings)

Static scanner for skill-poisoning: catch malicious bundled code — hook-install
persistence, egress, secret theft, opaque binaries — in an agent skill before you
install it.
