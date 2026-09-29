# Changelog

## 0.6.0

- **New detector `remote-exec`** (high, malice → verdict **review**): code fetched at
  run time and executed, so the code that actually runs was never scanned. Catches
  `curl|wget … | sh/bash/python/…` (incl. `sudo`), `bash -c "$(curl …)"`,
  `bash <(curl …)` / `. <(curl …)`, PowerShell `iwr|irm … | iex` and
  `iex (…DownloadString(…))`, Python `exec(requests.get(…).text)` /
  `eval(urlopen(…).read())`, and JS `eval(… fetch(…))`. Not auto-block: honest
  installers (rustup, nvm, Homebrew) use the same shape, so a human decides.
  `curl … | base64 -d | sh` still blocks (staged-exec).
- Dogfood on 664 real skills: 1 skill hit (gstack's bun installer, plus an attack
  string in one of its test files); no verdict changed.

## 0.5.0

- **`install`: the skill verdict now has a reader that enforces it.**
  `bastionskill install TARGET --to DIR [--policy FILE]` copies a skill (local, a
  folder of skills, or remote) into a skills dir only if it passes. It stages the
  copy and scans + hashes that copy, so the decision covers exactly the bytes
  installed. Without a policy the scan decides at `--fail-on` (default `review`).
  With a `harden` policy, a `deny` (by name or digest) refuses, and an `allow` counts
  only when its `digest` matches: reviewers can approve a `review`-rated skill, for
  those exact bytes only. All-or-nothing for a folder; the skill's own
  `.bastionskillignore` is ignored; symlinks refused; `--force` to replace. The
  staging copy lives next to the skills dir, never inside it (an agent must not load an
  unvetted copy, even after a crash), and install names can't leave `--to`.
- **`harden` pins each verdict with a `digest`** (sha256 over the path + bytes of
  every file `install` copies, SKILL.md and data included) and covers **every**
  skill in a folder, not just the first; colliding names are keyed by path. The
  output header now names `install --policy` as its reader.
- Dogfood: `harden ~/.claude/skills` on 664 real skills (557 nested copies) in ~14 s,
  every verdict pinned.

## 0.4.0

- **`harden` emits a `policy_version: 2` skill verdict.** The verdict moves under the
  `skill:` block the shared v2 format reserves for bastionskill, and the top-level
  `default: allow` is gone. The old file was labelled an agentbastion/bastiongate
  policy, but neither reads skill verdicts, and its `default: allow` loaded there as
  an allow-every-tool policy: a file that looked like enforcement and did nothing.
  Now both load it as valid v2 with no tool policy and ignore the `skill:` block. The
  docs say plainly that the verdict is for skill loaders and CI (`scan --fail-on` is
  the enforcement today).

## 0.3.0

- **SARIF output**: `bastionskill scan --sarif` emits SARIF 2.1.0 so bundled-code
  findings upload to GitHub code scanning. Each result carries a physicalLocation
  (file + line), with `kind`/`capability` as result properties; severity maps to
  level (critical/high→error, medium→warning, low→note).

## 0.2.0 (unreleased)

Verdict-model rework — capability is not malice (from the 642-skill dogfood).

- **Three verdicts** (`allow` / `review` / `block`) replace severity-driven deny.
  Every finding has a `kind`: `capability` (informational), `malice`, or `shadow`.
- `block` = staged-exec (decode piped to a shell); `review` = shadow, obfuscation,
  opaque binary, or exfil-combo (secrets + egress together); `allow` = clean, or
  capability the skill legitimately has (even a lot of it).
- New **exfil-combo** correlation: reads secrets AND has network egress.
- `--fail-on` is now `block|review|none` (default `review`).
- Report leads with the verdict + the malice/shadow reasons, then a one-line
  capability summary — no more wall of CRITICAL/HIGH on legit power-tools.
- Dogfood impact on 642 real skills: was 12 deny → now 0 false blocks, 9 review,
  633 allow. The poisoned demo still blocks.
- Manifest, ledger, and `harden` all key off the verdict now.

## 0.1.0 (unreleased)

First cut. Code-layer only; prompt-layer delegated to bastionsupply.

- Load a skill dir: parse SKILL.md `description`, collect bundled `.py/.sh/.js/...` files.
- Code-layer detectors: hook-install/persistence (lead), network egress, secret
  read, obfuscation, dynamic exec, destructive — regex tier for all languages plus
  a Python `ast` tier (dynamic exec / import / getattr-built call).
- Shadow detection: flag capabilities the code exercises that SKILL.md never declared.
- Findings fire regardless of dead-code / `if False:` / env-flag guards.
- `scan` (text/JSON) and `harden` (agentbastion/bastiongate skill policy) commands.
- Optional `--prompt` hidden-unicode check; `[prompt]` extra pulls bastionsupply.
- Zero required dependencies.

### before-GH cut (added)

- **Remote pre-flight**: `scan owner/repo` / URL shallow-clones to temp, scans, discards (never executes skill code).
- **Batch scan**: a dir of many skills → per-skill verdict + summary.
- **Opaque/binary detection**: bundled compiled/loadable files flagged HIGH; magic-byte sniff catches renamed binaries and skips images/fonts.
- **Noise control**: `.bastionskillignore` (skip globs + `suppress <check>`) and full-line comment stripping (kills the comment false-positives).
- **lateral-tamper** detector: writes to CLAUDE.md / MCP config / other skills.
- **CI**: `--fail-on <sev>` exit threshold, GitHub composite action (`action.yml`), example workflow + docs.
- **Signable report**: `--report out.json` — versioned manifest with per-file sha256, content hash, verdict.
- **Local ledger**: `--record` + `bastionskill ledger`; drift/rug-pull warning on changed re-scan.
- Hardening: AST tier can't be crashed by hostile input (broadened except); local path always wins over remote heuristics.
