# Changelog

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
