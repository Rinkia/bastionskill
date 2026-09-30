# bastionskill — future work

Deferred out of the before-GH cut. Roughly priority order.

## From the 2026-09-18 dogfood (642 real skills)

- (done in v0.2) **Verdict model rework.** Capability findings are now
  informational; verdict is allow/review/block driven by malice + shadow +
  exfil-combo, not raw capability. Dogfood: 12 deny → 0 false blocks / 9 review /
  633 allow. Demo still blocks.
- **Shadow is still description-dependent (open).** It "FPs" to REVIEW on
  power-tools whose terse SKILL.md omits real powers (gstack, browse). Now a
  review not a block, so less painful — but consider: only shadow when the
  description makes a positive scope claim ("offline", "no network"), or weight
  shadow by description richness, or a per-skill allowlist/baseline of accepted
  capabilities.
- (done) dist/build binary gap — opaque detection now sweeps dist/build while still
  skipping their source noise; node_modules/.git stay fully skipped.

## Post-launch, near term

- (done in v0.3.0) **SARIF output** (`--sarif`). Findings render inline in GitHub PR
  code-scanning.
- (done in v0.5.0) **A reader for the skill verdict.** `bastionskill install
  --policy` enforces `harden`'s verdicts, pinned by content digest. Still open: a
  runtime loader check (the agent loading a skill that changed after install; today
  `scan --record` + ledger drift catches it after the fact).
- (done in v0.7.0) **`lock` / `verify` commands.** The ledger already detects drift on `--record`;
  promote it to explicit pin/verify (a committed `skill.lock` of file hashes) so a
  repo can gate updates in CI, not just locally.
- **Broaden detectors:**
  - (done in v0.8.0) git-exfil: push to an explicit URL (per-line: a remote added in
    one command and pushed in another is still missed)
  - (done in v0.6.0) install-time `curl … | sh` fetch-then-exec: `remote-exec`
  - (done in v0.8.0) egress to raw public IP literals: `raw-ip-egress`. Still open:
    non-allowlisted **domains** (needs a user-supplied allowlist)
  - (done in v0.8.0) clipboard read / env dump / keylog: `clipboard-read`, `env-dump`,
    `keylogger`
  - (done in the cut: writes to CLAUDE.md / MCP config / other skills = `lateral-tamper`)
- **`rules` command + per-finding remediation.** `bastionskill rules` lists every
  detector; each finding gets a one-line "why risky / what to check." Trust + docs.
- **Trailing-comment / in-string awareness.** Current comment stripping only blanks
  full-line comments (ponytail note in checks.py). A real per-language tokenizer
  kills the remaining trailing-comment false positives — only if they prove noisy.

## Central data / study (the Supabase question)

- **Supabase sink for scan outcomes.** The ledger line + the manifest schema are
  already flat and hash-pinned so a sink is a thin adapter. Before building:
  - decide what leaves the machine (verdict + hashes only? or file contents?),
  - privacy stance + opt-in (never upload skill source by default),
  - a stable anonymous id, key handling.
  - Value: a cross-machine registry of clean/dirty skills + longitudinal drift =
    the data exhaust that later justifies the **certification** product.
- **Public clean/dirty skill registry** built from that data. Prerequisite for cert.

## Trust / commercial

- **True report signing** (sigstore/cosign or gpg) over the manifest. Format exists;
  add the signature. First real step toward "Bastion-certified".
- **Certification surface** — only after the scanner is a de-facto standard and the
  registry has data. Scanner first; cert is the exhaust.

## Suite-fit & publish parity

- **Real bastionsupply prompt-layer wiring (open).** `prompt.py` still checks only
  hidden unicode and whether bastionsupply is importable; it never calls its
  detectors. Wire them via the `[prompt]` extra.
- (done) **Publish parity:** `.gitattributes` forces LF on `.sh`; OIDC PyPI publish on
  GitHub Release. Still optional: a GHCR image (like MonoHunter), only if someone asks.
- (done 2026-09-18) **On bastiondefense.dev** (tools.ts + docs + pricing), versions
  refreshed from PyPI.

## Detector coverage gaps (known ceilings)

- Renamed/extension-less binaries: magic-byte sniff covers ELF/PE/Mach-O/wasm/class/
  dex; packed or exotic formats slip. Upgrade: broader magic table or entropy check.
- More languages: PowerShell/Ruby/Perl get regex only (no AST tier). Add AST tiers
  if those become common in skills.
- Typosquatting: detect a skill name impersonating a popular one (sibling idea from
  bastionsupply homoglyph work).
