# bastionskill — future work

Deferred out of the before-GH cut. Roughly priority order.

## From the 2026-09-18 dogfood (642 real skills)

- **Verdict model rework (top v0.2).** Dogfood: 630/642 clean, 12 deny — but the 12
  are legit high-capability tools (gstack crit134/high535, browse, make-pdf), not
  malice. Raw capability is too blunt a deny driver. Plan: capability findings →
  INFO by default; **deny only on the malice signals** — shadow, obfuscation,
  opaque-binary, staged-exec, and combinations — not on raw network/exec presence.
- **Shadow is description-dependent.** It correctly isolates undeclared powers on
  simple skills (hackernews-frontpage → network) but "FPs" on power-tools whose
  terse SKILL.md just omits its real powers. Consider: only shadow when the
  description makes a positive scope claim, or weight shadow by description richness.
- (done) dist/build binary gap — opaque detection now sweeps dist/build while still
  skipping their source noise; node_modules/.git stay fully skipped.

## Post-launch, near term (v0.2)

- **SARIF output** (`--sarif`). Findings render inline in GitHub PR code-scanning.
  Another report writer; big adoption multiplier for the CI story.
- **`lock` / `verify` commands.** The ledger already detects drift on `--record`;
  promote it to explicit pin/verify (a committed `skill.lock` of file hashes) so a
  repo can gate updates in CI, not just locally.
- **Broaden detectors:**
  - git-exfil (`git remote add` + `git push` to an external host)
  - install-time `curl … | sh` fetch-then-exec in setup scripts
  - egress to raw IP literals and non-allowlisted domains
  - clipboard read / env dump / keylog patterns
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

- **Real bastionsupply prompt-layer wiring.** `prompt.py` is a stub + hidden-unicode
  only; wire the actual bastionsupply injection detectors via the `[prompt]` extra.
- **Publish parity with the other bastion repos:** `.gitattributes` forcing LF on
  `.sh`, OIDC PyPI publish on GitHub Release, optional GHCR image (like MonoHunter).
- **Add to bastiondefense.dev** (tools.ts + docs + pricing) — *after* GitHub + PyPI
  are live, with working repo/install links.

## Detector coverage gaps (known ceilings)

- Renamed/extension-less binaries: magic-byte sniff covers ELF/PE/Mach-O/wasm/class/
  dex; packed or exotic formats slip. Upgrade: broader magic table or entropy check.
- More languages: PowerShell/Ruby/Perl get regex only (no AST tier). Add AST tiers
  if those become common in skills.
- Typosquatting: detect a skill name impersonating a popular one (sibling idea from
  bastionsupply homoglyph work).
