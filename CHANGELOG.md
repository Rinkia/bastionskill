# Changelog

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
