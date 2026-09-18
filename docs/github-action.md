# Using bastionskill in CI

Gate a repository so a poisoned skill can't merge. Add a workflow that runs the
scanner and fails the build at your chosen severity.

```yaml
# .github/workflows/skill-scan.yml
name: skill-scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Rinkia/bastionskill@v0.1.0
        with:
          path: ./skills        # dir holding one or many skills
          fail-on: high         # critical|high|medium|low|none
          # report: scan.json   # optional signable manifest artifact
```

The step exits non-zero when any finding is at `fail-on` or worse, blocking the
PR. Run it against a directory of skills to scan them all in one pass.

Prefer a plain step instead of the action? It is just the CLI:

```yaml
      - run: pipx run bastionskill scan ./skills --fail-on high
```
