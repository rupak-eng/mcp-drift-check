# Contributing

Thanks for helping make MCP configuration review more reproducible. First-time contributors are welcome.

## Before you start

1. Check the [open issues](../../issues) and [open pull requests](../../pulls) so we do not build the same fix twice.
2. If an issue already exists, leave a short comment that you want to work on it before coding. For larger changes, wait for a maintainer response before investing significant time.
3. Keep one focused problem per pull request. Small, reviewable PRs are much easier to merge quickly.
4. Prefer documented config locations and reproducible fixtures over assumptions about client behavior.

Look for `good first issue` and `help wanted` labels if you want a bounded place to start.

## Good contributions

- support for additional documented MCP client config locations
- package selector edge cases with small fixtures
- redaction improvements
- output integrations such as SARIF and CI
- public examples that can be independently verified without active testing

## Pull request checklist

- link the issue or explain the concrete gap
- add or update tests for behavior changes
- keep discovery bounded; do not crawl unrelated filesystems
- preserve workspace-only behavior where the GitHub Action expects it
- avoid unrelated formatting or refactors in the same PR
- update user-facing docs when behavior changes
- state what you tested

## Safety boundary

MCP Drift Check is intentionally static. Contributions must not execute discovered MCP server commands, download discovered packages, probe remote systems, or transmit users' configurations by default.

Do not include real credentials, private configs, customer data, internal URLs, or exploit details in public fixtures or issues.

## Test

```bash
python -m pip install .
python -m unittest discover -s tests -v
```

Please keep findings factual: a mutable dependency is a review/reproducibility risk, not proof that a package is malicious or compromised.
