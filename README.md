# MCP Drift Check

[![CI](https://github.com/tomelias10/mcp-drift-check/actions/workflows/ci.yml/badge.svg)](https://github.com/tomelias10/mcp-drift-check/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

### Your MCP config did not change. The code it resolves to might have.

**MCP Drift Check is a zero-execution security preflight for MCP package references.** It finds `@latest`, bare package references, and version ranges in common JavaScript package runners that can silently resolve to different code later.

**No MCP server execution · No package downloads · No API token · No signup · No telemetry**

**Public evidence:** in a documented 2026-09-25 GitHub code-search sample, **232 of 259** parsed public `.mcp.json` files containing npm/npx package references had at least one `HIGH` mutable reference. This is a **retrieved search sample, not an ecosystem prevalence estimate**. [Method + dataset](research/public-mcp-drift-census-2026-09-25.md) · [Reproduction script](scripts/public_census.py)

## Run it now

**No install:** [scan a public GitHub repository in the browser](https://orynval.com/mcp-drift-check). The browser preflight checks only public MCP config paths and never executes repository code or MCP servers.

### Share a live repo result

After scanning a public repository, copy the generated README badge from the result page. The badge reports only MCP dependency-drift findings — it is **not** a general security score.

```markdown
[![MCP Drift Check](https://orynval.com/api/mcp-badge?repo=OWNER%2FREPO)](https://orynval.com/mcp-drift-check?repo=OWNER%2FREPO)
```

The badge updates from bounded public MCP config paths and links back to a shareable zero-execution scan.

With `uv` installed, run directly from GitHub without installing the package globally:

```bash
uvx --from git+https://github.com/tomelias10/mcp-drift-check mcp-drift-check scan-workspace
```

Or install with pip:

```bash
python3 -m pip install git+https://github.com/tomelias10/mcp-drift-check.git
mcp-drift-check scan-workspace
```

Scan one file:

```bash
mcp-drift-check scan .mcp.json
```

## Use it as an agent skill

The repository also ships a portable Agent Skill for Claude Code, Codex, Cursor, and other skill-aware coding agents:

[`skills/mcp-dependency-drift-audit/SKILL.md`](skills/mcp-dependency-drift-audit/SKILL.md)

The skill preserves the same safety boundary: read MCP configuration statically, never execute discovered server commands, and never turn dependency mutability into an unsupported compromise claim.

## Add it to any GitHub repo

```yaml
name: MCP dependency drift
on: [push, pull_request]

jobs:
  mcp-drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
      - uses: tomelias10/mcp-drift-check@40e9f6760c56a0621f8aa8d91579ada77bd7414f # v0.3.1 tested
```

That scans **workspace MCP config locations only** by default, produces a Markdown report in the GitHub Actions job summary, adds visible GitHub PR annotations for non-safe findings, and fails the check when a `HIGH` mutable package reference is found.

Want findings in GitHub Code Scanning too? The action also emits SARIF:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
  - id: mcp
    uses: tomelias10/mcp-drift-check@40e9f6760c56a0621f8aa8d91579ada77bd7414f # v0.3.1 tested
    with:
      fail-on-high: 'false'
  - uses: github/codeql-action/upload-sarif@1190a975f95ce23525efb6a3fc21ea29567c1b52 # v3
    with:
      sarif_file: ${{ steps.mcp.outputs.sarif-file }}
  - if: steps.mcp.outputs.exit-code == '1'
    run: exit 1
```

## What it looks like

```text
MCP Drift Check
================================================
MCP server entries: 3

HIGH   1 mutable package references
MEDIUM 1 non-exact package selectors
SAFE   1 exact-version package references

HIGH   github-mcp
       package: example-package
       reason: Package version is not pinned; future resolution may select different package code.
       recommendation: Pin example-package to a reviewed exact version.
```

## Why this exists

Many MCP clients can launch servers through package runners such as `npx`, `bunx`, `pnpm dlx`, and `yarn dlx`. A configuration can remain unchanged while package resolution changes later. That creates a review gap: code running today may not be the same package version that was reviewed previously.

This tool finds that condition. It does **not** claim that an unpinned dependency is malicious or compromised.

## Public example of the review gap

This is not only a hypothetical packaging pattern. Microsoft has a public issue for GitHub Copilot for Azure titled **“Consider pinning Azure MCP”** where the project notes that its `.mcp.json` references the `@latest` Azure MCP package and discusses the tradeoff between automatic updates and mismatches between the reviewed/configured tools and the package version that actually resolves.

- Microsoft issue: https://github.com/microsoft/GitHub-Copilot-for-Azure/issues/3045

That issue is an example of the configuration-review problem this tool detects. It is **not** evidence that Azure MCP is malicious or compromised, and Microsoft does not endorse this project.

## What it checks

Current package-runner coverage includes `npx`, `npm exec` / `npm x`, `bunx` / `bun x`, `pnpm dlx`, `yarn dlx`, and `uvx`:

- exact versions such as `package@1.2.3` → `SAFE`
- bare packages such as `package` → `HIGH`
- explicit `package@latest` → `HIGH`
- version ranges such as `package@^1.2.0` → `MEDIUM`
- `uvx` references use PEP 508 selectors: `pkg==1.2.3` → `SAFE`, `pkg>=1.0` → `MEDIUM`, bare `pkg` → `HIGH`; URLs, local paths and wheels → `REVIEW`
- local or unknown executables → `REVIEW`
- `-y` / `--yes` is reported as context; it is not treated as a vulnerability by itself

Known-location discovery covers common Claude Desktop, Claude Code, Cursor, VS Code, GitHub Copilot, Windsurf and generic MCP config paths where present, including repo-scoped `.mcp.json`, `.github/mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, and `.windsurf/mcp.json`. Use `scan-workspace` for repo-only scope (the GitHub Action default) and `scan-all` only when you intentionally want user-level plus workspace configs.

## Example

```text
MCP Drift Check
================================================
MCP server entries: 3

HIGH   1 mutable package references
MEDIUM 1 non-exact package selectors
SAFE   1 exact-version package references

HIGH  github-mcp
      command: npx -y example-package
      reason: Package version is not pinned; future resolution may select different package code.
      recommendation: Pin example-package to a reviewed exact version.
```

## What it does NOT claim

- An unpinned dependency is not automatically malicious.
- A newer package version is not automatically compromised.
- A mutable package reference is not proof of exploitation.
- Pinning alone does not make an MCP integration secure.
- This tool does not test authorization, prompt injection, tool poisoning, data exposure, or runtime behavior.

It identifies a **change and review risk** that a security team may want to investigate.

## Public examples

We documented seven concrete public repositories where MCP configs contained mutable npm/npx package references. This is a **targeted examples set, not a prevalence study**. See the [public research page](https://orynval.com/research/mcp-dependency-drift) or [`research/public-mcp-dependency-drift-examples.md`](research/public-mcp-dependency-drift-examples.md).

## Public GitHub code-search sample

On 2026-09-25, the documented search method returned **296** de-duplicated hits whose exact basename was `.mcp.json`. We fetched and parsed **295** of them; **259** contained npm/npx package references, and **232** of those configs contained at least one `HIGH` mutable package reference. Across the sample, the classifier saw **392** npm/npx package references: 360 `HIGH`, 3 `MEDIUM`, and 29 `SAFE`.

These numbers describe **only the retrieved GitHub code-search sample**. GitHub search ranking is not random and result limits cap the sample, so the counts must **not** be presented as the prevalence of mutable dependencies across the MCP ecosystem. They also do not imply that any package is malicious or compromised.

- [Methodology and snapshot](research/public-mcp-drift-census-2026-09-25.md)
- [Sanitized machine-readable dataset](research/public-mcp-drift-census-2026-09-25.json)
- [Reproduction script](scripts/public_census.py)

## Why we built this

While researching public MCP configurations, we observed repeated patterns where package references were mutable after the configuration was written. The census above turns that observation into a reviewable dataset while preserving the boundary between **dependency mutability** and unsupported compromise claims.

## For security teams

For a machine-wide inventory that intentionally includes both user-level and current-workspace MCP configs, use:

```bash
mcp-drift-check scan-all --json > mcp-drift-findings.json
```

The output includes client, config path, server name, command, package, declared version, classification, reason and recommendation.

## Private security review

Found this pattern in a production AI environment?

Do **not** post sensitive configuration, credentials, access tokens, customer information, internal URLs or proprietary data in a public GitHub issue.

Request a private security review: **https://orynval.com/security-triage?utm_source=github&utm_medium=repo&utm_campaign=mcp_drift_check**

A review can help determine:

- whether the finding is actually exploitable
- what changed
- what access the MCP integration has
- whether credentials or data could be exposed
- what should be remediated
- how to verify the fix

## Privacy and safety

MCP Drift Check is static and local by design. It does not execute configured server commands, contact package registries, download dependencies, collect telemetry, or transmit findings. Common credential-bearing command arguments (for example `--api-key`, `--token`, `API_KEY=...`, and Authorization headers) are redacted from text and JSON reports. Avoid placing secrets directly in command arguments when possible.

## Development

```bash
python3 -m unittest discover -s tests -v
```

## Responsible disclosure

See [SECURITY.md](SECURITY.md).

## License

MIT
