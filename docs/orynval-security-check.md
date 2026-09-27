# Orynval Security Check — MVP

Orynval Security Check is a static, zero-execution preflight for public GitHub repositories and local source trees.

It is intentionally broader than MCP Drift Check. The first MVP combines several buyer-relevant signals into one report:

- potential committed secrets (reported with values redacted)
- GitHub Actions permission risks
- mutable third-party GitHub Action references
- mutable JavaScript and Python dependency selectors
- non-immutable Docker base images
- MCP package-reference drift via the existing MCP Drift Check engine
- basic repository security hygiene

## Run locally

```bash
python -m pip install .
orynval-security-check owner/repo
```

Or scan a local checkout:

```bash
orynval-security-check ./path/to/repository
```

Machine-readable output:

```bash
orynval-security-check owner/repo --json
```

Write a shareable report:

```bash
orynval-security-check owner/repo --output report.md
```

## GitHub Actions MVP

The repository contains a manually-triggered workflow named **Orynval Security Check**. Supply a public `owner/repo` target and it produces a Markdown report as both the job summary and a downloadable workflow artifact.

The target repository is cloned as data only. Orynval Security Check does not execute target scripts, build steps, package managers, MCP servers, containers, or workflow code.

## Safety boundary

This tool is a preflight, not a penetration test. It does not claim exploitability or compromise. Heuristic findings can contain false positives and the absence of findings does not imply a repository is secure.

It does not perform runtime authorization testing, network probing, cloud-account inspection, exploit attempts, or authenticated testing.

## Commercial funnel

The public report ends with a private-review path:

**Free static preflight → concrete finding → private verification → remediation scope → paid Orynval security review**

Production findings should not be pasted into public issues. Use the private triage path:

https://orynval.com/security-triage

## Next product steps

1. Add a web endpoint on orynval.com that accepts `owner/repo` and returns the report.
2. Add optional Trivy/Gitleaks/OpenSSF integrations while preserving license attribution and a no-target-code-execution boundary.
3. Add shareable result URLs and narrowly-scoped badges.
4. Track scan-to-triage conversion rather than GitHub stars as the primary business metric.
5. Use verified recurring findings to decide which checks become proprietary Orynval detection modules.
