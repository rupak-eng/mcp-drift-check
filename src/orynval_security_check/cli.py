from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from mcp_drift_check.discovery import workspace_config_paths
from mcp_drift_check.parser import parse_config

EXCLUDED_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
    "__pycache__", ".next", "coverage", "target",
}
MAX_FILE_BYTES = 1_000_000
TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".toml",
    ".ini", ".cfg", ".conf", ".env", ".sh", ".bash", ".zsh", ".md", ".txt",
    ".properties", ".xml", ".rb", ".go", ".rs", ".java", ".kt", ".kts",
}

SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "HIGH"),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"), "HIGH"),
    ("github-fine-grained-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"), "HIGH"),
    ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "HIGH"),
    ("openai-api-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "HIGH"),
]

DEPENDENCY_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    title: str
    path: str
    line: int | None = None
    evidence: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _iter_text_files(root: Path, max_files: int) -> Iterable[Path]:
    count = 0
    for path in root.rglob("*"):
        if count >= max_files:
            break
        if not path.is_file():
            continue
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        if path.name in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock", "poetry.lock"}:
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"Dockerfile", "requirements.txt", "SECURITY.md"}:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        count += 1
        yield path


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def scan_secrets(root: Path, max_files: int) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_text_files(root, max_files):
        text = _read_text(path)
        if text is None:
            continue
        for idx, line in enumerate(text.splitlines(), start=1):
            for name, pattern, severity in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        severity=severity,
                        category="secrets",
                        title=f"Potential {name} committed to the repository",
                        path=_relative(path, root),
                        line=idx,
                        evidence="Matched a high-confidence credential pattern. Secret value is intentionally redacted.",
                        recommendation="Rotate the credential if real, remove it from the repository and history, then enable secret scanning/pre-commit prevention.",
                    ))
    return findings


def _action_ref_is_pinned(ref: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", ref))


def scan_github_workflows(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.exists():
        return findings
    for path in list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")):
        text = _read_text(path) or ""
        rel = _relative(path, root)
        lines = text.splitlines()
        for idx, line in enumerate(lines, start=1):
            if re.search(r"^\s*pull_request_target\s*:", line):
                findings.append(Finding(
                    severity="MEDIUM",
                    category="github-actions",
                    title="Workflow uses pull_request_target",
                    path=rel,
                    line=idx,
                    evidence="pull_request_target executes in the base-repository security context and requires careful handling of untrusted PR data.",
                    recommendation="Keep checkout/execution of untrusted PR code out of this job, or switch to pull_request when privileged access is unnecessary.",
                ))
            if re.search(r"^\s*permissions\s*:\s*write-all\s*$", line):
                findings.append(Finding(
                    severity="HIGH",
                    category="github-actions",
                    title="Workflow grants write-all permissions",
                    path=rel,
                    line=idx,
                    evidence="The workflow grants broad write permissions to GITHUB_TOKEN.",
                    recommendation="Use least-privilege permissions and grant only the specific write scopes required by the job.",
                ))
            match = re.search(r"\buses:\s*([^\s#]+)@([^\s#]+)", line)
            if match and not match.group(1).startswith("./") and not _action_ref_is_pinned(match.group(2)):
                findings.append(Finding(
                    severity="MEDIUM",
                    category="supply-chain",
                    title="GitHub Action is not pinned to an immutable commit",
                    path=rel,
                    line=idx,
                    evidence=f"{match.group(1)} uses a mutable ref ({match.group(2)}).",
                    recommendation="Pin third-party actions to a reviewed 40-character commit SHA and document the human-readable release tag in a comment.",
                ))
    return findings


def _dependency_is_mutable(spec: str) -> bool:
    value = spec.strip()
    if value in {"", "*", "latest", "next"}:
        return True
    prefixes = ("github:", "git+", "http://", "https://")
    if value.startswith(prefixes):
        return True
    return value.startswith("^") or value.startswith("~") or "||" in value


def scan_package_json(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in root.rglob("package.json"):
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for section in DEPENDENCY_SECTIONS:
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                if isinstance(spec, str) and _dependency_is_mutable(spec):
                    findings.append(Finding(
                        severity="LOW",
                        category="dependencies",
                        title="JavaScript dependency uses a mutable selector",
                        path=_relative(path, root),
                        evidence=f"{name}: {spec}",
                        recommendation="For high-assurance builds, prefer lockfiles and reviewed exact versions; assess update automation separately.",
                    ))
    return findings


def scan_requirements(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in root.rglob("requirements*.txt"):
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        text = _read_text(path) or ""
        for idx, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(("-", ".")):
                continue
            if "==" not in line and not re.search(r"@\s*(?:file:|https?://)", line):
                findings.append(Finding(
                    severity="LOW",
                    category="dependencies",
                    title="Python dependency is not exactly pinned",
                    path=_relative(path, root),
                    line=idx,
                    evidence=line[:180],
                    recommendation="For reproducible deployments, consider exact resolved versions or a lockfile with integrity data.",
                ))
    return findings


def scan_dockerfiles(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in root.rglob("Dockerfile*"):
        if any(part in EXCLUDED_DIRS for part in path.parts) or not path.is_file():
            continue
        text = _read_text(path) or ""
        for idx, raw in enumerate(text.splitlines(), start=1):
            match = re.match(r"^\s*FROM\s+([^\s]+)", raw, flags=re.IGNORECASE)
            if not match:
                continue
            image = match.group(1)
            if "@sha256:" in image:
                continue
            if ":" not in image or image.endswith(":latest"):
                findings.append(Finding(
                    severity="MEDIUM",
                    category="containers",
                    title="Container base image is not immutable",
                    path=_relative(path, root),
                    line=idx,
                    evidence=f"Base image reference: {image}",
                    recommendation="Pin production base images by digest and use automated tooling to review digest updates.",
                ))
    return findings


def scan_mcp(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for client, path in workspace_config_paths(cwd=root):
        try:
            mcp_findings = parse_config(path, client)
        except Exception as exc:
            findings.append(Finding(
                severity="INFO",
                category="mcp",
                title="MCP configuration could not be parsed",
                path=_relative(path, root),
                evidence=type(exc).__name__,
                recommendation="Review the MCP configuration format manually.",
            ))
            continue
        for item in mcp_findings:
            severity = {
                "HIGH": "HIGH",
                "MEDIUM": "MEDIUM",
                "REVIEW": "LOW",
                "SAFE": "INFO",
            }.get(item.classification, "INFO")
            if severity == "INFO":
                continue
            findings.append(Finding(
                severity=severity,
                category="mcp",
                title="Mutable MCP package reference",
                path=_relative(path, root),
                evidence=f"{item.server_name}: {item.package or item.command}",
                recommendation=item.recommendation,
            ))
    return findings


def scan_hygiene(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not (root / "SECURITY.md").exists() and not (root / ".github" / "SECURITY.md").exists():
        findings.append(Finding(
            severity="INFO",
            category="repository-hygiene",
            title="No SECURITY.md found",
            path=".",
            evidence="The repository does not expose a standard vulnerability-reporting policy file.",
            recommendation="Add SECURITY.md with supported versions and a private vulnerability reporting path.",
        ))
    if not (root / ".github" / "dependabot.yml").exists():
        findings.append(Finding(
            severity="INFO",
            category="repository-hygiene",
            title="No Dependabot configuration found",
            path=".github/dependabot.yml",
            evidence="No repository-level Dependabot configuration was detected.",
            recommendation="Consider automated dependency update tooling if it fits the project workflow.",
        ))
    return findings


def scan_repository(root: Path, max_files: int = 5000) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(scan_secrets(root, max_files))
    findings.extend(scan_github_workflows(root))
    findings.extend(scan_package_json(root))
    findings.extend(scan_requirements(root))
    findings.extend(scan_dockerfiles(root))
    findings.extend(scan_mcp(root))
    findings.extend(scan_hygiene(root))
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    return sorted(findings, key=lambda f: (order.get(f.severity, 9), f.category, f.path, f.line or 0))


def _clone_public_repo(repo: str, destination: Path) -> Path:
    match = re.fullmatch(r"(?:https://github\.com/)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?", repo)
    if not match:
        raise ValueError("Target must be a local path or a public GitHub repository in owner/repo form.")
    owner, name = match.groups()
    url = f"https://github.com/{owner}/{name}.git"
    subprocess.run(
        ["git", "clone", "--depth", "1", "--filter=blob:none", "--no-tags", url, str(destination)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    return destination


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def render_markdown(target: str, findings: list[Finding]) -> str:
    counts = _severity_counts(findings)
    lines = [
        "# Orynval Security Check",
        "",
        f"Target: `{target}`",
        "",
        f"**{counts['HIGH']} HIGH · {counts['MEDIUM']} MEDIUM · {counts['LOW']} LOW · {counts['INFO']} INFO**",
        "",
        "> Static, zero-execution preflight. Findings are signals to verify, not proof of compromise and not a penetration test.",
        "",
    ]
    if not findings:
        lines.append("No findings in the checks currently implemented.")
        return "\n".join(lines)
    lines.extend(["## Findings", ""])
    for finding in findings:
        location = finding.path + (f":{finding.line}" if finding.line else "")
        lines.extend([
            f"### {finding.severity} — {finding.title}",
            f"- Category: `{finding.category}`",
            f"- Location: `{location}`",
        ])
        if finding.evidence:
            lines.append(f"- Evidence: {finding.evidence}")
        if finding.recommendation:
            lines.append(f"- Recommendation: {finding.recommendation}")
        lines.append("")
    lines.extend([
        "## Need verification?",
        "",
        "If this is a production system, request a private Orynval security review: https://orynval.com/security-triage",
    ])
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="orynval-security-check",
        description="Static, zero-execution security preflight for a local folder or public GitHub repository.",
    )
    parser.add_argument("target", help="Local path, owner/repo, or https://github.com/owner/repo")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Print machine-readable JSON")
    parser.add_argument("--output", type=Path, help="Also write the report to this path")
    parser.add_argument("--max-files", type=int, default=5000, help="Maximum text files inspected for secret patterns")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    target = args.target
    local = Path(target).expanduser()
    temp_dir = None
    try:
        if local.exists():
            root = local.resolve()
        else:
            temp_dir = tempfile.TemporaryDirectory(prefix="orynval-security-check-")
            root = _clone_public_repo(target, Path(temp_dir.name) / "repo")
        findings = scan_repository(root, max_files=max(1, args.max_files))
        if args.as_json:
            rendered = json.dumps({
                "target": target,
                "summary": _severity_counts(findings),
                "findings": [f.to_dict() for f in findings],
                "limitations": [
                    "Static zero-execution preflight",
                    "Heuristic findings can include false positives or miss vulnerabilities",
                    "No runtime authorization, exploitability, cloud-account, or network testing",
                ],
            }, indent=2)
        else:
            rendered = render_markdown(target, findings)
        print(rendered)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
        return 1 if any(f.severity == "HIGH" for f in findings) else 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"orynval-security-check: {exc}", file=sys.stderr)
        return 2
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


if __name__ == "__main__":
    sys.exit(main())
