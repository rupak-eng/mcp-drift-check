from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from . import cli as core


def build_parser():
    parser = core.build_parser()
    parser.add_argument(
        "--clone-timeout",
        type=int,
        default=60,
        help="Maximum seconds allowed for cloning a public GitHub repository",
    )
    return parser


def _clone_public_repo(repo: str, destination: Path, timeout: int) -> Path:
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
        timeout=max(1, timeout),
    )
    return destination


def render_markdown(target: str, findings: list[core.Finding]) -> str:
    rendered = core.render_markdown(target, findings)
    if "orynval.com/security-triage" not in rendered:
        rendered += (
            "\n\n## Need verification?\n\n"
            "If this is a production system, request a private Orynval security review: "
            "https://orynval.com/security-triage"
        )
    return rendered


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    target = args.target
    local = Path(target).expanduser()
    temp_dir = None
    try:
        if local.exists():
            if not local.is_dir():
                raise ValueError("Local target must be a directory.")
            root = local.resolve()
        else:
            temp_dir = tempfile.TemporaryDirectory(prefix="orynval-security-check-")
            root = _clone_public_repo(target, Path(temp_dir.name) / "repo", args.clone_timeout)

        findings = core.scan_repository(root, max_files=max(1, args.max_files))
        if args.as_json:
            rendered = json.dumps(
                {
                    "target": target,
                    "summary": core._severity_counts(findings),
                    "findings": [f.to_dict() for f in findings],
                    "limitations": [
                        "Static zero-execution preflight",
                        "Heuristic findings can include false positives or miss vulnerabilities",
                        "No runtime authorization, exploitability, cloud-account, or network testing",
                    ],
                    "private_review": "https://orynval.com/security-triage",
                },
                indent=2,
            )
        else:
            rendered = render_markdown(target, findings)

        print(rendered)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
        return 1 if any(f.severity == "HIGH" for f in findings) else 0
    except subprocess.TimeoutExpired:
        print(
            f"orynval-security-check: repository clone exceeded {max(1, args.clone_timeout)} seconds",
            file=sys.stderr,
        )
        return 2
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"orynval-security-check: {exc}", file=sys.stderr)
        return 2
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


if __name__ == "__main__":
    sys.exit(main())
