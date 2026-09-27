import json
import tempfile
import unittest
from pathlib import Path

from orynval_security_check.cli import scan_repository
from orynval_security_check.runtime import render_markdown


class OrynvalSecurityCheckTests(unittest.TestCase):
    def test_static_scan_finds_multiple_security_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "ci.yml").write_text(
                "name: CI\non: [push]\npermissions: write-all\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
                encoding="utf-8",
            )
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"example": "^1.2.3"}}),
                encoding="utf-8",
            )
            (root / "Dockerfile").write_text("FROM python:latest\n", encoding="utf-8")
            (root / "example.env").write_text(
                "KEY=-----BEGIN PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            (root / ".mcp.json").write_text(
                json.dumps({"mcpServers": {"demo": {"command": "npx", "args": ["-y", "example-package"]}}}),
                encoding="utf-8",
            )

            findings = scan_repository(root)
            categories = {item.category for item in findings}
            severities = {item.severity for item in findings}

            self.assertIn("secrets", categories)
            self.assertIn("github-actions", categories)
            self.assertIn("supply-chain", categories)
            self.assertIn("dependencies", categories)
            self.assertIn("containers", categories)
            self.assertIn("mcp", categories)
            self.assertIn("HIGH", severities)

    def test_report_never_prints_secret_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = "ghp_" + ("A" * 36)
            (root / "config.txt").write_text(f"TOKEN={secret}\n", encoding="utf-8")

            findings = scan_repository(root)
            report = render_markdown("demo/repo", findings)

            self.assertIn("Potential github-token", report)
            self.assertNotIn(secret, report)
            self.assertIn("orynval.com/security-triage", report)

    def test_clean_report_still_has_private_review_path(self):
        report = render_markdown("demo/clean", [])
        self.assertIn("No findings in the checks currently implemented.", report)
        self.assertIn("orynval.com/security-triage", report)


if __name__ == "__main__":
    unittest.main()
