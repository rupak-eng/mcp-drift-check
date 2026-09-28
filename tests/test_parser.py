import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from mcp_drift_check.parser import parse_config

FIX=Path(__file__).parent / "fixtures"

class ParserTests(unittest.TestCase):
    def test_multiple_servers(self):
        findings=parse_config(FIX/"mutable.json")
        self.assertEqual(len(findings), 3)
        self.assertEqual([f.classification for f in findings], ["HIGH","HIGH","MEDIUM"])

    def test_safe_scoped_package(self):
        f=parse_config(FIX/"safe.json")[0]
        self.assertEqual(f.package, "@scope/server")
        self.assertEqual(f.declared_version, "1.2.3")
        self.assertEqual(f.classification, "SAFE")

    def test_malformed_config(self):
        f=parse_config(FIX/"malformed.json")[0]
        self.assertEqual(f.classification, "REVIEW")
        self.assertIn("could not be parsed", f.reason)

    def test_embedded_command_string(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"npx -y package@1.2.3"}}}')
            f=parse_config(p)[0]
            self.assertEqual(f.classification, "SAFE")
            self.assertEqual(f.package, "package")

    def test_unknown_command_review(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"dotnet","args":["server.dll"]}}}')
            self.assertEqual(parse_config(p)[0].classification, "REVIEW")

    def test_local_executable_review(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"./server"}}}')
            self.assertEqual(parse_config(p)[0].classification, "REVIEW")


    def test_sensitive_command_args_are_redacted(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"npx","args":["package@1.2.3","--api-key","super-secret-value","--token=another-secret"]}}}')
            f=parse_config(p)[0]
            self.assertEqual(f.classification, "SAFE")
            self.assertNotIn("super-secret-value", f.command)
            self.assertNotIn("another-secret", f.command)
            self.assertIn("[REDACTED]", f.command)

    def test_sensitive_env_style_arg_is_redacted(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"env","args":["API_KEY=very-secret","./server"]}}}')
            f=parse_config(p)[0]
            self.assertNotIn("very-secret", f.command)
            self.assertIn("API_KEY=[REDACTED]", f.command)

    def test_malformed_shell_quoting_is_review(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text(json.dumps({"mcpServers": {"x": {"command": 'npx \"unterminated'}}}))
            f=parse_config(p)[0]
            self.assertEqual(f.classification, "REVIEW")
            self.assertIn("malformed shell quoting", f.reason)


    def test_bunx_latest_is_high(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"bunx","args":["@playwright/mcp@latest"]}}}')
            f=parse_config(p)[0]
            self.assertEqual((f.package, f.declared_version, f.classification), ("@playwright/mcp", "latest", "HIGH"))

    def test_bun_x_exact_is_safe(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"bun","args":["x","pkg@1.2.3"]}}}')
            f=parse_config(p)[0]
            self.assertEqual((f.package, f.declared_version, f.classification), ("pkg", "1.2.3", "SAFE"))

    def test_pnpm_dlx_bare_is_high(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"pnpm","args":["dlx","@scope/pkg"]}}}')
            f=parse_config(p)[0]
            self.assertEqual((f.package, f.declared_version, f.classification), ("@scope/pkg", None, "HIGH"))

    def test_yarn_dlx_range_is_medium(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"yarn","args":["dlx","pkg@^2.0.0"]}}}')
            f=parse_config(p)[0]
            self.assertEqual((f.package, f.declared_version, f.classification), ("pkg", "^2.0.0", "MEDIUM"))

    def test_npm_exec_with_separator(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"npm","args":["exec","--","@scope/pkg@2.0.0"]}}}')
            f=parse_config(p)[0]
            self.assertEqual((f.package, f.declared_version, f.classification), ("@scope/pkg","2.0.0","SAFE"))


    def test_uvx_bare_is_high(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"uvx","args":["mcp-server-fetch"]}}}')
            f=parse_config(p)[0]
            self.assertEqual((f.package, f.declared_version, f.classification), ("mcp-server-fetch", None, "HIGH"))

    def test_uvx_pinned_is_safe(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"uvx","args":["mcp-server-fetch==1.2.3"]}}}')
            f=parse_config(p)[0]
            self.assertEqual((f.package, f.declared_version, f.classification), ("mcp-server-fetch", "==1.2.3", "SAFE"))

    def test_uvx_from_flag_selects_package(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"uvx","args":["--from","mcp-server-fetch==1.0.0","mcp-server-fetch"]}}}')
            f=parse_config(p)[0]
            self.assertEqual((f.package, f.declared_version, f.classification), ("mcp-server-fetch", "==1.0.0", "SAFE"))

    def test_uvx_from_equals_form(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"uvx","args":["--from=mcp-server-fetch>=2.0","mcp-server-fetch"]}}}')
            f=parse_config(p)[0]
            self.assertEqual((f.package, f.classification), ("mcp-server-fetch", "MEDIUM"))

    def test_uvx_flag_values_are_not_packages(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"uvx","args":["--with","pydantic","-p","3.12","mcp-server-fetch"]}}}')
            f=parse_config(p)[0]
            self.assertEqual((f.package, f.classification), ("mcp-server-fetch", "HIGH"))

    def test_uvx_local_path_is_review(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"uvx","args":["./local-server"]}}}')
            f=parse_config(p)[0]
            self.assertEqual(f.classification, "REVIEW")
            self.assertIn("local path", f.reason)

    def test_uvx_git_url_is_review(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"uvx","args":["--from","git+https://github.com/org/srv","srv"]}}}')
            f=parse_config(p)[0]
            self.assertEqual(f.classification, "REVIEW")

    def test_uvx_no_args_is_review(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"mcp.json"
            p.write_text('{"mcpServers":{"x":{"command":"uvx","args":[]}}}')
            self.assertEqual(parse_config(p)[0].classification, "REVIEW")

if __name__ == "__main__": unittest.main()
