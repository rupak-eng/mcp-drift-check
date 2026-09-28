import unittest
from mcp_drift_check.classifier import classify_package, classify_uvx_spec, split_package_spec

class ClassifierTests(unittest.TestCase):
    def test_bare_package_high(self):
        self.assertEqual(classify_package("package")[2], "HIGH")

    def test_latest_high(self):
        self.assertEqual(classify_package("package@latest")[2], "HIGH")

    def test_exact_safe(self):
        self.assertEqual(classify_package("package@1.2.3")[2], "SAFE")

    def test_range_medium(self):
        self.assertEqual(classify_package("package@^1.2.3")[2], "MEDIUM")

    def test_scoped_exact(self):
        name, version = split_package_spec("@scope/package@1.2.3")
        self.assertEqual((name, version), ("@scope/package", "1.2.3"))
        self.assertEqual(classify_package("@scope/package@1.2.3")[2], "SAFE")

    def test_auto_yes_context(self):
        self.assertIn("-y/--yes", classify_package("package", True)[3])


class UvxClassifierTests(unittest.TestCase):
    def test_bare_is_high(self):
        package, version, level, _, _ = classify_uvx_spec("mcp-server-fetch")
        self.assertEqual((package, version, level), ("mcp-server-fetch", None, "HIGH"))

    def test_exact_pin_is_safe(self):
        package, version, level, _, _ = classify_uvx_spec("mcp-server-fetch==1.2.3")
        self.assertEqual((package, version, level), ("mcp-server-fetch", "==1.2.3", "SAFE"))

    def test_arbitrary_equality_pin_is_safe(self):
        self.assertEqual(classify_uvx_spec("pkg===1.2.3")[2], "SAFE")

    def test_range_is_medium(self):
        self.assertEqual(classify_uvx_spec("mcp-server-fetch>=1.0")[2], "MEDIUM")

    def test_compatible_release_is_medium(self):
        self.assertEqual(classify_uvx_spec("mcp-server-fetch~=1.2")[2], "MEDIUM")

    def test_wildcard_pin_is_medium(self):
        self.assertEqual(classify_uvx_spec("mcp-server-fetch==1.2.*")[2], "MEDIUM")

    def test_compound_specifier_is_medium(self):
        self.assertEqual(classify_uvx_spec("mcp-server-fetch>=1.0,<2.0")[2], "MEDIUM")

    def test_extras_are_stripped(self):
        package, version, level, _, _ = classify_uvx_spec("mcp-server-fetch[cli]==1.2.3")
        self.assertEqual((package, version, level), ("mcp-server-fetch", "==1.2.3", "SAFE"))

    def test_markers_are_stripped(self):
        self.assertEqual(classify_uvx_spec('mcp-server-fetch==1.2.3; python_version>"3.8"')[2], "SAFE")

    def test_url_is_review_not_registry(self):
        package, version, level, _, _ = classify_uvx_spec("git+https://github.com/org/mcp-server-fetch")
        self.assertEqual(level, "REVIEW")
        self.assertIsNone(version)

    def test_local_path_is_review(self):
        self.assertEqual(classify_uvx_spec("./local-server")[2], "REVIEW")
        self.assertEqual(classify_uvx_spec("/opt/servers/srv")[2], "REVIEW")

    def test_wheel_is_review(self):
        self.assertEqual(classify_uvx_spec("mcp-server-fetch-1.2.3-py3-none-any.whl")[2], "REVIEW")

    def test_at_selector_is_unsupported_review(self):
        # PEP 508 has no pkg@version form; guessing would misclassify pins.
        package, version, level, reason, _ = classify_uvx_spec("mcp-server-fetch@1.2.3")
        self.assertEqual(level, "REVIEW")
        self.assertIn("PEP 508", reason)

    def test_unrecognized_selector_is_review(self):
        self.assertEqual(classify_uvx_spec("mcp-server-fetch~~1.2")[2], "REVIEW")


if __name__ == "__main__": unittest.main()
