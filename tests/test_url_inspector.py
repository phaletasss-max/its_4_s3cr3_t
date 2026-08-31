import unittest

from secret_tools.errors import ToolError
from secret_tools.url_inspector import inspect_url


class UrlInspectorTests(unittest.TestCase):
    def test_clean_https_url_has_no_static_findings(self) -> None:
        report = inspect_url("https://example.com/account")

        self.assertEqual(report.hostname, "example.com")
        self.assertFalse(report.findings)

    def test_flags_credentials_ip_http_and_unusual_port(self) -> None:
        report = inspect_url("http://user:pass@127.0.0.1:8080/login")
        messages = " ".join(finding.message for finding in report.findings)

        self.assertIn("credenciales", messages)
        self.assertIn("dirección IP", messages)
        self.assertIn("HTTP sin cifrado", messages)
        self.assertIn("8080", messages)

    def test_flags_mixed_unicode_alphabets(self) -> None:
        report = inspect_url("https://раypal.com")
        self.assertTrue(
            any("mezcla alfabetos" in finding.message for finding in report.findings)
        )

    def test_rejects_invalid_port(self) -> None:
        with self.assertRaises(ToolError):
            inspect_url("https://example.com:not-a-port")


if __name__ == "__main__":
    unittest.main()

