import tempfile
import unittest
from pathlib import Path

from secret_tools.secret_scanner import scan_for_secrets


class SecretScannerTests(unittest.TestCase):
    def test_finds_known_signature_without_returning_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = "ghp_" + "A" * 36
            source = root / "settings.txt"
            source.write_text(f"safe=true\ntoken={token}\n", encoding="utf-8")

            report = scan_for_secrets(root)

            self.assertEqual(len(report.findings), 1)
            self.assertEqual(report.findings[0].line, 2)
            self.assertEqual(report.findings[0].kind, "token de GitHub")
            self.assertNotIn(token, repr(report))

    def test_ignores_git_and_binary_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git_directory = root / ".git"
            git_directory.mkdir()
            (git_directory / "config").write_text(
                "AKIA" + "A" * 16, encoding="utf-8"
            )
            (root / "image.bin").write_bytes(b"\x00AKIA" + b"A" * 16)

            report = scan_for_secrets(root)

            self.assertFalse(report.findings)
            self.assertEqual(report.scanned_files, 0)
            self.assertEqual(report.skipped_files, 1)


if __name__ == "__main__":
    unittest.main()

