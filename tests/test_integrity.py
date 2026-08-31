import hashlib
import tempfile
import unittest
from pathlib import Path

from secret_tools.errors import ToolError
from secret_tools.integrity import hash_file, verify_file_hash


class IntegrityTests(unittest.TestCase):
    def test_hashes_file_in_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            content = b"integrity-check" * 100
            path.write_bytes(content)

            self.assertEqual(hash_file(path), hashlib.sha256(content).hexdigest())
            self.assertEqual(
                hash_file(path, "blake2b"), hashlib.blake2b(content).hexdigest()
            )

    def test_verifies_expected_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_text("contenido", encoding="utf-8")
            expected = hashlib.sha256(b"contenido").hexdigest()

            self.assertTrue(verify_file_hash(path, expected.upper()))
            self.assertFalse(verify_file_hash(path, "0" * 64))

    def test_rejects_invalid_hash_and_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_text("contenido", encoding="utf-8")
            with self.assertRaises(ToolError):
                verify_file_hash(path, "not-a-hash")
            with self.assertRaises(ToolError):
                hash_file(Path(directory) / "missing.txt")


if __name__ == "__main__":
    unittest.main()

