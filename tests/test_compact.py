import base64
import unittest
import zlib

from secret_tools.compact import CompactTextError, compact_text, expand_text


class CompactTextTests(unittest.TestCase):
    def test_round_trip_preserves_unicode(self) -> None:
        original = "Texto compacto con café, ñ y 🔐"
        token = compact_text(original)

        self.assertTrue(token.startswith("CZ1."))
        self.assertEqual(expand_text(token), original)

    def test_repetitive_text_is_reduced_below_target(self) -> None:
        original = "seguridad y privacidad " * 10
        token = compact_text(original)

        self.assertEqual(len(original), 230)
        self.assertLess(len(token), 50)
        self.assertEqual(expand_text(token), original)

    def test_corrupted_and_extra_data_are_rejected(self) -> None:
        token = compact_text("contenido repetido " * 20)
        modified = token[:-1] + ("0" if token[-1] != "0" else "1")
        trailing = "CZ1." + base64.b85encode(zlib.compress(b"dato") + b"extra").decode()

        with self.assertRaises(CompactTextError):
            expand_text(modified)
        with self.assertRaises(CompactTextError):
            expand_text(trailing)

    def test_invalid_or_empty_values_are_rejected(self) -> None:
        with self.assertRaises(CompactTextError):
            compact_text("")
        for token in ("", "otro-formato", "CZ1.", "CZ1.000"):
            with self.subTest(token=token), self.assertRaises(CompactTextError):
                expand_text(token)

    def test_decompression_limit_blocks_oversized_output(self) -> None:
        oversized = zlib.compress(b"A" * (5 * 1024 * 1024 + 1), level=9)
        token = "CZ1." + base64.b85encode(oversized).decode("ascii")

        with self.assertRaisesRegex(CompactTextError, "máximo"):
            expand_text(token)


if __name__ == "__main__":
    unittest.main()

