import random
import unittest

from secret_tools.ctf_packing import PackedCtfError, pack_ctf_text, unpack_ctf_text


class CtfPackingTests(unittest.TestCase):
    def test_round_trip_for_every_supported_length(self) -> None:
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        randomizer = random.Random(20260901)

        for length in range(256):
            body = "".join(randomizer.choice(alphabet) for _ in range(length))
            original = f"CTF{{{body}}}"
            with self.subTest(length=length):
                packed = pack_ctf_text(original)
                self.assertIsNotNone(packed)
                self.assertEqual(unpack_ctf_text(packed), original)

    def test_rejects_unsupported_inputs(self) -> None:
        self.assertIsNone(pack_ctf_text("texto normal"))
        self.assertIsNone(pack_ctf_text("CTF{punto.no-compatible}"))
        self.assertIsNone(pack_ctf_text(f"CTF{{{'a' * 256}}}"))

    def test_rejects_malformed_payloads(self) -> None:
        for payload in (b"", b"\x01", b"\xff\x00", b"\x01\x02\x00", b"\x01\x01\x01"):
            with self.subTest(payload=payload), self.assertRaises(PackedCtfError):
                unpack_ctf_text(payload)


if __name__ == "__main__":
    unittest.main()
