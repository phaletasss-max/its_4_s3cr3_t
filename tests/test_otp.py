import unittest

from secret_tools.errors import ToolError
from secret_tools.otp import create_totp_secret, generate_totp_code


class TotpTests(unittest.TestCase):
    def test_generated_secret_produces_six_digit_code(self) -> None:
        secret = create_totp_secret()
        result = generate_totp_code(secret, at_time=59)

        self.assertGreaterEqual(len(secret), 32)
        self.assertEqual(len(result.value), 6)
        self.assertTrue(result.value.isdigit())
        self.assertEqual(result.remaining_seconds, 1)

    def test_matches_rfc_secret_vector_at_59_seconds(self) -> None:
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(generate_totp_code(secret, at_time=59).value, "287082")

    def test_rejects_invalid_secret(self) -> None:
        for secret in ("", "not base32 !!!"):
            with self.subTest(secret=secret), self.assertRaises(ToolError):
                generate_totp_code(secret, at_time=59)


if __name__ == "__main__":
    unittest.main()

