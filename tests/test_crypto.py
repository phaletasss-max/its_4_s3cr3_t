import base64
import unittest

from secret_tools.crypto import SecretCipherError, decrypt_text, encrypt_text


class SecretCipherTests(unittest.TestCase):
    def test_round_trip_preserves_unicode(self) -> None:
        original = "Mi frase secreta: café, ñ y 🔐"
        token = encrypt_text(original, "una contraseña larga")

        self.assertTrue(token.startswith("S4S1."))
        self.assertEqual(decrypt_text(token, "una contraseña larga"), original)

    def test_same_input_produces_different_tokens(self) -> None:
        first = encrypt_text("repetido", "contraseña segura")
        second = encrypt_text("repetido", "contraseña segura")

        self.assertNotEqual(first, second)
        self.assertEqual(decrypt_text(first, "contraseña segura"), "repetido")
        self.assertEqual(decrypt_text(second, "contraseña segura"), "repetido")

    def test_wrong_password_is_rejected(self) -> None:
        token = encrypt_text("dato", "contraseña correcta")

        with self.assertRaisesRegex(SecretCipherError, "incorrecta|cambiaron"):
            decrypt_text(token, "contraseña incorrecta")

    def test_modified_ciphertext_is_rejected(self) -> None:
        token = encrypt_text("dato", "contraseña correcta")
        prefix, encoded = token.split(".", maxsplit=1)
        packet = bytearray(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        packet[-1] ^= 1
        modified = base64.urlsafe_b64encode(packet).decode("ascii").rstrip("=")

        with self.assertRaisesRegex(SecretCipherError, "incorrecta|cambiaron"):
            decrypt_text(f"{prefix}.{modified}", "contraseña correcta")

    def test_invalid_or_incomplete_tokens_are_rejected(self) -> None:
        for token in ("", "otro-formato", "S4S1.", "S4S1.%%%%"):
            with self.subTest(token=token):
                with self.assertRaises(SecretCipherError):
                    decrypt_text(token, "contraseña correcta")

    def test_empty_values_are_rejected(self) -> None:
        with self.assertRaises(SecretCipherError):
            encrypt_text("", "contraseña correcta")
        with self.assertRaises(SecretCipherError):
            encrypt_text("dato", "")


if __name__ == "__main__":
    unittest.main()

