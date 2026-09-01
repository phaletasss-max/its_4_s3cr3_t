import unittest

from secret_tools.crypto import SecretCipherError, decrypt_text, encrypt_text


class SecretCipherTests(unittest.TestCase):
    def test_round_trip_preserves_unicode(self) -> None:
        original = "Mi frase secreta: café, ñ y 🔐"
        token = encrypt_text(original, "una contraseña larga")

        self.assertTrue(token.startswith("S4S2."))
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
        modified = token[:-1] + ("0" if token[-1] != "0" else "1")

        with self.assertRaises(SecretCipherError):
            decrypt_text(modified, "contraseña correcta")

    def test_invalid_or_incomplete_tokens_are_rejected(self) -> None:
        for token in ("", "otro-formato", "S4S1.", "S4S1.%%%%", "S4S2.", "S4S2.\""):
            with self.subTest(token=token):
                with self.assertRaises(SecretCipherError):
                    decrypt_text(token, "contraseña correcta")

    def test_empty_values_are_rejected(self) -> None:
        with self.assertRaises(SecretCipherError):
            encrypt_text("", "contraseña correcta")
        with self.assertRaises(SecretCipherError):
            encrypt_text("dato", "")

    def test_repetitive_text_reaches_compact_target(self) -> None:
        original = "seguridad y privacidad " * 10
        token = encrypt_text(original, "contraseña segura")

        self.assertLess(len(token), 150)
        self.assertEqual(decrypt_text(token, "contraseña segura"), original)

    def test_legacy_s4s1_token_remains_compatible(self) -> None:
        token = (
            "S4S1.UzRTAQEBpTif_8jygnIk1z0Z1i_XITVj7mPId9xJNKq5XEGG5qvpDI_"
            "5f8dttUHzglGB4Q0-JXjqQdaGBjbbyHkAiYToLnHr"
        )
        self.assertEqual(
            decrypt_text(token, "contraseña de prueba"),
            "compatibilidad S4S1 ñ",
        )


if __name__ == "__main__":
    unittest.main()
