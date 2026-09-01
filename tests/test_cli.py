import contextlib
import io
import unittest
from unittest.mock import patch

from secret_tools.cli import (
    _compact_interactive,
    _encrypt_interactive,
    _recover_interactive,
    main,
)
from secret_tools.compact import compact_text
from secret_tools.crypto import decrypt_text, encrypt_text
from secret_tools.errors import ToolError


class InteractiveCliTests(unittest.TestCase):
    def test_run_without_subcommand_shows_every_category(self) -> None:
        stdout = io.StringIO()

        with patch("builtins.input", return_value="0"), contextlib.redirect_stdout(stdout):
            result = main([])

        output = stdout.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("Texto y secretos:", output)
        self.assertIn("Contraseñas y 2FA:", output)
        self.assertIn("Archivos y análisis:", output)
        self.assertIn("Proteger o modernizar texto", output)
        self.assertIn("Recuperar texto", output)

    def test_compact_rejects_already_encrypted_tokens(self) -> None:
        with self.assertRaisesRegex(ToolError, "S4S1 ya está cifrado"):
            _compact_interactive("S4S1.token-cifrado")

        with self.assertRaisesRegex(ToolError, "S4S2 ya comprime"):
            _compact_interactive("S4S2.token-cifrado")

    def test_protect_migrates_legacy_s4s1_in_one_flow(self) -> None:
        legacy = (
            "S4S1.UzRTAQEBpTif_8jygnIk1z0Z1i_XITVj7mPId9xJNKq5XEGG5qvpDI_"
            "5f8dttUHzglGB4Q0-JXjqQdaGBjbbyHkAiYToLnHr"
        )
        stdout = io.StringIO()

        with (
            patch(
                "secret_tools.cli.getpass.getpass",
                side_effect=[
                    "contraseña de prueba",
                    "nueva contraseña segura",
                    "nueva contraseña segura",
                ],
            ),
            contextlib.redirect_stdout(stdout),
        ):
            _encrypt_interactive(legacy)

        token = next(
            line for line in stdout.getvalue().splitlines() if line.startswith("S4S2.")
        )
        self.assertEqual(
            decrypt_text(token, "nueva contraseña segura"),
            "compatibilidad S4S1 ñ",
        )
        self.assertIn("S4S1 convertido a S4S2", stdout.getvalue())

    def test_recover_auto_detects_compact_text_without_password(self) -> None:
        token = compact_text("texto repetido " * 20)
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            _recover_interactive(token)

        self.assertIn("Texto recuperado desde CZ1", stdout.getvalue())
        self.assertIn("texto repetido", stdout.getvalue())

    def test_recover_auto_detects_cz2_without_password(self) -> None:
        original = "CTF{synthetic_0134_code}"
        token = compact_text(original)
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            _recover_interactive(token)

        self.assertTrue(token.startswith("CZ2."))
        self.assertIn("Texto recuperado desde CZ2", stdout.getvalue())
        self.assertIn(original, stdout.getvalue())

    def test_recover_auto_detects_encrypted_text(self) -> None:
        token = encrypt_text("mi secreto", "contraseña segura")
        stdout = io.StringIO()

        with (
            patch("secret_tools.cli.getpass.getpass", return_value="contraseña segura"),
            contextlib.redirect_stdout(stdout),
        ):
            _recover_interactive(token)

        self.assertIn("Texto recuperado desde S4S2", stdout.getvalue())
        self.assertIn("mi secreto", stdout.getvalue())

    def test_canceling_a_tool_returns_to_menu(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            patch("builtins.input", side_effect=["3", KeyboardInterrupt, "0"]),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = main([])

        self.assertEqual(result, 0)
        self.assertIn("Volviste al menú", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
