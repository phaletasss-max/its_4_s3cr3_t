import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secret_tools.cli import (
    _compact_interactive,
    _encrypt_interactive,
    _recover_interactive,
    _show_vault_records,
    _vault_interactive,
    main,
)
from secret_tools.compact import compact_text
from secret_tools.crypto import decrypt_text, encrypt_text
from secret_tools.errors import ToolError
from secret_tools.storage import Vault


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
        self.assertIn("Almacenamiento local:", output)
        self.assertIn("Proteger o modernizar texto", output)
        self.assertIn("Recuperar texto", output)
        self.assertIn("Bóveda SQLite", output)

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

    def test_vault_menu_saves_lists_and_recovers_a_secret(self) -> None:
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = Path(temporary_directory) / "vault.sqlite3"
            with (
                patch(
                    "builtins.input",
                    side_effect=[
                        "1",
                        "Registro de prueba",
                        "dato secreto",
                        "3",
                        "5",
                        "1",
                        "0",
                    ],
                ),
                patch(
                    "secret_tools.cli.getpass.getpass",
                    side_effect=[
                        "contraseña segura",
                        "contraseña segura",
                        "contraseña segura",
                    ],
                ),
                contextlib.redirect_stdout(stdout),
            ):
                _vault_interactive(database)

        output = stdout.getvalue()
        self.assertIn("Guardado como registro 1", output)
        self.assertIn("Registro de prueba", output)
        self.assertIn("dato secreto", output)

    def test_vault_search_distinguishes_no_matches_from_empty_database(self) -> None:
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary_directory:
            vault = Vault(Path(temporary_directory) / "vault.sqlite3")
            vault.add_record("Correo", "S4S2.token-correo")
            with contextlib.redirect_stdout(stdout):
                _show_vault_records(vault, "Servidor")

        self.assertIn("No se encontraron registros", stdout.getvalue())

    def test_vault_delete_requires_exact_confirmation(self) -> None:
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = Path(temporary_directory) / "vault.sqlite3"
            vault = Vault(database)
            record_id = vault.add_record("Conservar", "S4S2.token-conservar")

            with (
                patch("builtins.input", side_effect=["7", str(record_id), "eliminar", "0"]),
                contextlib.redirect_stdout(stdout),
            ):
                _vault_interactive(database)

            self.assertEqual(Vault(database).get_token(record_id), "S4S2.token-conservar")

        self.assertIn("Eliminación cancelada", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
