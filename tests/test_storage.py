import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from secret_tools.storage import Vault, VaultError, default_vault_path


class VaultStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.database_path = self.root / "vault.sqlite3"
        self.vault = Vault(self.database_path)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_initializes_versioned_schema(self) -> None:
        with closing(sqlite3.connect(self.database_path)) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            table = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
                ("vault_records",),
            ).fetchone()

        self.assertEqual(version, 1)
        self.assertEqual(table, ("vault_records",))
        self.assertTrue(self.vault.integrity_check())
        self.assertEqual(self.vault.changed_record_ids(), ())

    def test_rejects_schema_from_a_future_version(self) -> None:
        future_database = self.root / "future.sqlite3"
        with closing(sqlite3.connect(future_database)) as connection:
            connection.execute("PRAGMA user_version = 999")

        with self.assertRaisesRegex(VaultError, "versión más nueva"):
            Vault(future_database)
        with closing(sqlite3.connect(future_database)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 999)

    def test_adds_lists_and_gets_only_encrypted_tokens(self) -> None:
        record_id = self.vault.add_record("Cuenta personal", "S4S2.token-seguro")

        records = self.vault.list_records()

        self.assertEqual(record_id, 1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].label, "Cuenta personal")
        self.assertEqual(records[0].token_format, "S4S2")
        self.assertFalse(hasattr(records[0], "token"))
        self.assertEqual(self.vault.get_token(record_id), "S4S2.token-seguro")

    def test_parameterizes_labels_that_look_like_sql_injection(self) -> None:
        label = "x'); DROP TABLE vault_records; --"
        self.vault.add_record(label, "S4S2.token-injection-test")

        records = self.vault.list_records()

        self.assertEqual(records[0].label, label)
        self.assertTrue(self.vault.integrity_check())

    def test_detects_token_changed_outside_the_application(self) -> None:
        record_id = self.vault.add_record("Original", "S4S2.token-original")
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute(
                "UPDATE vault_records SET token = ? WHERE id = ?",
                ("S4S2.token-modificado", record_id),
            )
            connection.commit()

        self.assertTrue(self.vault.integrity_check())
        self.assertEqual(self.vault.changed_record_ids(), (record_id,))

    def test_rejects_plaintext_compact_tokens_duplicates_and_bad_labels(self) -> None:
        for token in ("texto en claro", "CZ1.compacto", "CZ2.compacto", "S4S3.futuro"):
            with self.subTest(token=token), self.assertRaises(VaultError):
                self.vault.add_record("Prueba", token)

        self.vault.add_record("Primero", "S4S1.token-repetido")
        with self.assertRaisesRegex(VaultError, "ya está guardado"):
            self.vault.add_record("Duplicado", "S4S1.token-repetido")

        for label in ("", "   ", "línea\nnueva", "oculto\u202e", "x" * 121):
            with self.subTest(label=label), self.assertRaises(VaultError):
                self.vault.add_record(label, "S4S2.otro-token")

    def test_renames_and_deletes_by_positive_id(self) -> None:
        record_id = self.vault.add_record("Anterior", "S4S2.token-editable")

        self.vault.rename_record(record_id, "Nueva etiqueta")
        self.assertEqual(self.vault.list_records()[0].label, "Nueva etiqueta")

        self.vault.delete_record(record_id)
        self.assertEqual(self.vault.list_records(), ())
        for invalid_id in (0, -1, True):
            with self.subTest(invalid_id=invalid_id), self.assertRaises(VaultError):
                self.vault.get_token(invalid_id)
        with self.assertRaisesRegex(VaultError, "No existe"):
            self.vault.delete_record(999)

    def test_validates_list_limits_and_orders_newest_id_first(self) -> None:
        first_id = self.vault.add_record("Primero", "S4S2.token-primero")
        second_id = self.vault.add_record("Segundo", "S4S2.token-segundo")

        records = self.vault.list_records(limit=1)

        self.assertEqual(first_id, 1)
        self.assertEqual(records[0].id, second_id)
        for invalid_limit in (0, 501, True, "10"):
            with self.subTest(invalid_limit=invalid_limit), self.assertRaises(VaultError):
                self.vault.list_records(invalid_limit)

    def test_searches_labels_with_literal_sql_symbols(self) -> None:
        self.vault.add_record("Servidor %_ principal", "S4S2.token-busqueda-uno")
        self.vault.add_record("Correo secundario", "S4S2.token-busqueda-dos")

        matches = self.vault.search_records("%_")
        injection = self.vault.search_records("'); DROP TABLE vault_records; --")

        self.assertEqual(tuple(record.label for record in matches), ("Servidor %_ principal",))
        self.assertEqual(injection, ())
        self.assertEqual(len(self.vault.list_records()), 2)

    def test_creates_verified_backup_without_overwriting(self) -> None:
        self.vault.add_record("Para backup", "S4S2.token-backup")
        destination = self.root / "copies" / "backup.sqlite3"

        created = self.vault.backup(destination)
        backup_vault = Vault(created)

        self.assertEqual(created, destination.resolve())
        self.assertTrue(backup_vault.integrity_check())
        self.assertEqual(backup_vault.get_token(1), "S4S2.token-backup")
        with self.assertRaisesRegex(VaultError, "ya existe"):
            self.vault.backup(destination)
        with self.assertRaisesRegex(VaultError, "bóveda activa"):
            self.vault.backup(self.database_path)

    def test_automatic_backups_use_unique_paths(self) -> None:
        first = self.vault.backup()
        second = self.vault.backup()

        self.assertNotEqual(first, second)
        self.assertTrue(first.is_file())
        self.assertTrue(second.is_file())

    def test_rejects_corrupted_database(self) -> None:
        corrupted = self.root / "corrupted.sqlite3"
        corrupted.write_bytes(b"esto no es sqlite")

        with self.assertRaises(VaultError):
            Vault(corrupted)

    def test_environment_selects_default_data_directory(self) -> None:
        configured = self.root / "custom-data"

        with patch.dict(os.environ, {"ITS_4_S3CR3_T_DATA_DIR": str(configured)}):
            self.assertEqual(default_vault_path(), configured / "vault.sqlite3")


if __name__ == "__main__":
    unittest.main()
