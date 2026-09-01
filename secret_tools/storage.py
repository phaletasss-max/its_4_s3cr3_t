"""Bóveda SQLite local para conservar únicamente tokens cifrados S4S."""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import unicodedata
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Iterator

from .errors import ToolError

_DATA_DIRECTORY_ENV = "ITS_4_S3CR3_T_DATA_DIR"
_DATABASE_NAME = "vault.sqlite3"
_SCHEMA_RESOURCE = "schema.sql"
_SCHEMA_VERSION = 1
_MAX_LABEL_CHARACTERS = 120
_MAX_TOKEN_CHARACTERS = 7 * 1024 * 1024
_MAX_LIST_LIMIT = 500
_SUPPORTED_TOKEN_PREFIXES = ("S4S1.", "S4S2.")


class VaultError(ToolError):
    """Error seguro y presentable de la bóveda local."""


@dataclass(frozen=True, slots=True)
class VaultRecord:
    id: int
    label: str
    token_format: str
    created_at: str
    updated_at: str
    token_length: int


def default_vault_path() -> Path:
    configured = os.environ.get(_DATA_DIRECTORY_ENV)
    directory = Path(configured).expanduser() if configured else Path.home() / ".its_4_s3cr3_t"
    return directory / _DATABASE_NAME


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _validate_record_id(record_id: int) -> int:
    if isinstance(record_id, bool) or not isinstance(record_id, int) or record_id < 1:
        raise VaultError("El ID del registro debe ser un entero positivo.")
    return record_id


def _normalize_label(label: str) -> str:
    if not isinstance(label, str):
        raise VaultError("La etiqueta debe ser texto.")
    normalized = label.strip()
    if not normalized:
        raise VaultError("La etiqueta no puede estar vacía.")
    if len(normalized) > _MAX_LABEL_CHARACTERS:
        raise VaultError(
            f"La etiqueta admite como máximo {_MAX_LABEL_CHARACTERS} caracteres."
        )
    forbidden_categories = {"Cc", "Cf", "Cs", "Zl", "Zp"}
    if any(
        unicodedata.category(character) in forbidden_categories
        for character in normalized
    ):
        raise VaultError("La etiqueta no puede contener caracteres invisibles o de control.")
    return normalized


def _validate_limit(limit: int) -> int:
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= _MAX_LIST_LIMIT
    ):
        raise VaultError(f"El límite debe estar entre 1 y {_MAX_LIST_LIMIT}.")
    return limit


def _row_to_record(row: sqlite3.Row) -> VaultRecord:
    return VaultRecord(**dict(row))


def _normalize_token(token: str) -> tuple[str, str]:
    if not isinstance(token, str):
        raise VaultError("El token debe ser texto.")
    normalized = token.strip()
    if len(normalized) > _MAX_TOKEN_CHARACTERS:
        raise VaultError("El token supera el tamaño permitido.")
    if not normalized.isascii() or not normalized.startswith(_SUPPORTED_TOKEN_PREFIXES):
        raise VaultError("La bóveda solo guarda tokens cifrados S4S1 o S4S2.")
    return normalized, normalized[:4]


def _load_schema() -> str:
    try:
        return files("secret_tools").joinpath(_SCHEMA_RESOURCE).read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:
        raise VaultError("No se pudo cargar el esquema SQL incluido.") from exc


def _restrict_file_permissions(path: Path) -> None:
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass


class Vault:
    def __init__(self, path: str | Path | None = None) -> None:
        selected = Path(path).expanduser() if path is not None else default_vault_path()
        self.path = selected.resolve()
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            connection = sqlite3.connect(self.path, timeout=5)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
        except (OSError, sqlite3.Error) as exc:
            raise VaultError("No se pudo abrir la bóveda SQLite.") from exc

        try:
            yield connection
        except sqlite3.Error as exc:
            raise VaultError("SQLite no pudo completar la operación solicitada.") from exc
        finally:
            connection.close()

    def _initialize(self) -> None:
        schema = _load_schema()
        with self._connect() as connection:
            current_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current_version > _SCHEMA_VERSION:
                raise VaultError(
                    "La bóveda fue creada por una versión más nueva de la aplicación."
                )
            connection.executescript(schema)
            installed_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if installed_version != _SCHEMA_VERSION:
                raise VaultError("La versión del esquema SQLite no es válida.")
        _restrict_file_permissions(self.path)

    def add_record(self, label: str, token: str) -> int:
        normalized_label = _normalize_label(label)
        normalized_token, token_format = _normalize_token(token)
        fingerprint = hashlib.sha256(normalized_token.encode("ascii")).hexdigest()
        timestamp = _utc_now()

        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO vault_records (
                        label, token_format, token, token_sha256, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        normalized_label,
                        token_format,
                        normalized_token,
                        fingerprint,
                        timestamp,
                        timestamp,
                    ),
                )
                connection.commit()
                return int(cursor.lastrowid)
        except VaultError as exc:
            if isinstance(exc.__cause__, sqlite3.IntegrityError):
                raise VaultError("Ese token ya está guardado o sus datos no son válidos.") from exc
            raise

    def list_records(self, limit: int = 100) -> tuple[VaultRecord, ...]:
        selected_limit = _validate_limit(limit)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, label, token_format, created_at, updated_at, length(token) AS token_length
                FROM vault_records
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (selected_limit,),
            ).fetchall()
        return tuple(_row_to_record(row) for row in rows)

    def search_records(self, query: str, limit: int = 100) -> tuple[VaultRecord, ...]:
        normalized_query = _normalize_label(query)
        selected_limit = _validate_limit(limit)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, label, token_format, created_at, updated_at, length(token) AS token_length
                FROM vault_records
                WHERE instr(lower(label), lower(?)) > 0
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (normalized_query, selected_limit),
            ).fetchall()
        return tuple(_row_to_record(row) for row in rows)

    def get_token(self, record_id: int) -> str:
        selected_id = _validate_record_id(record_id)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT token FROM vault_records WHERE id = ?",
                (selected_id,),
            ).fetchone()
        if row is None:
            raise VaultError(f"No existe el registro {selected_id}.")
        return str(row["token"])

    def rename_record(self, record_id: int, new_label: str) -> None:
        selected_id = _validate_record_id(record_id)
        normalized_label = _normalize_label(new_label)
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE vault_records SET label = ?, updated_at = ? WHERE id = ?",
                (normalized_label, _utc_now(), selected_id),
            )
            connection.commit()
        if cursor.rowcount != 1:
            raise VaultError(f"No existe el registro {selected_id}.")

    def delete_record(self, record_id: int) -> None:
        selected_id = _validate_record_id(record_id)
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM vault_records WHERE id = ?",
                (selected_id,),
            )
            connection.commit()
        if cursor.rowcount != 1:
            raise VaultError(f"No existe el registro {selected_id}.")

    def integrity_check(self) -> bool:
        with self._connect() as connection:
            rows = connection.execute("PRAGMA integrity_check").fetchall()
        return bool(rows) and all(str(row[0]).lower() == "ok" for row in rows)

    def changed_record_ids(self) -> tuple[int, ...]:
        """Detecta cambios accidentales en tokens mediante su huella almacenada."""
        changed = []
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, token, token_sha256 FROM vault_records ORDER BY id"
            )
            for row in rows:
                actual = hashlib.sha256(str(row["token"]).encode("utf-8")).hexdigest()
                if not hmac.compare_digest(actual, str(row["token_sha256"])):
                    changed.append(int(row["id"]))
        return tuple(changed)

    def backup(self, destination: str | Path | None = None) -> Path:
        if destination is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            selected = self.path.with_name(f"vault-backup-{timestamp}.sqlite3")
        else:
            selected = Path(destination).expanduser().resolve()

        if selected == self.path:
            raise VaultError("La copia no puede sobrescribir la bóveda activa.")
        try:
            selected.parent.mkdir(parents=True, exist_ok=True)
            selected.touch(exist_ok=False)
        except FileExistsError as exc:
            raise VaultError("La ruta de backup ya existe; elige otra.") from exc
        except OSError as exc:
            raise VaultError("No se pudo crear el archivo de backup.") from exc

        try:
            with self._connect() as source:
                with closing(sqlite3.connect(selected)) as target:
                    source.backup(target)
                    result = target.execute("PRAGMA integrity_check").fetchone()
                    if result is None or str(result[0]).lower() != "ok":
                        raise VaultError("El backup no superó la comprobación de integridad.")
            _restrict_file_permissions(selected)
            return selected
        except (VaultError, sqlite3.Error, OSError) as exc:
            try:
                selected.unlink(missing_ok=True)
            except OSError:
                pass
            if isinstance(exc, VaultError):
                raise
            raise VaultError("No se pudo completar el backup SQLite.") from exc
