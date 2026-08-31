"""Cálculo y verificación de huellas criptográficas de archivos."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

from .errors import ToolError

SUPPORTED_ALGORITHMS = ("sha256", "sha512", "blake2b")
_BUFFER_SIZE = 1024 * 1024
_HEX_DIGITS = frozenset("0123456789abcdef")


def _validated_file(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.exists():
        raise ToolError(f"El archivo no existe: {candidate}")
    if not candidate.is_file():
        raise ToolError(f"La ruta no es un archivo: {candidate}")
    return candidate


def hash_file(path: str | Path, algorithm: str = "sha256") -> str:
    """Devuelve el hash hexadecimal de un archivo sin cargarlo entero en memoria."""
    normalized = algorithm.lower()
    if normalized not in SUPPORTED_ALGORITHMS:
        raise ToolError(f"Algoritmo no admitido: {algorithm}")

    candidate = _validated_file(path)
    digest = hashlib.new(normalized)
    try:
        with candidate.open("rb") as source:
            while chunk := source.read(_BUFFER_SIZE):
                digest.update(chunk)
    except OSError as exc:
        raise ToolError(f"No se pudo leer el archivo: {candidate}") from exc
    return digest.hexdigest()


def verify_file_hash(
    path: str | Path,
    expected: str,
    algorithm: str = "sha256",
) -> bool:
    """Compara una huella esperada en tiempo constante."""
    normalized = algorithm.lower()
    if normalized not in SUPPORTED_ALGORITHMS:
        raise ToolError(f"Algoritmo no admitido: {algorithm}")

    expected_clean = expected.strip().lower()
    expected_length = hashlib.new(normalized).digest_size * 2
    if len(expected_clean) != expected_length or any(
        character not in _HEX_DIGITS for character in expected_clean
    ):
        raise ToolError(
            f"La huella {normalized.upper()} debe tener {expected_length} caracteres hexadecimales."
        )
    return hmac.compare_digest(hash_file(path, normalized), expected_clean)
