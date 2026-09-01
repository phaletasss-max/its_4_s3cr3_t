"""Compresión DEFLATE y codificación Base85 para texto copiable."""

from __future__ import annotations

import base64
import zlib

from .errors import ToolError

_PREFIX = "CZ1."
_MAX_INPUT_BYTES = 5 * 1024 * 1024
_MAX_ENCODED_CHARACTERS = 7 * 1024 * 1024


class CompactTextError(ToolError):
    """Error controlado al compactar o expandir un texto."""


def compact_text(text: str) -> str:
    """Comprime UTF-8 con DEFLATE y lo representa con Base85."""
    if not isinstance(text, str) or not text:
        raise CompactTextError("El texto a compactar no puede estar vacío.")

    payload = text.encode("utf-8")
    if len(payload) > _MAX_INPUT_BYTES:
        raise CompactTextError("El texto supera el máximo permitido de 5 MiB.")

    compressed = zlib.compress(payload, level=9)
    encoded = base64.b85encode(compressed).decode("ascii")
    return f"{_PREFIX}{encoded}"


def _decompress_limited(compressed: bytes) -> bytes:
    decompressor = zlib.decompressobj()
    try:
        output = decompressor.decompress(compressed, _MAX_INPUT_BYTES + 1)
        if len(output) > _MAX_INPUT_BYTES or decompressor.unconsumed_tail:
            raise CompactTextError("El contenido expandido supera el máximo de 5 MiB.")
        output += decompressor.flush(_MAX_INPUT_BYTES + 1 - len(output))
    except zlib.error as exc:
        raise CompactTextError("El contenido comprimido está dañado.") from exc

    if len(output) > _MAX_INPUT_BYTES:
        raise CompactTextError("El contenido expandido supera el máximo de 5 MiB.")
    if not decompressor.eof or decompressor.unused_data:
        raise CompactTextError("El contenido comprimido está incompleto o tiene datos extra.")
    return output


def expand_text(token: str) -> str:
    """Restaura exactamente el texto de un token CZ1."""
    if not isinstance(token, str):
        raise CompactTextError("El texto compacto no tiene un formato válido.")

    compact = token.strip()
    if not compact.startswith(_PREFIX):
        raise CompactTextError("El texto no pertenece al formato CZ1.")

    encoded = compact[len(_PREFIX) :]
    if not encoded:
        raise CompactTextError("El texto compacto está incompleto.")
    if len(encoded) > _MAX_ENCODED_CHARACTERS:
        raise CompactTextError("El texto compacto supera el tamaño permitido.")

    try:
        compressed = base64.b85decode(encoded.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise CompactTextError("El texto compacto no tiene una codificación válida.") from exc

    try:
        return _decompress_limited(compressed).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CompactTextError("El contenido restaurado no es texto UTF-8 válido.") from exc

