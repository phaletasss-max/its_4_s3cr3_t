"""Compresión DEFLATE y codificación Base85 para texto copiable."""

from __future__ import annotations

import base64
import zlib

from .ctf_packing import PackedCtfError, pack_ctf_text, unpack_ctf_text
from .errors import ToolError

_PREFIX_ZLIB = "CZ1."
_PREFIX_CTF = "CZ2."
_MAX_INPUT_BYTES = 5 * 1024 * 1024
_MAX_ENCODED_CHARACTERS = 7 * 1024 * 1024


class CompactTextError(ToolError):
    """Error controlado al compactar o expandir un texto."""


def compact_text(text: str) -> str:
    """Elige el formato reversible más corto entre CZ1 y CZ2."""
    if not isinstance(text, str) or not text:
        raise CompactTextError("El texto a compactar no puede estar vacío.")

    payload = text.encode("utf-8")
    if len(payload) > _MAX_INPUT_BYTES:
        raise CompactTextError("El texto supera el máximo permitido de 5 MiB.")

    compressed = zlib.compress(payload, level=9)
    zlib_token = f"{_PREFIX_ZLIB}{base64.b85encode(compressed).decode('ascii')}"

    packed_ctf = pack_ctf_text(text)
    if packed_ctf is None:
        return zlib_token
    ctf_token = f"{_PREFIX_CTF}{base64.b85encode(packed_ctf).decode('ascii')}"
    return min(zlib_token, ctf_token, key=len)


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
    """Restaura exactamente el texto de un token CZ1 o CZ2."""
    if not isinstance(token, str):
        raise CompactTextError("El texto compacto no tiene un formato válido.")

    compact = token.strip()
    if compact.startswith(_PREFIX_ZLIB):
        prefix = _PREFIX_ZLIB
    elif compact.startswith(_PREFIX_CTF):
        prefix = _PREFIX_CTF
    else:
        raise CompactTextError("El texto no pertenece a un formato CZ1/CZ2 compatible.")

    encoded = compact[len(prefix) :]
    if not encoded:
        raise CompactTextError("El texto compacto está incompleto.")
    if len(encoded) > _MAX_ENCODED_CHARACTERS:
        raise CompactTextError("El texto compacto supera el tamaño permitido.")

    try:
        decoded = base64.b85decode(encoded.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise CompactTextError("El texto compacto no tiene una codificación válida.") from exc

    if prefix == _PREFIX_CTF:
        try:
            return unpack_ctf_text(decoded)
        except PackedCtfError as exc:
            raise CompactTextError(str(exc)) from exc

    try:
        return _decompress_limited(decoded).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CompactTextError("El contenido restaurado no es texto UTF-8 válido.") from exc
