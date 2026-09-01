"""Empaquetado reversible para códigos CTF con alfabetos restringidos."""

from __future__ import annotations

from .errors import ToolError

_MODE_LEET_5BIT = 1
_MODE_ALNUM_6BIT = 2
_LEET_ALPHABET = "abcdefghijklmnopqrstuvwxyz_0134-"
_ALNUM_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
_ALPHABETS = {
    _MODE_LEET_5BIT: _LEET_ALPHABET,
    _MODE_ALNUM_6BIT: _ALNUM_ALPHABET,
}
_MAX_BODY_CHARACTERS = 255


class PackedCtfError(ToolError):
    """Error controlado al restaurar un código CTF empaquetado."""


def _select_mode(body: str) -> tuple[int, str] | None:
    for mode, alphabet in _ALPHABETS.items():
        if all(character in alphabet for character in body):
            return mode, alphabet
    return None


def pack_ctf_text(text: str) -> bytes | None:
    """Empaqueta CTF{...}; devuelve None si el formato no es compatible."""
    if not text.startswith("CTF{") or not text.endswith("}"):
        return None

    body = text[4:-1]
    if len(body) > _MAX_BODY_CHARACTERS:
        return None

    selection = _select_mode(body)
    if selection is None:
        return None
    mode, alphabet = selection
    bits_per_symbol = 5 if mode == _MODE_LEET_5BIT else 6
    indexes = {character: index for index, character in enumerate(alphabet)}

    bit_length = len(body) * bits_per_symbol
    byte_length = (bit_length + 7) // 8
    packed_value = 0
    for character in body:
        packed_value = (packed_value << bits_per_symbol) | indexes[character]
    packed_value <<= byte_length * 8 - bit_length
    return bytes((mode, len(body))) + packed_value.to_bytes(byte_length, "big")


def unpack_ctf_text(payload: bytes) -> str:
    """Restaura exactamente un paquete producido por pack_ctf_text."""
    if len(payload) < 2:
        raise PackedCtfError("El contenido CTF empaquetado está incompleto.")

    mode, body_length = payload[:2]
    alphabet = _ALPHABETS.get(mode)
    if alphabet is None:
        raise PackedCtfError("El alfabeto del contenido CTF no es compatible.")
    bits_per_symbol = 5 if mode == _MODE_LEET_5BIT else 6

    packed = payload[2:]
    bit_length = body_length * bits_per_symbol
    expected_bytes = (bit_length + 7) // 8
    if len(packed) != expected_bytes:
        raise PackedCtfError("El contenido CTF empaquetado no tiene un tamaño válido.")

    packed_value = int.from_bytes(packed, "big")
    padding_bits = expected_bytes * 8 - bit_length
    if padding_bits and packed_value & ((1 << padding_bits) - 1):
        raise PackedCtfError("El contenido CTF empaquetado tiene relleno inválido.")
    packed_value >>= padding_bits

    characters = []
    for position in range(body_length):
        shift = (body_length - position - 1) * bits_per_symbol
        index = (packed_value >> shift) & ((1 << bits_per_symbol) - 1)
        if index >= len(alphabet):
            raise PackedCtfError("El contenido CTF usa un símbolo inválido.")
        characters.append(alphabet[index])
    return f"CTF{{{''.join(characters)}}}"
