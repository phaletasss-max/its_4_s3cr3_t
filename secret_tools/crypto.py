"""Cifrado autenticado compatible con los formatos S4S1 y S4S2.

S4S2 comprime cuando resulta útil y usa Base85 para reducir la representación.
La seguridad sigue descansando en primitivas auditadas: scrypt y AES-256-GCM.
Los tokens S4S1 creados por versiones anteriores continúan siendo descifrables.
"""

from __future__ import annotations

import base64
import binascii
import os
import struct
import zlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import ToolError

_PREFIX_V1 = "S4S1."
_PREFIX_V2 = "S4S2."
_MAGIC = b"S4S"
_VERSION_V1 = 1
_VERSION_V2 = 2
_KDF_SCRYPT = 1
_CIPHER_AES_GCM = 1
_COMPRESSION_NONE = 0
_COMPRESSION_ZLIB = 1
_SALT_SIZE = 16
_NONCE_SIZE = 12
_KEY_SIZE = 32
_TAG_SIZE = 16
_MAX_PLAINTEXT_BYTES = 5 * 1024 * 1024
_MAX_PACKET_BYTES = _MAX_PLAINTEXT_BYTES + 1024
_MAX_ENCODED_CHARACTERS = 7 * 1024 * 1024
_HEADER_V1 = struct.Struct(f">3sBBB{_SALT_SIZE}s{_NONCE_SIZE}s")
_HEADER_V2 = struct.Struct(f">3sBBBB{_SALT_SIZE}s{_NONCE_SIZE}s")


class SecretCipherError(ToolError):
    """Error seguro y presentable al usuario durante cifrado o descifrado."""


def _require_passphrase(passphrase: str) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise SecretCipherError("La contraseña no puede estar vacía.")
    return passphrase.encode("utf-8")


def _derive_key(passphrase: bytes, salt: bytes) -> bytes:
    return Scrypt(
        salt=salt,
        length=_KEY_SIZE,
        n=2**15,
        r=8,
        p=1,
    ).derive(passphrase)


def _encode_v2(packet: bytes) -> str:
    return f"{_PREFIX_V2}{base64.b85encode(packet).decode('ascii')}"


def _decode_token(token: str) -> tuple[int, bytes]:
    if not isinstance(token, str):
        raise SecretCipherError("El texto cifrado no tiene un formato válido.")

    compact = token.strip()
    if compact.startswith(_PREFIX_V1):
        encoded = compact[len(_PREFIX_V1) :]
        if not encoded:
            raise SecretCipherError("El texto cifrado está incompleto.")
        if len(encoded) > _MAX_ENCODED_CHARACTERS:
            raise SecretCipherError("El texto cifrado supera el tamaño permitido.")
        try:
            packet = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4),
                altchars=b"-_",
                validate=True,
            )
        except (binascii.Error, ValueError) as exc:
            raise SecretCipherError("El texto cifrado no tiene un formato válido.") from exc
        version = _VERSION_V1
    elif compact.startswith(_PREFIX_V2):
        encoded = compact[len(_PREFIX_V2) :]
        if not encoded:
            raise SecretCipherError("El texto cifrado está incompleto.")
        if len(encoded) > _MAX_ENCODED_CHARACTERS:
            raise SecretCipherError("El texto cifrado supera el tamaño permitido.")
        try:
            packet = base64.b85decode(encoded.encode("ascii"))
        except (UnicodeEncodeError, ValueError) as exc:
            raise SecretCipherError("El texto cifrado no tiene un formato válido.") from exc
        version = _VERSION_V2
    else:
        raise SecretCipherError("El texto no pertenece a un formato S4S compatible.")

    if len(packet) > _MAX_PACKET_BYTES:
        raise SecretCipherError("El texto cifrado supera el tamaño permitido.")
    return version, packet


def _compress_if_useful(plaintext: bytes) -> tuple[int, bytes]:
    compressed = zlib.compress(plaintext, level=9)
    if len(compressed) < len(plaintext):
        return _COMPRESSION_ZLIB, compressed
    return _COMPRESSION_NONE, plaintext


def _decompress_limited(compressed: bytes) -> bytes:
    decompressor = zlib.decompressobj()
    try:
        output = decompressor.decompress(compressed, _MAX_PLAINTEXT_BYTES + 1)
        if len(output) > _MAX_PLAINTEXT_BYTES or decompressor.unconsumed_tail:
            raise SecretCipherError("El contenido descifrado supera el tamaño permitido.")
        output += decompressor.flush(_MAX_PLAINTEXT_BYTES + 1 - len(output))
    except zlib.error as exc:
        raise SecretCipherError("El contenido comprimido del secreto está dañado.") from exc

    if len(output) > _MAX_PLAINTEXT_BYTES:
        raise SecretCipherError("El contenido descifrado supera el tamaño permitido.")
    if not decompressor.eof or decompressor.unused_data:
        raise SecretCipherError("El contenido comprimido del secreto no es válido.")
    return output


def encrypt_text(plaintext: str, passphrase: str) -> str:
    """Cifra Unicode y devuelve un token S4S2 compacto y portable."""
    if not isinstance(plaintext, str) or not plaintext:
        raise SecretCipherError("El texto a cifrar no puede estar vacío.")

    plaintext_bytes = plaintext.encode("utf-8")
    if len(plaintext_bytes) > _MAX_PLAINTEXT_BYTES:
        raise SecretCipherError("El texto a cifrar supera el máximo permitido de 5 MiB.")

    password_bytes = _require_passphrase(passphrase)
    compression_id, payload = _compress_if_useful(plaintext_bytes)
    salt = os.urandom(_SALT_SIZE)
    nonce = os.urandom(_NONCE_SIZE)
    header = _HEADER_V2.pack(
        _MAGIC,
        _VERSION_V2,
        _KDF_SCRYPT,
        _CIPHER_AES_GCM,
        compression_id,
        salt,
        nonce,
    )
    key = _derive_key(password_bytes, salt)
    ciphertext = AESGCM(key).encrypt(nonce, payload, header)
    return _encode_v2(header + ciphertext)


def _decrypt_v1(packet: bytes, password_bytes: bytes) -> bytes:
    if len(packet) < _HEADER_V1.size + _TAG_SIZE:
        raise SecretCipherError("El texto cifrado está incompleto.")
    header = packet[: _HEADER_V1.size]
    ciphertext = packet[_HEADER_V1.size :]
    try:
        magic, version, kdf_id, cipher_id, salt, nonce = _HEADER_V1.unpack(header)
    except struct.error as exc:
        raise SecretCipherError("El texto cifrado no tiene un formato válido.") from exc
    if magic != _MAGIC or version != _VERSION_V1:
        raise SecretCipherError("La versión del texto cifrado no es compatible.")
    if kdf_id != _KDF_SCRYPT or cipher_id != _CIPHER_AES_GCM:
        raise SecretCipherError("El algoritmo indicado no es compatible.")
    key = _derive_key(password_bytes, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, header)


def _decrypt_v2(packet: bytes, password_bytes: bytes) -> bytes:
    if len(packet) < _HEADER_V2.size + _TAG_SIZE:
        raise SecretCipherError("El texto cifrado está incompleto.")
    header = packet[: _HEADER_V2.size]
    ciphertext = packet[_HEADER_V2.size :]
    try:
        magic, version, kdf_id, cipher_id, compression_id, salt, nonce = (
            _HEADER_V2.unpack(header)
        )
    except struct.error as exc:
        raise SecretCipherError("El texto cifrado no tiene un formato válido.") from exc
    if magic != _MAGIC or version != _VERSION_V2:
        raise SecretCipherError("La versión del texto cifrado no es compatible.")
    if kdf_id != _KDF_SCRYPT or cipher_id != _CIPHER_AES_GCM:
        raise SecretCipherError("El algoritmo indicado no es compatible.")
    if compression_id not in {_COMPRESSION_NONE, _COMPRESSION_ZLIB}:
        raise SecretCipherError("La compresión indicada no es compatible.")

    key = _derive_key(password_bytes, salt)
    payload = AESGCM(key).decrypt(nonce, ciphertext, header)
    if compression_id == _COMPRESSION_ZLIB:
        return _decompress_limited(payload)
    if len(payload) > _MAX_PLAINTEXT_BYTES:
        raise SecretCipherError("El contenido descifrado supera el tamaño permitido.")
    return payload


def decrypt_text(token: str, passphrase: str) -> str:
    """Descifra S4S1/S4S2 o falla si la clave/datos no son auténticos."""
    password_bytes = _require_passphrase(passphrase)
    version, packet = _decode_token(token)
    try:
        if version == _VERSION_V1:
            plaintext = _decrypt_v1(packet, password_bytes)
        else:
            plaintext = _decrypt_v2(packet, password_bytes)
        return plaintext.decode("utf-8")
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise SecretCipherError(
            "No se pudo descifrar: la contraseña es incorrecta o los datos cambiaron."
        ) from exc
