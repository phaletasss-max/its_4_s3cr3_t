"""Primitivas para el formato cifrado S4S1.

S4S1 define únicamente el contenedor. La seguridad descansa en primitivas
estándar y auditadas: scrypt para derivar la clave y AES-256-GCM para cifrado
autenticado.
"""

from __future__ import annotations

import base64
import binascii
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import ToolError

_PREFIX = "S4S1."
_MAGIC = b"S4S"
_VERSION = 1
_KDF_SCRYPT = 1
_CIPHER_AES_GCM = 1
_SALT_SIZE = 16
_NONCE_SIZE = 12
_KEY_SIZE = 32
_TAG_SIZE = 16
_MAX_TOKEN_BYTES = 10 * 1024 * 1024
_HEADER = struct.Struct(f">3sBBB{_SALT_SIZE}s{_NONCE_SIZE}s")


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


def _encode(packet: bytes) -> str:
    encoded = base64.urlsafe_b64encode(packet).decode("ascii").rstrip("=")
    return f"{_PREFIX}{encoded}"


def _decode(token: str) -> bytes:
    if not isinstance(token, str):
        raise SecretCipherError("El texto cifrado no tiene un formato válido.")

    compact = token.strip()
    if not compact.startswith(_PREFIX):
        raise SecretCipherError("El texto no pertenece al formato S4S1.")

    encoded = compact[len(_PREFIX) :]
    if not encoded:
        raise SecretCipherError("El texto cifrado está incompleto.")

    try:
        packet = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise SecretCipherError("El texto cifrado no tiene un formato válido.") from exc

    if len(packet) > _MAX_TOKEN_BYTES:
        raise SecretCipherError("El texto cifrado supera el tamaño permitido.")
    return packet


def encrypt_text(plaintext: str, passphrase: str) -> str:
    """Cifra texto Unicode y devuelve un token portable con formato S4S1."""
    if not isinstance(plaintext, str) or not plaintext:
        raise SecretCipherError("El texto a cifrar no puede estar vacío.")

    password_bytes = _require_passphrase(passphrase)
    salt = os.urandom(_SALT_SIZE)
    nonce = os.urandom(_NONCE_SIZE)
    header = _HEADER.pack(
        _MAGIC,
        _VERSION,
        _KDF_SCRYPT,
        _CIPHER_AES_GCM,
        salt,
        nonce,
    )
    key = _derive_key(password_bytes, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), header)
    return _encode(header + ciphertext)


def decrypt_text(token: str, passphrase: str) -> str:
    """Descifra un token S4S1 o falla si la clave/datos no son auténticos."""
    password_bytes = _require_passphrase(passphrase)
    packet = _decode(token)

    if len(packet) < _HEADER.size + _TAG_SIZE:
        raise SecretCipherError("El texto cifrado está incompleto.")

    header = packet[: _HEADER.size]
    ciphertext = packet[_HEADER.size :]
    try:
        magic, version, kdf_id, cipher_id, salt, nonce = _HEADER.unpack(header)
    except struct.error as exc:
        raise SecretCipherError("El texto cifrado no tiene un formato válido.") from exc

    if magic != _MAGIC or version != _VERSION:
        raise SecretCipherError("La versión del texto cifrado no es compatible.")
    if kdf_id != _KDF_SCRYPT or cipher_id != _CIPHER_AES_GCM:
        raise SecretCipherError("El algoritmo indicado no es compatible.")

    key = _derive_key(password_bytes, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
        return plaintext.decode("utf-8")
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise SecretCipherError(
            "No se pudo descifrar: la contraseña es incorrecta o los datos cambiaron."
        ) from exc
