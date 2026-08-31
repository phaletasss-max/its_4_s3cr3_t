"""Creación y uso local de secretos TOTP compatibles con autenticadores."""

from __future__ import annotations

import base64
import binascii
import time
from dataclasses import dataclass

import pyotp

from .errors import ToolError


@dataclass(frozen=True, slots=True)
class TotpCode:
    value: str
    remaining_seconds: int


def create_totp_secret() -> str:
    """Crea un secreto Base32 criptográficamente aleatorio."""
    return pyotp.random_base32()


def _normalize_secret(secret: str) -> str:
    compact = "".join(secret.split()).upper()
    if not compact:
        raise ToolError("El secreto TOTP no puede estar vacío.")
    try:
        base64.b32decode(compact + "=" * (-len(compact) % 8), casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise ToolError("El secreto TOTP no es Base32 válido.") from exc
    return compact


def generate_totp_code(secret: str, *, at_time: int | None = None) -> TotpCode:
    """Genera el código TOTP actual y el tiempo restante de su intervalo."""
    compact = _normalize_secret(secret)
    timestamp = int(time.time()) if at_time is None else int(at_time)
    totp = pyotp.TOTP(compact)
    try:
        value = totp.at(timestamp)
    except (TypeError, ValueError, binascii.Error) as exc:
        raise ToolError("No se pudo generar el código con ese secreto TOTP.") from exc
    remaining = totp.interval - (timestamp % totp.interval)
    return TotpCode(value=value, remaining_seconds=remaining)

