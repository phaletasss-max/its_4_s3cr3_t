"""Generación segura y evaluación local de contraseñas."""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass

from zxcvbn import zxcvbn

from .errors import ToolError

_SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~"
_SCORE_LABELS = ("muy débil", "débil", "aceptable", "fuerte", "muy fuerte")


@dataclass(frozen=True, slots=True)
class PasswordReport:
    score: int
    label: str
    crack_time: str
    warning: str
    suggestions: tuple[str, ...]


def generate_password(length: int = 24, *, include_symbols: bool = True) -> str:
    """Genera una contraseña con CSPRNG y presencia garantizada por categoría."""
    if not 12 <= length <= 256:
        raise ToolError("La longitud debe estar entre 12 y 256 caracteres.")

    categories = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if include_symbols:
        categories.append(_SYMBOLS)

    password = [secrets.choice(category) for category in categories]
    alphabet = "".join(categories)
    password.extend(secrets.choice(alphabet) for _ in range(length - len(password)))
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


def analyze_password(password: str) -> PasswordReport:
    """Evalúa una contraseña localmente sin almacenarla ni enviarla a internet."""
    if not password:
        raise ToolError("La contraseña no puede estar vacía.")
    if len(password) > 512:
        raise ToolError("La contraseña supera el máximo de 512 caracteres.")

    result = zxcvbn(password)
    score = int(result["score"])
    feedback = result.get("feedback", {})
    crack_times = result.get("crack_times_display", {})
    return PasswordReport(
        score=score,
        label=_SCORE_LABELS[score],
        crack_time=str(crack_times.get("offline_slow_hashing_1e4_per_second", "desconocido")),
        warning=str(feedback.get("warning", "")),
        suggestions=tuple(str(item) for item in feedback.get("suggestions", ())),
    )

