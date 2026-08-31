"""Análisis estático y privado de señales sospechosas en URLs."""

from __future__ import annotations

import ipaddress
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from .errors import ToolError


@dataclass(frozen=True, slots=True)
class UrlFinding:
    level: str
    message: str


@dataclass(frozen=True, slots=True)
class UrlReport:
    hostname: str
    findings: tuple[UrlFinding, ...]


def _scripts_in_hostname(hostname: str) -> set[str]:
    scripts: set[str] = set()
    for character in hostname:
        if not character.isalpha():
            continue
        name = unicodedata.name(character, "")
        for script in ("LATIN", "CYRILLIC", "GREEK"):
            if script in name:
                scripts.add(script)
                break
    return scripts


def inspect_url(value: str) -> UrlReport:
    """Identifica indicadores comunes sin conectarse al destino."""
    candidate = value.strip()
    if not candidate:
        raise ToolError("La URL no puede estar vacía.")
    if len(candidate) > 4096:
        raise ToolError("La URL supera el máximo de 4096 caracteres.")
    if any(ord(character) < 32 for character in candidate):
        raise ToolError("La URL contiene caracteres de control.")

    findings: list[UrlFinding] = []
    if "\\" in candidate:
        findings.append(UrlFinding("alto", "Contiene barras invertidas que pueden confundir el destino."))

    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        findings.append(UrlFinding("alto", "El esquema no es HTTP ni HTTPS."))
    elif parsed.scheme.lower() == "http":
        findings.append(UrlFinding("medio", "Usa HTTP sin cifrado de transporte."))

    hostname = parsed.hostname or ""
    if not hostname:
        findings.append(UrlFinding("alto", "No contiene un nombre de host válido."))
        return UrlReport(hostname="(sin host)", findings=tuple(findings))

    if parsed.username is not None or parsed.password is not None:
        findings.append(
            UrlFinding("alto", "Incluye credenciales antes del host; puede ocultar el destino real.")
        )

    try:
        ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        pass
    else:
        findings.append(UrlFinding("medio", "Usa una dirección IP en lugar de un dominio."))

    decoded_host = unquote(hostname)
    if "xn--" in hostname.lower():
        findings.append(UrlFinding("medio", "Usa Punycode; revisa posibles caracteres imitadores."))
    if any(ord(character) > 127 for character in decoded_host):
        findings.append(UrlFinding("medio", "El dominio contiene caracteres Unicode."))
    if len(_scripts_in_hostname(decoded_host)) > 1:
        findings.append(UrlFinding("alto", "El dominio mezcla alfabetos visualmente parecidos."))

    labels = [label for label in hostname.split(".") if label]
    if len(labels) > 5:
        findings.append(UrlFinding("bajo", "El dominio tiene una cantidad inusual de subdominios."))
    if len(hostname) > 253 or any(len(label) > 63 for label in labels):
        findings.append(UrlFinding("alto", "El nombre de host excede longitudes DNS normales."))

    try:
        port = parsed.port
    except ValueError as exc:
        raise ToolError("La URL contiene un puerto inválido.") from exc
    if port is not None and port not in {80, 443}:
        findings.append(UrlFinding("bajo", f"Usa el puerto no habitual {port}."))

    return UrlReport(hostname=hostname, findings=tuple(findings))

