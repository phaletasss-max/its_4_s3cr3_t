"""Escáner local y conservador de credenciales expuestas en archivos."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from .errors import ToolError

_MAX_FILE_SIZE = 2 * 1024 * 1024
_MAX_FILES = 10_000
_IGNORED_DIRECTORIES = frozenset(
    {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
)
_PATTERNS = (
    ("clave privada", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("token de GitHub", re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b")),
    ("access key de AWS", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("token de Slack", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,200}\b")),
    ("API key de Google", re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("JWT", re.compile(rb"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")),
)


@dataclass(frozen=True, slots=True)
class SecretFinding:
    path: Path
    line: int
    kind: str


@dataclass(frozen=True, slots=True)
class ScanReport:
    findings: tuple[SecretFinding, ...]
    scanned_files: int
    skipped_files: int


def _iter_files(root: Path):
    if root.is_file():
        yield root
        return

    for current, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = [
            name
            for name in directories
            if name.lower() not in _IGNORED_DIRECTORIES
            and not (Path(current) / name).is_symlink()
        ]
        for filename in filenames:
            candidate = Path(current) / filename
            if not candidate.is_symlink():
                yield candidate


def scan_for_secrets(path: str | Path) -> ScanReport:
    """Busca firmas conocidas y nunca devuelve el valor encontrado."""
    root = Path(path).expanduser()
    if not root.exists():
        raise ToolError(f"La ruta no existe: {root}")
    if root.is_symlink():
        raise ToolError("No se escanean rutas que sean enlaces simbólicos.")
    if not root.is_file() and not root.is_dir():
        raise ToolError("La ruta debe ser un archivo normal o una carpeta.")

    findings: list[SecretFinding] = []
    scanned = 0
    skipped = 0
    for candidate in _iter_files(root):
        if scanned + skipped >= _MAX_FILES:
            raise ToolError(f"El escaneo se detuvo al alcanzar {_MAX_FILES} archivos.")
        if not candidate.is_file():
            skipped += 1
            continue
        try:
            size = candidate.stat().st_size
            if size > _MAX_FILE_SIZE:
                skipped += 1
                continue
            data = candidate.read_bytes()
        except OSError:
            skipped += 1
            continue

        if b"\x00" in data[:8192]:
            skipped += 1
            continue
        scanned += 1
        for line_number, line in enumerate(data.splitlines(), start=1):
            for kind, pattern in _PATTERNS:
                if pattern.search(line):
                    findings.append(
                        SecretFinding(path=candidate, line=line_number, kind=kind)
                    )

    return ScanReport(
        findings=tuple(findings),
        scanned_files=scanned,
        skipped_files=skipped,
    )
