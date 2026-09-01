"""Interfaz de consola para la caja de herramientas."""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Sequence
from pathlib import Path

from .compact import compact_text, expand_text
from .crypto import decrypt_text, encrypt_text
from .errors import ToolError
from .integrity import SUPPORTED_ALGORITHMS, hash_file, verify_file_hash
from .otp import create_totp_secret, generate_totp_code
from .passwords import analyze_password, generate_password
from .registry import Tool, ToolRegistry
from .secret_scanner import ScanReport, scan_for_secrets
from .url_inspector import inspect_url

_MIN_PASSWORD_LENGTH = 8


def _read_new_passphrase() -> str:
    password = getpass.getpass("Contraseña secreta: ")
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise ToolError(
            f"Usa una contraseña de al menos {_MIN_PASSWORD_LENGTH} caracteres."
        )
    confirmation = getpass.getpass("Repite la contraseña: ")
    if password != confirmation:
        raise ToolError("Las contraseñas no coinciden.")
    return password


def _read_passphrase() -> str:
    password = getpass.getpass("Contraseña secreta: ")
    if not password:
        raise ToolError("La contraseña no puede estar vacía.")
    return password


def _ask_path(prompt: str) -> str:
    value = input(prompt).strip().strip('"')
    if not value:
        raise ToolError("Debes indicar una ruta.")
    return value


def _encrypt_interactive(text: str | None = None) -> None:
    plaintext = text if text is not None else input("Texto o frase que quieres proteger: ")
    token = encrypt_text(plaintext, _read_new_passphrase())
    print("\nTexto protegido S4S2 (comprimido y cifrado automáticamente):\n")
    print(token)
    print()
    _show_compaction(len(plaintext), len(token))


def _decrypt_interactive(value: str | None = None) -> None:
    token = value if value is not None else input("Pega el texto S4S1/S4S2: ")
    plaintext = decrypt_text(token, _read_passphrase())
    print("\nTexto original:\n")
    print(plaintext)


def _recover_interactive(value: str | None = None) -> None:
    token = (
        value
        if value is not None
        else input("Pega el texto protegido o compacto (S4S1, S4S2 o CZ1): ")
    ).strip()

    if token.startswith("CZ1."):
        plaintext = expand_text(token)
        source = "CZ1"
    elif token.startswith(("S4S1.", "S4S2.")):
        plaintext = decrypt_text(token, _read_passphrase())
        source = token[:4]
    else:
        raise ToolError(
            "Formato desconocido. El texto debe comenzar con S4S1., S4S2. o CZ1."
        )

    print(f"\nTexto recuperado desde {source}:\n")
    print(plaintext)


def _show_compaction(original_length: int, compact_length: int) -> None:
    difference = original_length - compact_length
    if difference > 0:
        percentage = difference / original_length * 100
        print(
            f"Longitud: {original_length} -> {compact_length} caracteres "
            f"({difference} menos, {percentage:.1f}% de reducción)."
        )
    elif difference == 0:
        print(f"Longitud: {original_length} caracteres; no hubo ahorro.")
    else:
        print(
            f"Longitud: {original_length} -> {compact_length} caracteres "
            f"({-difference} más; el contenido no es compresible)."
        )


def _compact_interactive(text: str | None = None) -> None:
    plaintext = text if text is not None else input("Texto a comprimir y codificar: ")
    token = compact_text(plaintext)
    print("\nTexto compacto CZ1:\n")
    print(token)
    print()
    _show_compaction(len(plaintext), len(token))
    print("CZ1 comprime, pero NO cifra ni oculta el contenido.")


def _expand_interactive(value: str | None = None) -> None:
    token = value if value is not None else input("Pega el texto CZ1: ")
    plaintext = expand_text(token)
    print("\nTexto restaurado:\n")
    print(plaintext)
    print()
    _show_compaction(len(plaintext), len(token.strip()))


def _generate_password_interactive(
    length: int | None = None,
    *,
    include_symbols: bool = True,
) -> None:
    if length is None:
        raw_length = input("Longitud [24]: ").strip()
        try:
            length = int(raw_length) if raw_length else 24
        except ValueError as exc:
            raise ToolError("La longitud debe ser un número entero.") from exc
    password = generate_password(length, include_symbols=include_symbols)
    print("\nContraseña generada (guárdala en un gestor seguro):\n")
    print(password)


def _analyze_password_interactive() -> None:
    password = getpass.getpass("Contraseña a evaluar (no se almacena): ")
    report = analyze_password(password)
    print(f"\nFortaleza: {report.score}/4 — {report.label}")
    print(f"Estimación con hash lento: {report.crack_time}")
    if report.warning:
        print(f"Aviso de zxcvbn: {report.warning}")
    for suggestion in report.suggestions:
        print(f"- {suggestion}")


def _hash_file_interactive(
    path: str | None = None,
    algorithm: str = "sha256",
) -> None:
    selected = path if path is not None else _ask_path("Ruta del archivo: ")
    result = hash_file(selected, algorithm)
    print(f"\n{algorithm.upper()} ({Path(selected).expanduser()}):\n{result}")


def _verify_hash_interactive(
    path: str | None = None,
    expected: str | None = None,
    algorithm: str = "sha256",
) -> bool:
    selected = path if path is not None else _ask_path("Ruta del archivo: ")
    fingerprint = expected if expected is not None else input("Huella esperada: ").strip()
    matches = verify_file_hash(selected, fingerprint, algorithm)
    if matches:
        print("\nCoincide: el archivo tiene la huella esperada.")
    else:
        print("\nNO coincide: no confíes en este archivo.", file=sys.stderr)
    return matches


def _totp_interactive(*, new_secret: bool = False) -> None:
    if not new_secret:
        choice = input("[1] Generar código  [2] Crear secreto nuevo: ").strip()
        new_secret = choice == "2"

    if new_secret:
        secret = create_totp_secret()
        print("\nSecreto TOTP nuevo (se muestra una sola vez):\n")
        print(secret)
        print("\nImpórtalo en tu autenticador y guárdalo cifrado; quien lo tenga genera tus códigos.")
        return

    secret = getpass.getpass("Secreto TOTP Base32 (entrada oculta): ")
    code = generate_totp_code(secret)
    print(f"\nCódigo: {code.value}  (vence en {code.remaining_seconds} s)")


def _scan_secrets_interactive(path: str | None = None) -> ScanReport:
    selected = path if path is not None else _ask_path("Archivo o carpeta a revisar: ")
    report = scan_for_secrets(selected)
    print(
        f"\nArchivos revisados: {report.scanned_files}; "
        f"omitidos: {report.skipped_files}; hallazgos: {len(report.findings)}"
    )
    for finding in report.findings:
        print(f"- {finding.path}:{finding.line} — posible {finding.kind}")
    if report.findings:
        print("\nRevisa y rota las credenciales confirmadas. El escáner nunca imprime sus valores.")
    else:
        print("No se detectaron firmas conocidas; esto no garantiza que no existan secretos.")
    return report


def _inspect_url_interactive(url: str | None = None) -> None:
    selected = url if url is not None else input("URL a analizar: ")
    report = inspect_url(selected)
    print(f"\nHost interpretado: {report.hostname}")
    if not report.findings:
        print("No se detectaron señales estáticas obvias.")
    for finding in report.findings:
        print(f"- [{finding.level.upper()}] {finding.message}")
    print("El análisis es local y no visita la URL; un resultado limpio no demuestra que sea segura.")


def build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    tools = (
        Tool(
            "1",
            "Proteger texto",
            "Comprime y cifra automáticamente en un secreto S4S2.",
            _encrypt_interactive,
            "Texto y secretos",
        ),
        Tool(
            "2",
            "Recuperar texto",
            "Detecta y abre S4S1, S4S2 o CZ1 automáticamente.",
            _recover_interactive,
            "Texto y secretos",
        ),
        Tool(
            "3",
            "Compactar sin contraseña",
            "Crea CZ1; reduce texto, pero no lo cifra.",
            _compact_interactive,
            "Texto y secretos",
        ),
        Tool(
            "4",
            "Generar contraseña",
            "Crea una contraseña con aleatoriedad criptográfica.",
            _generate_password_interactive,
            "Contraseñas y 2FA",
        ),
        Tool(
            "5",
            "Evaluar contraseña",
            "Estima fortaleza localmente con zxcvbn.",
            _analyze_password_interactive,
            "Contraseñas y 2FA",
        ),
        Tool(
            "6",
            "Código TOTP",
            "Crea secretos o genera códigos 2FA compatibles.",
            _totp_interactive,
            "Contraseñas y 2FA",
        ),
        Tool(
            "7",
            "Calcular hash",
            "Obtiene SHA-256, SHA-512 o BLAKE2b de un archivo.",
            _hash_file_interactive,
            "Archivos y análisis",
        ),
        Tool(
            "8",
            "Verificar hash",
            "Compara la integridad de un archivo.",
            _verify_hash_interactive,
            "Archivos y análisis",
        ),
        Tool(
            "9",
            "Buscar secretos",
            "Detecta credenciales expuestas sin mostrar sus valores.",
            _scan_secrets_interactive,
            "Archivos y análisis",
        ),
        Tool(
            "10",
            "Analizar URL",
            "Busca señales sospechosas sin abrir la dirección.",
            _inspect_url_interactive,
            "Archivos y análisis",
        ),
    )
    for tool in tools:
        registry.register(tool)
    return registry


def _show_tools(registry: ToolRegistry) -> None:
    previous_category: str | None = None
    for tool in registry.all():
        if tool.category != previous_category:
            if previous_category is not None:
                print()
            print(f"{tool.category}:")
            previous_category = tool.category
        print(f"{tool.key}. {tool.name} — {tool.description}")
    print()


def _run_menu(registry: ToolRegistry) -> int:
    print("\nits_4_s3cr3_t — caja defensiva de ciberseguridad\n")
    print("Todo está aquí: elige una opción; no necesitas ejecutar subcomandos.\n")
    while True:
        _show_tools(registry)
        print("0. Salir")
        choice = input("\nElige una opción: ").strip()
        if choice == "0":
            return 0

        tool = registry.get(choice)
        if tool is None:
            print("\nOpción desconocida.\n", file=sys.stderr)
            continue

        try:
            print()
            tool.run()
            print()
        except ToolError as exc:
            print(f"\nError: {exc}\n", file=sys.stderr)
        except (EOFError, KeyboardInterrupt):
            print("\nOperación cancelada. Volviste al menú.\n", file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-tools",
        description="Caja defensiva y extensible de herramientas personales.",
    )
    subparsers = parser.add_subparsers(dest="command")

    encrypt_parser = subparsers.add_parser("encrypt", help="Cifra una palabra o frase.")
    encrypt_parser.add_argument(
        "--text",
        help="Texto directo (puede quedar guardado en el historial de la terminal).",
    )

    decrypt_parser = subparsers.add_parser("decrypt", help="Descifra un token S4S1.")
    decrypt_parser.add_argument(
        "--value",
        help="Token S4S1/S4S2 directo; puede requerir comillas y quedar en el historial.",
    )

    password_parser = subparsers.add_parser(
        "generate-password", help="Genera una contraseña segura."
    )
    password_parser.add_argument("--length", type=int, default=24)
    password_parser.add_argument("--no-symbols", action="store_true")

    subparsers.add_parser("password-strength", help="Evalúa una contraseña sin enviarla.")

    hash_parser = subparsers.add_parser("hash-file", help="Calcula el hash de un archivo.")
    hash_parser.add_argument("--file")
    hash_parser.add_argument("--algorithm", choices=SUPPORTED_ALGORITHMS, default="sha256")

    verify_parser = subparsers.add_parser("verify-hash", help="Verifica el hash de un archivo.")
    verify_parser.add_argument("--file")
    verify_parser.add_argument("--expected")
    verify_parser.add_argument("--algorithm", choices=SUPPORTED_ALGORITHMS, default="sha256")

    totp_parser = subparsers.add_parser("totp", help="Crea un secreto o genera un código TOTP.")
    totp_parser.add_argument("--new-secret", action="store_true")

    scan_parser = subparsers.add_parser("scan-secrets", help="Busca credenciales expuestas.")
    scan_parser.add_argument("--path")

    url_parser = subparsers.add_parser("inspect-url", help="Analiza una URL sin visitarla.")
    url_parser.add_argument("--url")

    compact_parser = subparsers.add_parser(
        "compact", help="Comprime texto y lo codifica como CZ1/Base85."
    )
    compact_parser.add_argument(
        "--text",
        help="Texto directo (puede quedar guardado en el historial de la terminal).",
    )

    expand_parser = subparsers.add_parser(
        "expand", help="Restaura un texto compacto CZ1."
    )
    expand_parser.add_argument(
        "--value",
        help="Token CZ1 directo; puede requerir comillas y quedar en el historial.",
    )

    subparsers.add_parser("list", help="Muestra las herramientas disponibles.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    registry = build_registry()

    try:
        if args.command is None:
            return _run_menu(registry)
        if args.command == "encrypt":
            _encrypt_interactive(args.text)
        elif args.command == "decrypt":
            _decrypt_interactive(args.value)
        elif args.command == "generate-password":
            _generate_password_interactive(args.length, include_symbols=not args.no_symbols)
        elif args.command == "password-strength":
            _analyze_password_interactive()
        elif args.command == "hash-file":
            _hash_file_interactive(args.file, args.algorithm)
        elif args.command == "verify-hash":
            return 0 if _verify_hash_interactive(args.file, args.expected, args.algorithm) else 1
        elif args.command == "totp":
            _totp_interactive(new_secret=args.new_secret)
        elif args.command == "scan-secrets":
            return 1 if _scan_secrets_interactive(args.path).findings else 0
        elif args.command == "inspect-url":
            _inspect_url_interactive(args.url)
        elif args.command == "compact":
            _compact_interactive(args.text)
        elif args.command == "expand":
            _expand_interactive(args.value)
        elif args.command == "list":
            _show_tools(registry)
        return 0
    except (EOFError, KeyboardInterrupt):
        print("\nOperación cancelada.", file=sys.stderr)
        return 130
    except ToolError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
