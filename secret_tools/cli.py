"""Interfaz de consola para la caja de herramientas."""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Sequence

from .crypto import SecretCipherError, decrypt_text, encrypt_text
from .registry import Tool, ToolRegistry

_MIN_PASSWORD_LENGTH = 8


def _read_new_passphrase() -> str:
    password = getpass.getpass("Contraseña secreta: ")
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise SecretCipherError(
            f"Usa una contraseña de al menos {_MIN_PASSWORD_LENGTH} caracteres."
        )
    confirmation = getpass.getpass("Repite la contraseña: ")
    if password != confirmation:
        raise SecretCipherError("Las contraseñas no coinciden.")
    return password


def _read_passphrase() -> str:
    password = getpass.getpass("Contraseña secreta: ")
    if not password:
        raise SecretCipherError("La contraseña no puede estar vacía.")
    return password


def _encrypt_interactive(text: str | None = None) -> None:
    plaintext = text if text is not None else input("Texto o frase a cifrar: ")
    token = encrypt_text(plaintext, _read_new_passphrase())
    print("\nTexto cifrado:\n")
    print(token)


def _decrypt_interactive(value: str | None = None) -> None:
    token = value if value is not None else input("Pega el texto S4S1: ")
    plaintext = decrypt_text(token, _read_passphrase())
    print("\nTexto original:\n")
    print(plaintext)


def build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        Tool(
            key="1",
            name="Cifrar texto",
            description="Convierte una palabra o frase en un secreto S4S1.",
            run=_encrypt_interactive,
        )
    )
    registry.register(
        Tool(
            key="2",
            name="Descifrar texto",
            description="Recupera el texto usando su contraseña.",
            run=_decrypt_interactive,
        )
    )
    return registry


def _show_tools(registry: ToolRegistry) -> None:
    for tool in registry.all():
        print(f"{tool.key}. {tool.name} — {tool.description}")


def _run_menu(registry: ToolRegistry) -> int:
    print("\nits_4_s3cr3_t — caja de herramientas\n")
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
        except SecretCipherError as exc:
            print(f"\nError: {exc}\n", file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-tools",
        description="Caja extensible de pequeñas herramientas personales.",
    )
    subparsers = parser.add_subparsers(dest="command")

    encrypt_parser = subparsers.add_parser("encrypt", help="Cifra una palabra o frase.")
    encrypt_parser.add_argument(
        "--text",
        help="Texto directo (puede quedar guardado en el historial de la terminal).",
    )

    decrypt_parser = subparsers.add_parser("decrypt", help="Descifra un token S4S1.")
    decrypt_parser.add_argument("--value", help="Token S4S1 que se desea descifrar.")

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
        elif args.command == "list":
            _show_tools(registry)
        return 0
    except (EOFError, KeyboardInterrupt):
        print("\nOperación cancelada.", file=sys.stderr)
        return 130
    except SecretCipherError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

