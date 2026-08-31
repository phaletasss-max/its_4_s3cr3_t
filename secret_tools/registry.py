"""Catálogo central para ampliar la caja sin acoplar sus herramientas."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class Tool:
    key: str
    name: str
    description: str
    run: Callable[[], None]


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if not tool.key or tool.key in self._tools:
            raise ValueError(f"Clave de herramienta inválida o repetida: {tool.key!r}")
        self._tools[tool.key] = tool

    def get(self, key: str) -> Tool | None:
        return self._tools.get(key)

    def all(self) -> tuple[Tool, ...]:
        return tuple(self._tools.values())

