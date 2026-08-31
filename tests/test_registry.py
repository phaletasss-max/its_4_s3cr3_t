import unittest

from secret_tools.registry import Tool, ToolRegistry


class ToolRegistryTests(unittest.TestCase):
    def test_registers_and_lists_a_tool(self) -> None:
        registry = ToolRegistry()
        tool = Tool("x", "Ejemplo", "Descripción", lambda: None)

        registry.register(tool)

        self.assertIs(registry.get("x"), tool)
        self.assertEqual(registry.all(), (tool,))

    def test_rejects_duplicate_keys(self) -> None:
        registry = ToolRegistry()
        registry.register(Tool("x", "Uno", "", lambda: None))

        with self.assertRaises(ValueError):
            registry.register(Tool("x", "Dos", "", lambda: None))


if __name__ == "__main__":
    unittest.main()

