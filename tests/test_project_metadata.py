import tomllib
import unittest
from pathlib import Path

import secret_tools


class ProjectMetadataTests(unittest.TestCase):
    def test_package_version_matches_pyproject(self) -> None:
        project_file = Path(__file__).resolve().parents[1] / "pyproject.toml"
        project = tomllib.loads(project_file.read_text(encoding="utf-8"))

        self.assertEqual(secret_tools.__version__, project["project"]["version"])


if __name__ == "__main__":
    unittest.main()
