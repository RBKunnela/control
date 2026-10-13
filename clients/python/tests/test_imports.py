"""What the module may import: the standard library modules named here, and itself."""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
PACKAGE = "guardana_control"

ALLOWED = {
    "__future__",
    "base64",
    "codecs",
    "collections",
    "contextlib",
    "dataclasses",
    "datetime",
    "inspect",
    "json",
    "math",
    "re",
    "socket",
    "time",
    "types",
    "typing",
}

# The names a test's own client or harness may take from the module.
PUBLIC = {
    "Answer",
    "CallAborted",
    "CallBlocked",
    "CallPending",
    "CallRefused",
    "CallerGone",
    "EnforceError",
    "Held",
    "MalformedAnswer",
    "NoAnswer",
    "NotRecorded",
    "NotSent",
    "Result",
}


def imports_of(source: str) -> tuple[set[str], set[str]]:
    """The top-level modules source imports absolutely, and the ways it imports by other means."""
    modules: set[str] = set()
    other: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            modules.add((node.module or "").split(".")[0])
        elif isinstance(node, ast.Name) and node.id in ("__import__", "importlib", "exec", "eval"):
            other.add(node.id)
    return modules, other


def taken_from_the_module(source: str) -> set[str]:
    """Every name source imports from the package, a submodule spelled as its dotted path."""
    taken: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            taken |= {alias.name for alias in node.names if alias.name.split(".")[0] == PACKAGE}
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == PACKAGE:
            if node.module != f"{PACKAGE}.enforce":
                taken.add(node.module or "")
            else:
                taken |= {alias.name for alias in node.names}
    return taken


class Imports(unittest.TestCase):
    def test_the_reading_of_imports_sees_each_form(self) -> None:
        source = (
            "import os.path, json as j\n"
            "from urllib.request import urlopen\n"
            "from . import _wire\n"
            "from ._types import Answer\n"
            "def late():\n"
            "    import requests\n"
            "    return __import__('yaml')\n"
        )
        self.assertEqual(imports_of(source), ({"os", "json", "urllib", "requests"}, {"__import__"}))

    def test_every_allowed_module_is_of_the_standard_library(self) -> None:
        self.assertEqual(ALLOWED - set(sys.stdlib_module_names), set())

    def test_the_module_imports_only_the_allowed_modules_and_itself(self) -> None:
        files = sorted((SRC / PACKAGE).rglob("*.py"))
        self.assertEqual(
            [path.relative_to(SRC).as_posix() for path in files],
            [
                f"{PACKAGE}/__init__.py",
                f"{PACKAGE}/enforce/__init__.py",
                f"{PACKAGE}/enforce/_client.py",
                f"{PACKAGE}/enforce/_ops.py",
                f"{PACKAGE}/enforce/_schema.py",
                f"{PACKAGE}/enforce/_transport.py",
                f"{PACKAGE}/enforce/_types.py",
                f"{PACKAGE}/enforce/_wire.py",
            ],
        )
        used: set[str] = set()
        for path in files:
            modules, other = imports_of(path.read_text(encoding="utf-8"))
            self.assertEqual(modules - ALLOWED - {PACKAGE}, set(), path.name)
            self.assertEqual(other, set(), path.name)
            used |= modules
        self.assertEqual(ALLOWED - used, set(), "a module is allowed that nothing imports")

    def test_the_reading_of_what_a_test_takes_sees_each_form(self) -> None:
        source = (
            f"import {PACKAGE}.enforce._wire\n"
            f"from {PACKAGE}.enforce import Answer, _ops\n"
            f"from {PACKAGE}.enforce._schema import MESSAGES\n"
            f"from {PACKAGE} import enforce\n"
            "from tests import harness\n"
        )
        self.assertEqual(
            taken_from_the_module(source),
            {f"{PACKAGE}.enforce._wire", "Answer", "_ops", f"{PACKAGE}.enforce._schema", PACKAGE},
        )

    def test_the_second_client_and_the_harness_take_only_public_types(self) -> None:
        for name in ("second_client.py", "harness.py"):
            taken = taken_from_the_module(
                (Path(__file__).parent / name).read_text(encoding="utf-8")
            )
            self.assertTrue(taken, name)
            self.assertEqual(taken - PUBLIC, set(), name)
