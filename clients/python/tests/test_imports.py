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


# The standard library's modules the list does not hold.
UNLISTED = set(sys.stdlib_module_names) - ALLOWED
# Names that load or build code, and the two refused as an attribute of anything.
LOADERS = {"__import__", "importlib", "eval", "exec", "compile"}
LOADERS_ANYWHERE = {"__import__", "importlib"}


def _reached(node: ast.Attribute, bound: set[str]) -> set[str]:
    """The chain node ends, as written, when it reaches a module the list does not hold."""
    names = [node.attr]
    value = node.value
    while isinstance(value, ast.Attribute):
        names.append(value.attr)
        value = value.value
    start = value.id if isinstance(value, ast.Name) else ""
    if node.attr in LOADERS_ANYWHERE or (start in bound and node.attr in UNLISTED):
        return {".".join([start, *reversed(names)]) if start else node.attr}
    return set()


def imports_of(source: str) -> tuple[set[str], set[str]]:
    """The top-level modules source imports absolutely, and each other way it reaches a module.

    Only what is written is read: an import, a name that loads or builds
    code, a module taken from another by a from-import, and an attribute
    chain that starts at a name an import bound. A module reached through
    getattr, vars, a __dict__ or __builtins__, or under a name an assignment
    gave it, is not seen.
    """
    tree = ast.parse(source)
    modules: set[str] = set()
    other: set[str] = set()
    bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {alias.name.split(".")[0] for alias in node.names}
            bound |= {alias.asname or alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                modules.add((node.module or "").split(".")[0])
            origin = "." * node.level + (node.module or "")
            bound |= {alias.asname or alias.name for alias in node.names}
            other |= {f"{origin}.{alias.name}" for alias in node.names if alias.name in UNLISTED}
        elif isinstance(node, ast.Name) and node.id in LOADERS:
            other.add(node.id)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            other |= _reached(node, bound)
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

    def test_the_reading_sees_a_module_reached_without_an_import_of_it(self) -> None:
        for source, ways in (
            ("import inspect\ninspect.importlib.import_module('os')\n", {"inspect.importlib"}),
            ("import socket\nsocket.os.system('id')\n", {"socket.os"}),
            ("import socket as s\ns.os.system('id')\n", {"s.os"}),
            ("import inspect\ninspect.types.sys.modules['os']\n", {"inspect.types.sys"}),
            ("from . import _wire\n_wire.json.os.getcwd()\n", {"_wire.json.os"}),
            ("from socket import os\n", {"socket.os"}),
            ("from inspect import importlib as loader\n", {"inspect.importlib"}),
            ("from ._transport import os\n", {"._transport.os"}),
            ("__import__('os')\n", {"__import__"}),
            ("def f(x):\n    return x.__import__('os')\n", {"x.__import__"}),
            ("importlib.import_module('os')\n", {"importlib"}),
            ("def f(x):\n    return x().importlib\n", {"importlib"}),
            ("eval('1')\n", {"eval"}),
            ("exec('x = 1')\n", {"exec"}),
            ("compile('1', 'f', 'eval')\n", {"compile"}),
            ("def late():\n    return socket.os\nimport socket\n", {"socket.os"}),
        ):
            with self.subTest(source=source):
                self.assertEqual(imports_of(source)[1], ways)

    def test_the_reading_passes_what_reaches_no_other_module(self) -> None:
        source = (
            "import re, socket, inspect\n"
            "from datetime import datetime\n"
            "from . import _ops\n"
            "pattern = re.compile('a')\n"
            "sock = socket.socket(socket.AF_UNIX)\n"
            "now = datetime.now()\n"
            "proxy = inspect.types.MappingProxyType\n"
            "done = _ops.complete\n"
            "def f(exc):\n"
            "    return exc.code, exc.os, exc.sys.modules\n"
        )
        self.assertEqual(imports_of(source), ({"re", "socket", "inspect", "datetime"}, set()))

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

    def test_every_source_file_is_ascii(self) -> None:
        """A character a reader cannot see, or tell from its twin, is written as an escape."""
        files = sorted([*SRC.rglob("*.py"), *Path(__file__).parent.rglob("*.py")])
        self.assertLessEqual({"_wire.py", "second_client.py"}, {path.name for path in files})
        for path in files:
            lines = path.read_bytes().splitlines()
            odd = [number for number, line in enumerate(lines, start=1) if not line.isascii()]
            self.assertEqual(odd, [], f"{path.name} holds a character outside ASCII on these lines")

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
