"""The gate's own two programs: each must refuse what it exists to refuse."""

from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
import zipfile
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import check_wheel
import run_tests

PROJECT = Path(__file__).resolve().parent.parent
LICENCE = PROJECT / "LICENSE"
DIST = check_wheel.MODULE
VERSION = "1.2.3"


def _module_files() -> list[str]:
    src = PROJECT / "src"
    return sorted(p.relative_to(src).as_posix() for p in (src / DIST).rglob("*") if p.is_file())


@dataclass(frozen=True)
class Shape:
    """One hand-made wheel; licence b"" stands for the repository's own."""

    version: str = VERSION
    requires: str = ""
    licence: bytes | None = b""
    extra: tuple[str, ...] = ()
    without: tuple[str, ...] = ()


def _wheel(directory: Path, shape: Shape = Shape()) -> None:  # noqa: B008
    info = f"{DIST}-{shape.version}.dist-info"
    head = f"Metadata-Version: 2.4\nName: {DIST}\nVersion: {shape.version}\n{shape.requires}"
    members = {name: b"" for name in _module_files() if name not in shape.without}
    members |= {
        f"{info}/METADATA": f"{head}\ntext\n".encode(),
        f"{info}/WHEEL": b"",
        f"{info}/RECORD": b"",
    }
    if shape.licence is not None:
        members[f"{info}/licenses/LICENSE"] = shape.licence or LICENCE.read_bytes()
    members |= {name.replace("INFO", info): b"" for name in shape.extra}
    with zipfile.ZipFile(directory / f"{DIST}-{shape.version}-py3-none-any.whl", "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)


def _sdist(directory: Path, *, names: tuple[str, ...] = ("LICENSE", "pyproject.toml")) -> None:
    with tarfile.open(directory / f"{DIST}-{VERSION}.tar.gz", "w:gz") as archive:
        for name in names:
            member = tarfile.TarInfo(f"{DIST}-{VERSION}/{name}")
            archive.addfile(member, io.BytesIO(b""))


class Runner(unittest.TestCase):
    """run_tests.judge, fed runs that examined less than they claim."""

    REQUIRED = ("a.test_one", "a.test_two")

    def _run(self, **changed: object) -> SimpleNamespace:
        clean: dict[str, object] = {
            "testsRun": 2,
            "skipped": [],
            "expectedFailures": [],
            "unexpectedSuccesses": [],
            "failures": [],
            "errors": [],
            "started": {"a.test_one", "a.test_two"},
        }
        return SimpleNamespace(**(clean | changed))

    def test_a_run_that_examined_everything_has_no_problem(self) -> None:
        self.assertEqual(run_tests.judge(self._run(), self.REQUIRED), [])

    def test_each_way_a_run_examines_nothing_is_a_problem(self) -> None:
        cases: dict[str, tuple[dict[str, object], str]] = {
            "no test": ({"testsRun": 0, "started": set()}, "no test ran"),
            "a skip": ({"skipped": [("a.test_one", "later")]}, "1 test(s) skipped"),
            "an expected failure": ({"expectedFailures": [1]}, "marked as an expected failure"),
            "an unexpected success": ({"unexpectedSuccesses": [1]}, "marked as an expected"),
            "a failure": ({"failures": [1]}, "1 failure(s), 0 error(s)"),
            "an error": ({"errors": [1, 2]}, "0 failure(s), 2 error(s)"),
            "a required test that did not run": (
                {"started": {"a.test_one"}},
                "1 required test(s) did not run, the first: a.test_two",
            ),
        }
        for name, (changed, want) in cases.items():
            with self.subTest(name):
                problems = run_tests.judge(self._run(**changed), self.REQUIRED)
                self.assertTrue(any(want in p for p in problems), problems)

    def test_the_required_tests_hold_every_case_every_vector_and_the_promised_ones(self) -> None:
        required = run_tests.required_tests()
        for name in (
            "tests.test_conformance.ReferenceClient.test_block",
            "tests.test_conformance.SecondClient.test_tool_reports_nothing",
            "tests.test_conformance.NegativeControls.test_execute_rewritten",
            "tests.test_vectors.ReferenceClient.test_admit_execute_full",
            "tests.test_vectors.SecondClient.test_admit_past_the_bound",
            "tests.test_e2e.Plane.test_an_allowed_call_runs_and_a_denied_one_never_reaches_the_tool",
            "tests.test_gate.Wheel.test_each_defect_of_the_built_files_is_refused",
        ):
            self.assertIn(name, required)
        self.assertEqual(len(required), len(set(required)))


class Wheel(unittest.TestCase):
    """check_wheel.check_files, fed built files a release must not hold."""

    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.dist = Path(scratch.name) / "dist"
        self.dist.mkdir()
        self.changelog = Path(scratch.name) / "CHANGELOG.md"
        self.changelog.write_text(
            f"# Changelog\n\n## [Unreleased]\n\n## [{VERSION}] - 2026-01-02\n"
        )

    def _problems(self) -> list[str]:
        return check_wheel.check_files(self.dist, LICENCE, self.changelog)

    def test_the_files_a_build_writes_pass(self) -> None:
        _wheel(self.dist)
        _sdist(self.dist)
        self.assertEqual(self._problems(), [])

    def test_each_defect_of_the_built_files_is_refused(self) -> None:
        first = _module_files()[0]
        wheels: dict[str, tuple[Shape, str]] = {
            "a requirement": (Shape(requires="Requires-Dist: anything"), "declares a requirement"),
            "no licence": (Shape(licence=None), "carries no licence"),
            "another licence": (Shape(licence=b"other terms"), "licence is not the repository's"),
            "another version": (Shape(version="1.2.4"), "its version is not 1.2.3"),
            "a file src/ lacks": (Shape(extra=(f"{DIST}/stowaway.py",)), "differ from src/"),
            "a file of src/ missing": (Shape(without=(first,)), "differ from src/"),
            "an entry point": (Shape(extra=("INFO/entry_points.txt",)), "describes itself with"),
        }
        for name, (shape, want) in wheels.items():
            with self.subTest(name):
                for old in self.dist.iterdir():
                    old.unlink()
                _wheel(self.dist, shape)
                _sdist(self.dist)
                self.assertTrue(any(want in p for p in self._problems()), self._problems())
        archives: dict[str, tuple[tuple[str, ...], str]] = {
            "the tests": (("LICENSE", "tests/test_x.py"), "carries the tests"),
            "no licence": (("pyproject.toml",), "source archive carries no licence"),
        }
        for name, (names, want) in archives.items():
            with self.subTest(f"a source archive with {name}"):
                for old in self.dist.iterdir():
                    old.unlink()
                _wheel(self.dist)
                _sdist(self.dist, names=names)
                self.assertTrue(any(want in p for p in self._problems()), self._problems())

    def test_two_wheels_are_refused(self) -> None:
        _wheel(self.dist)
        _wheel(self.dist, Shape(version="1.2.4"))
        _sdist(self.dist)
        with self.assertRaises(SystemExit):
            self._problems()

    def test_a_version_is_read_from_the_newest_dated_section_as_python_spells_it(self) -> None:
        spelled = {
            "## [2.0.0] - 2026-03-01\n\n## [1.9.0] - 2026-02-01\n": "2.0.0",
            "## [Unreleased]\n\n## [2.0.0-rc.1] - 2026-03-01\n": "2.0.0rc1",
            "## [2.0.0-beta.3] - 2026-03-01\n": "2.0.0b3",
            "## [0.10.2-alpha] - 2026-03-01\n": "0.10.2a0",
        }
        for text, want in spelled.items():
            with self.subTest(want):
                self.assertEqual(check_wheel.release_version(text), want)
        for text in ("## [Unreleased]\n", "## [2.0.0+build] - 2026-03-01\n", "## [2.0.0]\n"):
            with self.subTest(text), self.assertRaises(SystemExit):
                check_wheel.release_version(text)
