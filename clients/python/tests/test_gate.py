"""The gate's own two programs: each must refuse what it exists to refuse."""

from __future__ import annotations

import contextlib
import io
import tarfile
import tempfile
import unittest
import warnings
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
    altered: tuple[str, ...] = ()
    stated: str = ""


def _wheel(directory: Path, shape: Shape = Shape()) -> None:  # noqa: B008
    info = f"{DIST}-{shape.version}.dist-info"
    stated = shape.stated or shape.version
    head = f"Metadata-Version: 2.4\nName: {DIST}\nVersion: {stated}\n{shape.requires}"
    src = PROJECT / "src"
    members = {n: (src / n).read_bytes() for n in _module_files() if n not in shape.without}
    members |= {name: b"something else\n" for name in shape.altered}
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
            "bodiless": set(),
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
            "a test whose body never runs": (
                {"bodiless": {"a.test_two"}},
                "1 test(s) whose body never runs, the first: a.test_two",
            ),
        }
        for name, (changed, want) in cases.items():
            with self.subTest(name):
                problems = run_tests.judge(self._run(**changed), self.REQUIRED)
                self.assertTrue(any(want in p for p in problems), problems)

    def test_a_run_cut_short_is_no_pass(self) -> None:
        test = "class T(unittest.TestCase):\n    def test_x(self):\n        {act}\n"
        sources = {
            "cut_by_a_fixture": "def setUpModule():\n    raise SystemExit(0)\n\n\n"
            + test.format(act="pass"),
            "cut_by_a_test": test.format(act="raise SystemExit(0)"),
            "cut_on_import": "raise SystemExit(0)\n",
            "whole": test.format(act="pass"),
        }
        finished = {}
        for package, source in sources.items():
            with tempfile.TemporaryDirectory() as top:
                tests = Path(top) / package
                tests.mkdir()
                (tests / "__init__.py").write_text("")
                (tests / "test_it.py").write_text("import unittest\n\n\n" + source)
                with contextlib.redirect_stderr(io.StringIO()):
                    finished[package] = run_tests.run(str(tests), top)
        # unittest lets an exit from a module fixture end the run; one from a
        # test or from an import it records as an error.
        self.assertIsNone(finished["cut_by_a_fixture"])
        for package in ("cut_by_a_test", "cut_on_import"):
            with self.subTest(package):
                recorded = finished[package]
                if recorded is None:
                    self.fail("an exit unittest records came back as a run cut short")
                problems = run_tests.judge(recorded, [])
                self.assertTrue(any("error(s)" in p for p in problems), problems)
        whole = finished["whole"]
        if whole is None:
            self.fail("a run nothing cut short came back as cut short")
        self.assertEqual(run_tests.judge(whole, ["whole.test_it.T.test_x"]), [])

    def test_a_test_whose_body_never_runs_is_a_problem(self) -> None:
        source = (
            "import unittest\n\n\n"
            "class T(unittest.TestCase):\n"
            "    async def test_awaited(self):\n        self.fail('never reached')\n\n"
            "    def test_yielded(self):\n        yield\n        self.fail('never reached')\n\n"
            "    def test_plain(self):\n        pass\n"
        )
        with tempfile.TemporaryDirectory() as top:
            tests = Path(top) / "bodiless"
            tests.mkdir()
            (tests / "__init__.py").write_text("")
            (tests / "test_it.py").write_text(source)
            with contextlib.redirect_stderr(io.StringIO()), warnings.catch_warnings():
                warnings.simplefilter("ignore")
                finished = run_tests.run(str(tests), top)
        if finished is None:
            self.fail("the run came back as cut short")
        self.assertEqual(
            sorted(finished.bodiless),
            ["bodiless.test_it.T.test_awaited", "bodiless.test_it.T.test_yielded"],
        )
        problems = run_tests.judge(finished, [])
        self.assertTrue(any("2 test(s) whose body never runs" in p for p in problems), problems)

    def test_the_report_follows_the_judgement(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            clean = run_tests.report(self._run(), self.REQUIRED, "9.9.9")
            failing = run_tests.report(self._run(failures=[1]), self.REQUIRED, "9.9.9")
            missing = run_tests.report(self._run(started=set()), self.REQUIRED, "9.9.9")
            cut = run_tests.report(None, self.REQUIRED, "9.9.9")
        self.assertEqual((clean, failing, missing, cut), (0, 1, 1, 1))
        self.assertEqual(
            out.getvalue(),
            "run_tests: python 9.9.9: 2 tests, 0 skipped, every required test ran\n",
        )
        self.assertIn("1 failure(s), 0 error(s)", err.getvalue())
        self.assertIn("the run was cut short", err.getvalue())

    def test_the_promised_tests_are_all_there(self) -> None:
        self.assertEqual(len(run_tests.PROMISED), 42)
        self.assertEqual(len(set(run_tests.PROMISED)), 42)

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
        first, last = _module_files()[0], _module_files()[-1]
        wheels: dict[str, tuple[Shape, str]] = {
            "a requirement": (Shape(requires="Requires-Dist: anything"), "declares a requirement"),
            "another requirement": (
                Shape(requires="Requires-Dist: other-thing>=2"),
                "declares a requirement",
            ),
            "a version stated otherwise inside": (Shape(stated="9.9.9"), "version is not 1.2.3"),
            "no licence": (Shape(licence=None), "carries no licence"),
            "another licence": (Shape(licence=b"other terms"), "licence is not the repository's"),
            "another version": (Shape(version="1.2.4"), "its version is not 1.2.3"),
            "a file src/ lacks": (Shape(extra=(f"{DIST}/stowaway.py",)), "differ from src/"),
            "a file of src/ missing": (Shape(without=(first,)), "differ from src/"),
            "a file of src/ altered": (Shape(altered=(first,)), "do not hold what src/ holds"),
            "the last file altered": (Shape(altered=(last,)), "do not hold what src/ holds"),
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

    def test_a_project_licence_that_is_not_the_repositorys_is_refused(self) -> None:
        other = self.dist.parent / "LICENSE"
        other.write_bytes(b"other terms\n")
        _wheel(self.dist, Shape(licence=b"other terms\n"))
        _sdist(self.dist)
        problems = check_wheel.check_files(self.dist, other, self.changelog)
        self.assertEqual(problems, ["clients/python/LICENSE is not the repository's LICENSE"])

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
