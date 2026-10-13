"""Runs the test suite for the gate and refuses a run that examined nothing.

A plain ``unittest`` run exits 0 with every test skipped, and on some versions
with no test at all. This runner fails on either, on a conformance case or an
answer vector of ``testdata/enforce`` that no test ran, and when one of the
tests a public claim rests on did not run.

    python -I -B run_tests.py --bin DIR
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import unittest
from collections.abc import Collection, Sized
from pathlib import Path
from typing import Protocol

HERE = Path(__file__).resolve().parent
TESTDATA = HERE.parent.parent / "testdata" / "enforce"

# Isolated mode leaves the script's directory off the path.
sys.path[:0] = [str(HERE / "src"), str(HERE)]

# Tests a page or the record names: the run against a real plane, the reading
# of the module's imports, the harness's independence, and this gate's own
# controls. A renamed or uncollected one fails the run.
PROMISED = (
    "tests.test_e2e.Plane.test_an_allowed_call_runs_and_a_denied_one_never_reaches_the_tool",
    "tests.test_imports.Imports.test_the_module_imports_only_the_allowed_modules_and_itself",
    "tests.test_imports.Imports.test_the_second_client_and_the_harness_take_only_public_types",
    "tests.test_gate.Runner.test_each_way_a_run_examines_nothing_is_a_problem",
    "tests.test_gate.Wheel.test_each_defect_of_the_built_files_is_refused",
)


class Outcome(Protocol):
    """What the runner reads of a finished run."""

    testsRun: int  # noqa: N815
    skipped: Sized
    expectedFailures: Sized  # noqa: N815
    unexpectedSuccesses: Sized  # noqa: N815
    failures: Sized
    errors: Sized
    started: Collection[str]


class _Recording(unittest.TextTestResult):
    """A result that remembers the id of every test it started."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.started: set[str] = set()

    def startTest(self, test: unittest.TestCase) -> None:  # noqa: N802
        super().startTest(test)
        self.started.add(test.id())


def _method(case_id: str) -> str:
    return "test_" + case_id.replace("-", "_")


def required_tests() -> list[str]:
    """The tests that must run: three per client case, two per vector, the promised ones."""
    listed = json.loads((TESTDATA / "cases.json").read_text(encoding="utf-8"))["cases"]
    cases = [c["id"] for c in listed if c["side"] == "client"]
    vectors = [
        json.loads(line)["id"]
        for line in (TESTDATA / "answers" / "vectors.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    if not cases or not vectors:
        raise SystemExit("run_tests: the shared files list no client case or no answer vector")
    suites = ("ReferenceClient", "SecondClient", "NegativeControls")
    needed = [f"tests.test_conformance.{s}.{_method(c)}" for s in suites for c in cases]
    needed += [f"tests.test_vectors.{s}.{_method(v)}" for s in suites[:2] for v in vectors]
    return [*needed, *PROMISED]


def judge(outcome: Outcome, required: Collection[str]) -> list[str]:
    """Every way a run did not examine what the gate says it examined."""
    problems = []
    if outcome.testsRun == 0:
        problems.append("no test ran")
    if len(outcome.skipped):
        problems.append(f"{len(outcome.skipped)} test(s) skipped")
    if len(outcome.expectedFailures) or len(outcome.unexpectedSuccesses):
        problems.append("a test is marked as an expected failure")
    if len(outcome.failures) or len(outcome.errors):
        problems.append(f"{len(outcome.failures)} failure(s), {len(outcome.errors)} error(s)")
    missing = sorted(name for name in required if name not in outcome.started)
    if missing:
        problems.append(f"{len(missing)} required test(s) did not run, the first: {missing[0]}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bin", required=True, help="the directory holding the built commands")
    args = parser.parse_args()
    # The end-to-end test starts a real plane from these; it fails without them.
    os.environ["ENFORCE_E2E_BIN"] = str(Path(args.bin).resolve())

    suite = unittest.defaultTestLoader.discover(str(HERE / "tests"), top_level_dir=str(HERE))
    runner = unittest.TextTestRunner(resultclass=_Recording, verbosity=1)
    result = runner.run(suite)
    if not isinstance(result, _Recording):
        raise SystemExit("run_tests: the runner did not use the recording result")

    problems = judge(result, required_tests())
    version = platform.python_version()
    if problems:
        print(f"run_tests: python {version}: " + "; ".join(problems), file=sys.stderr)
        return 1
    ran = f"{result.testsRun} tests, 0 skipped, every required test ran"
    print(f"run_tests: python {version}: {ran}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
