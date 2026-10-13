"""Runs the test suite for the gate and refuses a run that examined nothing.

A plain ``unittest`` run exits 0 with every test skipped, and on some versions
with no test at all. This runner fails on either, and on a conformance case or
an answer vector of ``testdata/enforce`` that no test ran.

    python -I -B run_tests.py --bin DIR
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TESTDATA = HERE.parent.parent / "testdata" / "enforce"

# Isolated mode leaves the script's directory off the path.
sys.path[:0] = [str(HERE / "src"), str(HERE)]


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
    """The tests the shared files demand: three per client case, one per vector."""
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
    return needed


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

    problems = []
    if result.testsRun == 0:
        problems.append("no test ran")
    if result.skipped:
        problems.append(f"{len(result.skipped)} test(s) skipped")
    if result.expectedFailures or result.unexpectedSuccesses:
        problems.append("a test is marked as an expected failure")
    if not result.wasSuccessful():
        problems.append(f"{len(result.failures)} failure(s), {len(result.errors)} error(s)")
    missing = [name for name in required_tests() if name not in result.started]
    if missing:
        problems.append(
            f"{len(missing)} case or vector test(s) did not run, the first: {missing[0]}"
        )

    version = platform.python_version()
    if problems:
        print(f"run_tests: python {version}: " + "; ".join(problems), file=sys.stderr)
        return 1
    ran = f"{result.testsRun} tests, 0 skipped, every case and vector ran"
    print(f"run_tests: python {version}: {ran}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
