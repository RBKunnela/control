"""Runs the test suite for the gate and refuses a run that examined nothing.

A plain ``unittest`` run exits 0 with every test skipped, with a module
fixture that exits, and on some versions with no test at all. This runner
fails on each, on a conformance case or an answer vector of
``testdata/enforce`` that no test ran, and when one of the tests a public
claim rests on did not run.

It cannot defend against a test that reaches into this process and rewrites
the judgement, any more than a compiled test can be kept from printing its
own pass: the tests run where the runner does. Review is the defence there.

    python -I -B run_tests.py --bin DIR
"""

from __future__ import annotations

import argparse
import inspect
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

# Isolated mode leaves the script's directory off the path. The tree goes
# after the standard library, so nothing in it can stand in for a module of it.
sys.path += [str(HERE / "src"), str(HERE)]

# Tests a page or the record names: the run against a real plane, the reading
# of the module's imports, the harness's independence, the rules no case file
# holds, the reader's refusals, the transport's bounds, and this gate's own
# controls. A renamed, deleted or uncollected one fails the run.
_RULES = "tests.test_rules"
_TRANSPORT = "tests.test_transport.Transport"
PROMISED = (
    "tests.test_e2e.Plane.test_an_allowed_call_runs_and_a_denied_one_never_reaches_the_tool",
    "tests.test_imports.Imports.test_the_module_imports_only_the_allowed_modules_and_itself",
    "tests.test_imports.Imports.test_the_second_client_and_the_harness_take_only_public_types",
    "tests.test_gate.Runner.test_each_way_a_run_examines_nothing_is_a_problem",
    "tests.test_gate.Runner.test_a_run_cut_short_is_no_pass",
    "tests.test_gate.Wheel.test_each_defect_of_the_built_files_is_refused",
    "tests.test_conformance.CaseFiles.test_the_index_lists_the_directories",
    "tests.test_vectors.VectorFile.test_the_pinned_refusals_are_the_files_may_refuse_vectors",
    "tests.test_wire.Refused.test_every_refusal",
    "tests.test_wire.Refused.test_the_other_answers_are_read_as_strictly",
    f"{_RULES}.Construction.test_a_timeout_that_is_no_finite_positive_number_is_refused",
    f"{_RULES}.Returning.test_only_recorded_says_the_record_landed",
    f"{_RULES}.Returning.test_an_answer_the_client_cannot_act_on_sends_nothing",
    f"{_RULES}.Aborting.test_an_obligation_outranks_missing_bytes_and_a_gone_caller",
    f"{_RULES}.Aborting.test_a_refused_abort_is_still_an_abort",
    f"{_RULES}.Aborting.test_a_caller_gone_before_admit_sends_nothing",
    f"{_RULES}.Aborting.test_an_interrupt_between_admit_and_the_tool_aborts_and_is_raised_again",
    f"{_RULES}.Running.test_the_tool_cannot_change_what_complete_reports_as_sent",
    f"{_RULES}.Running.test_not_sent_met_only_in_a_chain_completes",
    f"{_RULES}.Running.test_any_exception_of_the_tool_is_completed_unknown_and_raised_again",
    f"{_RULES}.Running.test_an_interrupt_after_the_tool_is_completed_unknown_and_raised_again",
    f"{_RULES}.Running.test_a_tool_that_cannot_return_a_result_is_refused_before_admit",
    f"{_RULES}.Running.test_one_client_serves_concurrent_calls_from_threads",
    f"{_TRANSPORT}.test_the_timeout_bounds_a_whole_request_not_each_read",
    f"{_TRANSPORT}.test_an_answer_at_the_bound_is_read_and_one_byte_past_it_is_not",
    f"{_TRANSPORT}.test_a_redirect_is_not_followed",
    f"{_TRANSPORT}.test_a_bound_on_the_head_or_on_a_chunk_ends_the_read_at_once",
    f"{_TRANSPORT}.test_a_framing_a_stricter_reader_refuses_is_no_answer",
    f"{_TRANSPORT}.test_the_framings_a_receiver_may_write_are_still_read",
    f"{_RULES}.Nested.test_an_exception_of_a_call_the_tool_made_leaves_as_the_outer_calls_own",
    f"{_RULES}.Nested.test_an_outer_complete_that_did_not_land_is_raised_from_the_outer_calls_own",
    f"{_RULES}.Nested.test_a_group_holding_an_exception_of_a_call_leaves_as_the_outer_calls_own",
    f"{_RULES}.Nested.test_a_group_that_holds_an_interrupt_leaves_as_raised",
    f"{_RULES}.Nested.test_a_group_holding_no_exception_of_this_module_leaves_unchanged",
    f"{_TRANSPORT}.test_a_trailer_that_never_ends_ends_the_call_by_the_timeout",
    "tests.test_e2e.Commands.test_the_plane_is_named_gateway_and_the_command_is_the_other",
    "tests.test_e2e.Commands.test_any_other_holding_is_refused_and_named",
    "tests.test_imports.Imports.test_every_source_file_is_ascii",
    "tests.test_harness.Comparison.test_requests_are_held_to_their_expectation",
    "tests.test_harness.Receivers.test_a_request_the_script_does_not_hold_is_refused",
    "tests.test_gate.Runner.test_a_test_whose_body_never_runs_is_a_problem",
    "tests.test_gate.Runner.test_the_report_follows_the_judgement",
)


# What unittest calls, gets a coroutine or a generator back from, and counts
# as passed without running a line of.
_BODILESS = (
    inspect.iscoroutinefunction,
    inspect.isgeneratorfunction,
    inspect.isasyncgenfunction,
)


class Outcome(Protocol):
    """What the runner reads of a finished run; read-only, so a list of anything fits."""

    @property
    def testsRun(self) -> int: ...  # noqa: N802
    @property
    def skipped(self) -> Sized: ...
    @property
    def expectedFailures(self) -> Sized: ...  # noqa: N802
    @property
    def unexpectedSuccesses(self) -> Sized: ...  # noqa: N802
    @property
    def failures(self) -> Sized: ...
    @property
    def errors(self) -> Sized: ...
    @property
    def started(self) -> Collection[str]: ...
    @property
    def bodiless(self) -> Collection[str]: ...


class _Recording(unittest.TextTestResult):
    """A result that remembers every test it started, and those that cannot run."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.started: set[str] = set()
        self.bodiless: set[str] = set()

    def startTest(self, test: unittest.TestCase) -> None:  # noqa: N802
        super().startTest(test)
        self.started.add(test.id())
        method = getattr(test, getattr(test, "_testMethodName", ""), None)
        if any(is_bodiless(method) for is_bodiless in _BODILESS):
            self.bodiless.add(test.id())


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
    if len(outcome.bodiless):
        first = sorted(outcome.bodiless)[0]
        problems.append(
            f"{len(outcome.bodiless)} test(s) whose body never runs, the first: {first}"
        )
    missing = sorted(name for name in required if name not in outcome.started)
    if missing:
        problems.append(f"{len(missing)} required test(s) did not run, the first: {missing[0]}")
    return problems


def run(tests: str, top: str) -> _Recording | None:
    """The finished run, or nothing when anything cut it short.

    unittest lets a SystemExit or an interrupt from a test or a module fixture
    end the process, and an exit with status 0 would then read as a pass.
    """
    try:
        suite = unittest.defaultTestLoader.discover(tests, top_level_dir=top)
        result = unittest.TextTestRunner(resultclass=_Recording, verbosity=1).run(suite)
    except BaseException as exc:
        print(f"run_tests: {type(exc).__name__} left the run: {exc}", file=sys.stderr)
        return None
    return result if isinstance(result, _Recording) else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bin", required=True, help="the directory holding the built commands")
    args = parser.parse_args()
    # The end-to-end test starts a real plane from these; it fails without them.
    os.environ["ENFORCE_E2E_BIN"] = str(Path(args.bin).resolve())

    return report(run(str(HERE / "tests"), str(HERE)), required_tests(), platform.python_version())


def report(result: Outcome | None, required: Collection[str], version: str) -> int:
    """Prints the verdict of a run as its last line and returns the exit status."""
    if result is None:
        print(f"run_tests: python {version}: the run was cut short", file=sys.stderr)
        return 1
    problems = judge(result, required)
    if problems:
        print(f"run_tests: python {version}: " + "; ".join(problems), file=sys.stderr)
        return 1
    ran = f"{result.testsRun} tests, 0 skipped, every required test ran"
    print(f"run_tests: python {version}: {ran}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
