"""Runs the qualification harness's tests and refuses a run that examined nothing.

A plain unittest run exits 0 with every test skipped, and a SystemExit from a
test or a module fixture ends it with whatever status it carries. This runner
fails on each, on a failure, an error or an expected failure, and when a test
named below did not run. Its last line is its verdict.

    python -I -B run_tests.py
"""

import os
import platform
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

# Isolated mode leaves the script's directory off the path. It goes after the
# standard library, so nothing here can stand in for a module of it.
sys.path.append(HERE)

# The tests the harness's refusals rest on; a renamed or uncollected one fails the run.
PROMISED = (
    "tests.test_hold.Concurrent.test_a_retry_with_another_input_is_unknown",
    "tests.test_hold.Concurrent.test_no_file_and_no_edit_is_no_pass",
    "tests.test_hold.Resumed.test_no_file_and_no_edit_is_no_pass",
    "tests.test_verdicts.Allow.test_no_file_and_no_content_is_no_pass",
    "tests.test_bypasses.Disabled.test_no_control_invocation_is_unknown",
    "tests.test_bypasses.Disabled.test_a_control_that_recorded_nothing_is_unknown",
    "tests.test_bypasses.Matcher.test_no_recorded_call_beside_it_is_unknown",
    "tests.test_commands.Snapshot.test_a_missing_project_writes_nothing",
    "tests.test_commands.Snapshot.test_a_walk_that_fails_writes_nothing",
    "tests.test_commands.Scrubbed.test_every_kept_copy_is_judged_as_its_results_say",
    "tests.test_commands.StreamPart.test_the_models_text_and_reasoning_are_not_kept",
    "tests.test_commands.StreamLines.test_an_unreadable_line_is_replaced_and_reasoning_dropped",
    "tests.test_commands.Report.test_the_exit_status_follows_the_verdicts",
)


class Recording(unittest.TextTestResult):
    """A result that remembers every test it started."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.started: set[str] = set()

    def startTest(self, test: unittest.TestCase) -> None:  # noqa: N802
        super().startTest(test)
        self.started.add(test.id())


def problems(result: Recording) -> list[str]:
    found = []
    if result.testsRun == 0:
        found.append("no test ran")
    if result.skipped:
        found.append(f"{len(result.skipped)} test(s) skipped")
    if result.expectedFailures or result.unexpectedSuccesses:
        found.append("a test is marked as an expected failure")
    if result.failures or result.errors:
        found.append(f"{len(result.failures)} failure(s), {len(result.errors)} error(s)")
    missing = sorted(name for name in PROMISED if name not in result.started)
    if missing:
        found.append(f"{len(missing)} required test(s) did not run, the first: {missing[0]}")
    return found


def main() -> int:
    version = platform.python_version()
    try:
        suite = unittest.defaultTestLoader.discover(os.path.join(HERE, "tests"), top_level_dir=HERE)
        result = unittest.TextTestRunner(resultclass=Recording, verbosity=1).run(suite)
    except BaseException as exc:
        print(f"harness_tests: {type(exc).__name__} left the run: {exc}", file=sys.stderr)
        print(f"harness_tests: python {version}: the run was cut short", file=sys.stderr)
        return 1
    found = problems(result) if isinstance(result, Recording) else ["the run kept no record"]
    if found:
        print(f"harness_tests: python {version}: " + "; ".join(found), file=sys.stderr)
        return 1
    ran = f"{result.testsRun} tests, 0 skipped, every required test ran"
    print(f"harness_tests: python {version}: {ran}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
