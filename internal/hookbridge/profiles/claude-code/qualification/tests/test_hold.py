import json
import unittest

from harness_hold import judge_concurrent, judge_obligation, judge_pending
from tests import layouts
from tests.observations import SEEDS, Run


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.run_ = Run()
        self.addCleanup(self.run_.close)
        self.c = self.run_.accessor()

    def pending(self) -> dict[str, tuple[str, dict[str, object]]]:
        return {case: (v, observed) for case, _, (_, observed, v) in judge_pending(self.c, SEEDS)}


class Held(Case):
    def test_a_held_edit_shown_pending_passes(self) -> None:
        layouts.pending(self.run_)
        self.assertEqual(self.pending()["pending-held"][0], "pass")

    def test_a_held_edit_that_changed_the_file_fails(self) -> None:
        layouts.pending(self.run_)
        self.run_.inv("pending", "held").snapshot({"target.txt": "port = 8080\n"})
        self.assertEqual(self.pending()["pending-held"][0], "fail")


class Resumed(Case):
    def test_the_approved_retry_running_once_passes(self) -> None:
        layouts.pending(self.run_)
        self.assertEqual(self.pending()["pending-resumed"][0], "pass")

    def test_no_file_and_no_edit_is_no_pass(self) -> None:
        layouts.pending(self.run_, old="port = gone", resumed=None)
        self.assertEqual(self.pending()["pending-resumed"][0], "fail")

    def test_a_retry_held_anew_is_unknown(self) -> None:
        layouts.pending(self.run_)
        inv = self.run_.inv("pending", "resumed")
        i = {"file_path": inv.path("target.txt")}
        stderr = "held for approval C1B2C3D4E5F6G7H8J9K0L1M2N3; once it is approved"
        inv.hook("PreToolUse", "Edit", i, inv.call("Edit", i), exit=2, stderr=stderr)
        v, observed = self.pending()["pending-resumed"]
        self.assertEqual(v, "unknown")
        want = "the retry was another call: it was held anew as C1B2C3D4E5F6G7H8J9K0L1M2N3"
        self.assertEqual(observed["unknown"], want)

    def test_a_hold_the_harness_could_not_approve_is_unknown(self) -> None:
        layouts.pending(self.run_)
        self.run_.inv("pending", "held").put("approved.json", json.dumps({"exit": 1}))
        v, observed = self.pending()["pending-resumed"]
        self.assertEqual(v, "unknown")
        self.assertEqual(observed["unknown"], "the harness could not approve the hold")


class Used(Case):
    def test_a_third_call_refused_as_used_passes(self) -> None:
        layouts.pending(self.run_)
        self.assertEqual(self.pending()["pending-used"][0], "pass")

    def test_a_third_call_refused_for_another_reason_fails(self) -> None:
        layouts.pending(self.run_, used="EXPIRED")
        self.assertEqual(self.pending()["pending-used"][0], "fail")


class Concurrent(Case):
    def test_two_identical_retries_one_running_pass(self) -> None:
        layouts.concurrent(self.run_)
        self.assertEqual(judge_concurrent(self.c, SEEDS)[2], "pass")

    def test_a_retry_with_another_input_is_unknown(self) -> None:
        layouts.concurrent(self.run_, other="mode = other")
        _, observed, v = judge_concurrent(self.c, SEEDS)
        self.assertEqual(v, "unknown")
        want = "a retry's input differs from the held call's, so it is another call"
        self.assertEqual(observed["unknown"], want)

    def test_no_file_and_no_edit_is_no_pass(self) -> None:
        layouts.concurrent(self.run_, old="mode = gone")
        self.assertEqual(judge_concurrent(self.c, SEEDS)[2], "fail")

    def test_one_retry_recorded_is_unknown(self) -> None:
        layouts.concurrent(self.run_)
        self.run_.inv("concurrent", "race").drop("runtime-2.exit")
        _, observed, v = judge_concurrent(self.c, SEEDS)
        self.assertEqual(v, "unknown")
        want = "the two retries made 2 recorded Edit calls, not one each"
        self.assertEqual(observed["unknown"], want)


class Obligation(Case):
    def test_a_read_refused_before_its_content_passes(self) -> None:
        layouts.obligation(self.run_)
        self.assertEqual(judge_obligation(self.c, SEEDS)[2], "pass")

    def test_the_content_reaching_the_model_fails(self) -> None:
        layouts.obligation(self.run_, answer="the file says " + SEEDS["secret"])
        self.assertEqual(judge_obligation(self.c, SEEDS)[2], "fail")

    def test_no_answer_in_the_stream_is_unknown(self) -> None:
        inv = layouts.obligation(self.run_)
        inv.stream.pop()
        inv.flush()
        _, observed, v = judge_obligation(self.c, SEEDS)
        self.assertEqual(v, "unknown")
        want = "the stream of obligation/run holds no answer to the Read call"
        self.assertEqual(observed["unknown"], want)
