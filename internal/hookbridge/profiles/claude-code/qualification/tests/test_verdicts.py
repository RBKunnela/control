import os
import unittest

from harness_verdicts import judge_allow, judge_block, missing
from tests import layouts
from tests.observations import Run


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.run_ = Run()
        self.addCleanup(self.run_.close)
        self.c = self.run_.accessor()


class Allow(Case):
    def test_the_proposed_content_written_passes(self) -> None:
        layouts.allow(self.run_)
        self.assertEqual(judge_allow(self.c)[2], "pass")

    def test_other_content_written_fails(self) -> None:
        layouts.allow(self.run_, written="hellO")
        self.assertEqual(judge_allow(self.c)[2], "fail")

    def test_no_file_and_no_content_is_no_pass(self) -> None:
        layouts.allow(self.run_, written=None, content=None)
        self.assertEqual(judge_allow(self.c)[2], "fail")

    def test_an_admit_that_printed_fails(self) -> None:
        layouts.allow(self.run_, stdout='{"hookSpecificOutput": {}}')
        self.assertEqual(judge_allow(self.c)[2], "fail")

    def test_no_write_in_the_stream_is_unknown(self) -> None:
        inv = layouts.allow(self.run_)
        inv.stream.clear()
        inv.flush()
        _, observed, v = judge_allow(self.c)
        self.assertEqual(v, "unknown")
        self.assertEqual(observed["unknown"], "the model made no Write call in allow/run")


class Block(Case):
    def test_a_blocked_call_with_no_marker_passes(self) -> None:
        layouts.block(self.run_)
        self.assertEqual(judge_block(self.c("block", "run"))[2], "pass")

    def test_a_marker_fails(self) -> None:
        layouts.block(self.run_, marker=True)
        self.assertEqual(judge_block(self.c("block", "run"))[2], "fail")

    def test_another_command_is_unknown(self) -> None:
        layouts.block(self.run_, command="touch other")
        _, observed, v = judge_block(self.c("block", "run"))
        self.assertEqual(v, "unknown")
        want = "the model asked for another command than touch marker in block/run"
        self.assertEqual(observed["unknown"], want)


class Missing(Case):
    def why(self) -> str | None:
        return missing(self.c("allow", "run"))

    def test_a_complete_invocation_is_judged(self) -> None:
        layouts.allow(self.run_)
        self.assertIsNone(self.why())

    def test_an_unselected_invocation(self) -> None:
        layouts.allow(self.run_).put("unselected", "")
        self.assertEqual(self.why(), "not run: QUALIFY_ONLY left out allow/run")

    def test_a_skipped_invocation(self) -> None:
        layouts.allow(self.run_).put("skipped", "")
        self.assertEqual(self.why(), "skipped: the invocation cap was reached before allow/run")

    def test_a_runtime_never_started(self) -> None:
        layouts.allow(self.run_).drop("runtime-1.exit")
        self.assertEqual(self.why(), "the runtime was not run for allow/run")

    def test_no_snapshot(self) -> None:
        layouts.allow(self.run_).drop("files.json")
        self.assertEqual(self.why(), "the project's snapshot could not be read for allow/run")

    def test_no_trail(self) -> None:
        layouts.allow(self.run_).drop("trail.jsonl")
        self.assertEqual(self.why(), "the trail could not be read for allow/run")

    def test_a_stream_line_that_does_not_parse(self) -> None:
        layouts.allow(self.run_).put("stream-1.jsonl", "{not json\n")
        self.assertEqual(self.why(), "line 1 of stream-1.jsonl does not parse in allow/run")

    def test_a_runtime_that_left_no_stream(self) -> None:
        layouts.allow(self.run_).drop("stream-1.jsonl")
        self.assertEqual(self.why(), "runtime-1 left no stream in allow/run")

    def test_no_events_directory(self) -> None:
        inv = layouts.allow(self.run_)
        for name in os.listdir(inv.events):
            os.remove(os.path.join(inv.events, name))
        os.rmdir(inv.events)
        want = "the hook events of run could not be listed: FileNotFoundError in allow/run"
        self.assertEqual(self.why(), want)

    def test_an_event_that_does_not_parse(self) -> None:
        inv = layouts.allow(self.run_)
        with open(os.path.join(inv.events, "001.json"), "w", encoding="utf-8") as f:
            f.write("{")
        self.assertEqual(self.why(), "hook event 001.json could not be read in allow/run")
