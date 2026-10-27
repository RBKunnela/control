import unittest

from tests import layouts
from tests.observations import Run


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.run_ = Run()
        self.addCleanup(self.run_.close)

    def verdict(self, group: str) -> str:
        return str(self.run_.result(group)["verdict"])


class Effects(unittest.TestCase):
    """Each failing hook's Write as its case wants it passes; the other way, it fails."""

    def test_each_case_passes_as_laid_out_and_fails_the_other_way(self) -> None:
        for group in ("plane-down", "timeout-block", "crash-block"):
            self.check(group, False)
        for group in ("timeout-open", "crash-open", "garbage"):
            self.check(group, True)

    def check(self, group: str, runs: bool) -> None:
        for laid_out, want in ((runs, "pass"), (not runs, "fail")):
            with self.subTest(group=group, runs=laid_out):
                run = Run()
                self.addCleanup(run.close)
                layouts.effect(run, group, runs=laid_out)
                self.assertEqual(run.result(group)["verdict"], want)


class Effect(Case):
    def test_plane_down_passes(self) -> None:
        layouts.effect(self.run_, "plane-down")
        self.assertEqual(self.verdict("plane-down"), "pass")

    def test_plane_down_with_a_bridge_exit_other_than_two_fails(self) -> None:
        inv = layouts.effect(self.run_, "plane-down")
        inv.hook("PreToolUse", "Write", {"file_path": inv.path("down.txt")}, "x", exit=1)
        self.assertEqual(self.verdict("plane-down"), "fail")

    def test_a_block_in_other_words_fails(self) -> None:
        inv = layouts.effect(self.run_, "timeout-block")
        inv.stream[-1]["message"]["content"][0]["content"] = "blocked"
        inv.flush()
        self.assertEqual(self.verdict("timeout-block"), "fail")

    def test_another_hook_answering_is_unknown(self) -> None:
        layouts.effect(self.run_, "crash-block", act="pass")
        result = self.run_.result("crash-block")
        self.assertEqual(result["verdict"], "unknown")
        want = "the Write's PreToolUse hooks were ['pass'], not crash alone"
        self.assertEqual(result["observed"]["unknown"], want)

    def test_garbage_not_recorded_as_printed_is_unknown(self) -> None:
        inv = layouts.effect(self.run_, "garbage", act="garbage")
        inv.hook("PreToolUse", "Write", {"file_path": inv.path("garbage.txt")}, "x", act="garbage")
        result = self.run_.result("garbage")
        self.assertEqual(result["verdict"], "unknown")
        want = "the hook's exit and output were not recorded as written and 0"
        self.assertEqual(result["observed"]["unknown"], want)

    def test_a_runtime_stopped_by_the_harness_fails(self) -> None:
        layouts.effect(self.run_, "crash-open").put(
            "runtime-1.err", "qualify: stopped after 300 s\n"
        )
        self.assertEqual(self.verdict("crash-open"), "fail")

    def test_a_write_outside_the_project_is_unknown(self) -> None:
        inv = layouts.effect(self.run_, "timeout-open")
        inv.stream[0]["message"]["content"][0]["input"]["file_path"] = "/elsewhere/timeout-open.txt"
        inv.flush()
        result = self.run_.result("timeout-open")
        self.assertEqual(result["verdict"], "unknown")
        want = "the model wrote timeout-open.txt outside the project"
        self.assertEqual(result["observed"]["unknown"], want)
