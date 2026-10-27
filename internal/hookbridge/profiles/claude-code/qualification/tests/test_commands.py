import argparse
import contextlib
import glob
import io
import json
import os
import shutil
import tempfile
import unittest

import harness
from harness_judge import judged
from harness_scrub import UNREADABLE, Scrubber, copy_scrubbed, judged_part
from tests import layouts
from tests.observations import Run

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Scratch(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="qualification-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def path(self, *parts: str) -> str:
        return os.path.join(self.dir, *parts)


class Snapshot(Scratch):
    def snapshot(self, project: str) -> None:
        harness.snapshot(argparse.Namespace(project=project, out=self.path("files.json")))

    def test_every_file_and_link_is_kept(self) -> None:
        os.makedirs(self.path("p", "sub"))
        os.makedirs(self.path("p", ".claude"))
        os.makedirs(self.path("elsewhere"))
        for name in ("p/note.txt", "p/sub/deep.txt", "p/.claude/settings.json"):
            with open(self.path(name), "w", encoding="utf-8") as f:
                f.write("text of " + name)
        os.symlink(self.path("elsewhere"), self.path("p", "marker"))
        self.snapshot(self.path("p"))
        with open(self.path("files.json"), encoding="utf-8") as f:
            files = json.load(f)
        want = {
            "note.txt": "text of p/note.txt",
            "sub/deep.txt": "text of p/sub/deep.txt",
            "marker": "symbolic link to " + self.path("elsewhere"),
        }
        self.assertEqual(files, want)

    def test_a_missing_project_writes_nothing(self) -> None:
        with self.assertRaises(SystemExit):
            self.snapshot(self.path("absent"))
        self.assertEqual(os.listdir(self.dir), [])

    def test_a_walk_that_fails_writes_nothing(self) -> None:
        os.makedirs(self.path("p", "shut"))
        os.chmod(self.path("p", "shut"), 0)
        self.addCleanup(os.chmod, self.path("p", "shut"), 0o700)
        with self.assertRaises(PermissionError):
            self.snapshot(self.path("p"))
        self.assertEqual(os.listdir(self.dir), ["p"])


class Report(Scratch):
    def report(self, verdicts: list[str], text: str | None = None) -> int:
        lines = [
            {"id": f"c{i}", "invocations": 1, "observed": {}, "verdict": v}
            for i, v in enumerate(verdicts)
        ]
        with open(self.path("results.jsonl"), "w", encoding="utf-8") as f:
            f.write(text if text is not None else "".join(json.dumps(r) + "\n" for r in lines))
        with open(self.path("meta.json"), "w", encoding="utf-8") as f:
            f.write('{"runtime": "stub"}')
        args = argparse.Namespace(
            results=self.path("results.jsonl"),
            meta=self.path("meta.json"),
            out=self.path("results.json"),
            judged_at=None,
        )
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return harness.report(args)

    def test_the_exit_status_follows_the_verdicts(self) -> None:
        self.assertEqual(self.report(["pass", "pass"]), 0)
        self.assertEqual(self.report(["pass", "fail", "unknown"]), 1)
        self.assertEqual(self.report(["pass", "unknown"]), 3)
        self.assertEqual(self.report([]), 2)
        self.assertEqual(self.report(["pass", "passed"]), 2)
        self.assertEqual(self.report([], text='{"id": "c0"\n'), 2)

    def test_the_results_file_holds_the_meta_and_the_cases(self) -> None:
        self.report(["pass"])
        with open(self.path("results.json"), encoding="utf-8") as f:
            doc = json.load(f)
        self.assertEqual(doc["runtime"], "stub")
        self.assertEqual([c["verdict"] for c in doc["cases"]], ["pass"])


ALL_PASS = {
    case: "pass"
    for case in (
        "allow",
        "block",
        "pending-held",
        "pending-resumed",
        "pending-used",
        "concurrent",
        "obligation",
        "plane-down",
        "timeout-block",
        "timeout-open",
        "crash-block",
        "crash-open",
        "garbage",
        "disabled",
        "rewrite",
        "rewrite-denied",
        "mcp-matcher",
        "subagent",
        "control-allow-all",
        "control-report-proposed",
    )
}


class StreamPart(unittest.TestCase):
    def test_the_models_text_and_reasoning_are_not_kept(self) -> None:
        """A kept stream line holds the tool calls, their results and the
        status alone: never the model's text or its reasoning."""
        assistant = {
            "type": "assistant",
            "session_id": "s-1",
            "parent_tool_use_id": None,
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": "a private chain"},
                    {"type": "text", "text": "I will write the file"},
                    {
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": "Write",
                        "input": {"file_path": "a"},
                    },
                ],
            },
        }
        self.assertEqual(
            judged_part(assistant),
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": "Write",
                            "input": {"file_path": "a"},
                        }
                    ],
                },
                "parent_tool_use_id": None,
            },
        )
        user = {
            "type": "user",
            "message": {
                "role": "user",
                "content": [
                    {"type": "text", "text": "a prompt"},
                    {"type": "tool_result", "tool_use_id": "toolu_1"},
                ],
            },
        }
        self.assertEqual(
            judged_part(user),
            {
                "type": "user",
                "message": {
                    "role": "user",
                    "content": [{"type": "tool_result", "tool_use_id": "toolu_1"}],
                },
            },
        )
        result = {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "result": "done, the file is written",
        }
        self.assertEqual(
            judged_part(result), {"type": "result", "subtype": "success", "is_error": False}
        )


class StreamLines(unittest.TestCase):
    def test_an_unreadable_line_is_replaced_and_reasoning_dropped(self) -> None:
        """A stream line that does not parse is replaced by a marker that
        does not parse either, and a parsed line keeps no reasoning."""
        thinking = {"type": "thinking", "thinking": "a private chain"}
        line = {"type": "assistant", "message": {"role": "assistant", "content": [thinking]}}
        out = Scrubber("/nowhere", "/nowhere/events").stream(
            json.dumps(line) + "\n" + '{"type": "assi\n'
        )
        self.assertEqual(out.splitlines(keepends=True)[1], UNREADABLE)
        self.assertNotIn("a private chain", out)
        self.assertEqual(len(out.splitlines()), 2)


class Scrubbed(Scratch):
    def setUp(self) -> None:
        super().setUp()
        self.run_ = Run()
        self.addCleanup(self.run_.close)
        layouts.full(self.run_)
        self.results = self.path("results.jsonl")
        with open(self.results, "w", encoding="utf-8") as f:
            for r in judged(self.run_.cases, self.run_.events):
                f.write(json.dumps(r) + "\n")
        self.copy = self.path("results.observed")
        copy_scrubbed(self.run_.cases, self.run_.events, self.run_.root, self.copy)

    def rejudge(self, copy: str, results: str) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return harness.rejudge(argparse.Namespace(copy=copy, results=results))

    def test_every_kept_copy_is_judged_as_its_results_say(self) -> None:
        """Each scrubbed copy kept beside a results file, and the copy of a run
        that passes every case, made here."""
        self.assertEqual(self.run_.verdicts(), ALL_PASS)
        kept = sorted(glob.glob(os.path.join(HERE, "*.observed")))
        for copy in [self.copy, *kept]:
            results = (
                self.results if copy == self.copy else copy.removesuffix(".observed") + ".json"
            )
            with self.subTest(copy=os.path.basename(copy)):
                self.assertEqual(self.rejudge(copy, results), 0)

    def test_the_copy_names_neither_the_run_directory_nor_its_ids(self) -> None:
        for base, _, names in os.walk(self.copy):
            for name in names:
                with open(os.path.join(base, name), encoding="utf-8") as f:
                    text = f.read()
                self.assertNotIn(self.run_.root, text)
                self.assertNotIn(layouts.HELD, text)
                self.assertNotIn("toolu_0001", text)

    def test_a_copy_judged_otherwise_is_refused(self) -> None:
        os.remove(os.path.join(self.copy, "cases", "block", "run", "files.json"))
        self.assertEqual(self.rejudge(self.copy, self.results), 1)

    def test_results_that_cannot_be_read_are_refused(self) -> None:
        with open(self.results, "w", encoding="utf-8") as f:
            f.write("")
        self.assertEqual(self.rejudge(self.copy, self.results), 2)

    def test_a_copy_is_never_written_over(self) -> None:
        with self.assertRaises(FileExistsError):
            copy_scrubbed(self.run_.cases, self.run_.events, self.run_.root, self.copy)
