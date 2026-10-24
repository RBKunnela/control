"""The harness itself: what its comparison refuses, so that a pass through it means something."""

from __future__ import annotations

import unittest

from guardana_control.enforce import (
    Answer,
    CallAborted,
    CallRefused,
    Held,
    MalformedAnswer,
    NoAnswer,
)
from tests import cases, harness
from tests.harness import ABORT, ADMIT, COMPLETE, Got, Scripted
from tests.second_client import Connection

NOTHING = Answer("OUTCOME_BLOCK", None, None, False, None, "")


def got(path: str, body: bytes, **changed: object) -> Got:
    members: dict[str, object] = {
        "method": "POST",
        "path": path,
        "version": "HTTP/1.1",
        "tokens": ("tok",),
        "content_type": "application/json",
        "body": body,
    }
    return Got(**{**members, **changed})  # type: ignore[arg-type]


def post(socket_path: str, path: str) -> tuple[int, bytes]:
    connection = Connection(socket_path, 5.0)
    try:
        connection.request("POST", path, b"{}", {"Run-Token": "tok"})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


class Comparison(unittest.TestCase):
    def test_a_repeated_member_and_a_nan_are_refused(self) -> None:
        self.assertEqual(harness.strict_json(b'{"a":{"b":[1,"x"]}}'), {"a": {"b": [1, "x"]}})
        for text in ('{"a":1,"a":1}', '{"a":{"b":1,"b":2}}', '{"a":NaN}', '{"a":Infinity}', "{"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                harness.strict_json(text)

    def test_a_value_matches_only_its_like(self) -> None:
        want = {"handle": "h-1", "startedAt": "*", "nested": {"n": 1}}
        same = {"handle": "h-1", "startedAt": "2026-10-11T12:00:01Z", "nested": {"n": 1}}
        self.assertEqual(cases.match_json("r", want, same), [])
        for body, miss in (
            (
                {"handle": "h-2", "startedAt": "x", "nested": {"n": 1}},
                ["r.handle: 'h-2', want 'h-1'"],
            ),
            ({"handle": "h-1", "nested": {"n": 1}}, ["r.startedAt: absent, want a value"]),
            ({"startedAt": "x", "nested": {"n": 1}}, ["r.handle: absent, want 'h-1'"]),
            ({**same, "extra": 0}, ["r.extra: present, want absent"]),
            ({**same, "nested": {"n": 1, "m": 2}}, ["r.nested.m: present, want absent"]),
            ({**same, "nested": {"n": True}}, ["r.nested.n: True, want 1"]),
            ({**same, "nested": {"n": 1.0}}, ["r.nested.n: 1.0, want 1"]),
            ({**same, "nested": "n"}, ["r.nested: 'n', want {'n': 1}"]),
            ({**same, "handle": None}, ["r.handle: None, want 'h-1'"]),
        ):
            with self.subTest(body=body):
                self.assertEqual(cases.match_json("r", want, body), miss)

    def test_requests_are_held_to_their_expectation(self) -> None:
        admit = b'{"tool":"t","arguments":"eyJhIjoxfQ=="}'
        complete = (
            b'{"handle":"h-1","status":"COMPLETION_STATUS_UNKNOWN",'
            b'"startedAt":"2026-10-11T12:00:10Z","endedAt":"2026-10-11T12:00:11.500Z"}'
        )
        expect: dict[str, object] = {
            "requests": [
                {"path": ADMIT, "body": {"tool": "t", "arguments": "eyJhIjoxfQ=="}},
                {
                    "path": COMPLETE,
                    "body": {
                        "handle": "h-1",
                        "status": "COMPLETION_STATUS_UNKNOWN",
                        "startedAt": "*",
                        "endedAt": "*",
                    },
                },
            ],
            "completion_status": "COMPLETION_STATUS_UNKNOWN",
        }
        sent = [got(ADMIT, admit), got(COMPLETE, complete)]
        self.assertEqual(cases.compare_requests(sent, "tok", expect), [])
        late = complete.replace(b"12:00:10Z", b"12:00:09Z")
        local = complete.replace(b"12:00:11.500Z", b"14:00:11.500+02:00")
        for what, requests, miss in (
            ("one request missing", sent[:1], "1 requests, want 2"),
            (
                "one request more",
                [*sent, sent[1]],
                "request 3 to /enforce/v1alpha1/complete not expected",
            ),
            (
                "the other operation",
                [sent[0], got(ABORT, complete)],
                "request 2 to /enforce/v1alpha1/abort, want",
            ),
            (
                "another token",
                [got(ADMIT, admit, tokens=("other",)), sent[1]],
                "request 1 presented the run token",
            ),
            (
                "no token",
                [got(ADMIT, admit, tokens=()), sent[1]],
                "request 1 presented the run token",
            ),
            (
                "the token twice",
                [got(ADMIT, admit, tokens=("tok", "tok")), sent[1]],
                "request 1 presented",
            ),
            (
                "another content type",
                [got(ADMIT, admit, content_type="text/plain"), sent[1]],
                "content type",
            ),
            (
                "another method",
                [got(ADMIT, admit, method="PUT"), sent[1]],
                "request 1 is PUT over HTTP/1.1",
            ),
            ("another protocol", [got(ADMIT, admit, version="HTTP/1.0"), sent[1]], "over HTTP/1.0"),
            (
                "a repeated member",
                [got(ADMIT, admit[:-1] + b',"tool":"t"}'), sent[1]],
                "'tool' is repeated",
            ),
            (
                "a member too many",
                [got(ADMIT, admit[:-1] + b',"requestKey":"k"}'), sent[1]],
                "requestKey: present",
            ),
            (
                "a start the clock did not read",
                [sent[0], got(COMPLETE, late)],
                "want the clock's 2026-10-11T12:00:10Z",
            ),
            (
                "an end with an offset",
                [sent[0], got(COMPLETE, local)],
                "is no RFC 3339 time ending in Z",
            ),
            (
                "another status",
                [sent[0], got(COMPLETE, complete.replace(b"UNKNOWN", b"SUCCESS"))],
                "completion status",
            ),
        ):
            with self.subTest(what=what):
                misses = cases.compare_requests(requests, "tok", expect)
                self.assertTrue([m for m in misses if miss in m], misses)

    def test_an_outcome_is_told_in_the_shared_files_words(self) -> None:
        own = ValueError("the tool's own")
        refused = CallRefused(NOTHING, status=409, code="ERROR_CODE_HANDLE_SPENT", message="spent")
        aborted = CallAborted("aborted", NOTHING, cause="ABORT_CAUSE_OBLIGATION")
        aborted.__cause__ = refused
        for error, tool_error, kind, code, ending in (
            (None, None, "none", "", "ENDING_RECORDED"),
            (own, own, "tool_error", "", "ENDING_RECORDED"),
            (own, None, f"another exception: {own!r}", "", ""),
            (refused, None, "refused", "ERROR_CODE_HANDLE_SPENT", ""),
            (aborted, None, "aborted", "ERROR_CODE_HANDLE_SPENT", ""),
            (MalformedAnswer("m", NOTHING), None, "malformed_answer", "", ""),
            (NoAnswer("n", NOTHING), None, "transport", "", ""),
        ):
            with self.subTest(kind=kind):
                answer = Answer("OUTCOME_EXECUTE", None, None, True, None, "ENDING_RECORDED")
                told = cases.describe(None if error else answer, error, tool_error)
                self.assertEqual((told.kind, told.code, told.ending), (kind, code, ending))
        undeclared = CallRefused(NOTHING, status=500, code="42", message="")
        self.assertEqual(cases.describe(None, undeclared, None).code, "")
        numbered = Answer("OUTCOME_EXECUTE", None, Held("ap-1", "", None, None), True, None, "9")
        told = cases.describe(numbered, None, None)
        self.assertEqual((told.ending, told.approval_id, told.retry_after), ("", "ap-1", ""))


class Receivers(unittest.TestCase):
    def test_a_request_the_script_does_not_hold_is_refused(self) -> None:
        receiver = harness.Receiver(
            [Scripted(ADMIT, 200, b"{}"), Scripted(COMPLETE, 201, b'{"a":1}')]
        )
        self.addCleanup(receiver.close)
        self.assertEqual(post(receiver.socket, ADMIT), (200, b"{}"))
        self.assertEqual(post(receiver.socket, ABORT), (400, harness.UNSCRIPTED))
        self.assertEqual(post(receiver.socket, COMPLETE), (400, harness.UNSCRIPTED))
        self.assertEqual(
            [request.path for request in receiver.requests()], [ADMIT, ABORT, COMPLETE]
        )
        self.assertEqual(receiver.requests()[0].tokens, ("tok",))

    def test_a_receiver_that_goes_on_records_what_comes_after_its_script(self) -> None:
        receiver = harness.Receiver([Scripted(ADMIT, 302, b"{}", location=ADMIT)], goes_on=True)
        self.addCleanup(receiver.close)
        self.assertEqual(post(receiver.socket, ADMIT), (302, b"{}"))
        self.assertEqual(post(receiver.socket, "/elsewhere"), (200, harness.RECORDED))

    def test_a_script_that_acts_on_a_caller_needs_one(self) -> None:
        with self.assertRaisesRegex(ValueError, "nothing can do it"):
            harness.Receiver([Scripted(ADMIT, 200, b"{}", then="cancel_caller")])
