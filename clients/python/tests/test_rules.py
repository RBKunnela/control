"""The rules of a call that no case file holds."""

from __future__ import annotations

import asyncio
import functools
import gc
import inspect
import math
import threading
import traceback
import unittest
import warnings
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import UTC, datetime, timedelta, timezone, tzinfo

from guardana_control import enforce
from guardana_control.enforce import (
    Answer,
    BadResult,
    CallAborted,
    CallBlocked,
    CallerGone,
    CallPending,
    CallRefused,
    Client,
    EnforceError,
    Held,
    MalformedAnswer,
    NoAnswer,
    NotRecorded,
    NotSent,
    Result,
    Status,
    ToolRaised,
)
from tests import harness
from tests.harness import ABORT, ADMIT, COMPLETE, RECORDED, Scripted

ARGUMENTS = b'{"a":1}'
EXECUTE = (
    b'{"outcome":"OUTCOME_EXECUTE","decision":{"schemaVersion":"1.0","decisionId":"d-1","verdict":1},'
    b'"execution":{"handle":"h-1","authorizedArguments":"eyJhIjoxfQ=="}}'
)
OBLIGED = (
    b'{"outcome":"OUTCOME_EXECUTE","execution":{"handle":"h-1",'
    b'"authorizedArguments":"eyJhIjoxfQ==","obligations":[{"type":"x"}]}}'
)
ABORT_NOT_SENT = {"handle": "h-1", "cause": "ABORT_CAUSE_NOT_SENT"}
INNER_EXECUTE = (
    b'{"outcome":"OUTCOME_EXECUTE","execution":{"handle":"h-2",'
    b'"authorizedArguments":"eyJhIjoxfQ=="}}'
)
INNER_BLOCK = (
    b'{"outcome":"OUTCOME_BLOCK","decision":{"schemaVersion":"1.0","verdict":"VERDICT_DENY"}}'
)
INNER_PENDING = b'{"outcome":"OUTCOME_PENDING","pending":{"approvalId":"ap-1"}}'
PLUS_TWO = timezone(timedelta(hours=2))


def admit(body: bytes, status: int = 200) -> Scripted:
    return Scripted(ADMIT, status, body)


def complete(body: bytes = RECORDED, status: int = 200) -> Scripted:
    return Scripted(COMPLETE, status, body)


def abort(body: bytes = RECORDED, status: int = 200) -> Scripted:
    return Scripted(ABORT, status, body)


def succeed(_authorized: bytes) -> Result:
    return Result(Status.SUCCESS)


def returning(value: object) -> Callable[[bytes], Result | None]:
    """A tool that returns value, whatever its type."""

    def tool(_authorized: bytes) -> Result | None:
        return value  # type: ignore[return-value]

    return tool


def misreporting(**members: object) -> Result:
    """A successful result with members of whatever type the test gives them."""
    return Result(Status.SUCCESS, **members)  # type: ignore[arg-type]


def misstating(status: object) -> Result:
    """A result whose status is of whatever type the test gives it."""
    return Result(status)  # type: ignore[arg-type]


def result_of(answer: Answer) -> Result:
    if answer.result is None:
        raise AssertionError("the answer carries no result")
    return answer.result


class Zone(tzinfo):
    """A zone that says UTC so many times, and from then on what it was given."""

    def __init__(self, then: object, times: int = 0) -> None:
        self.then = then
        self.left = times

    def utcoffset(self, _at: datetime | None) -> timedelta:
        if self.left:
            self.left -= 1
            return timedelta(0)
        if isinstance(self.then, BaseException):
            raise self.then
        return self.then  # type: ignore[return-value]

    def dst(self, _at: datetime | None) -> timedelta:
        return timedelta(0)

    def tzname(self, _at: datetime | None) -> str:
        return "a zone"


def scripted(*readings: datetime | BaseException) -> Callable[[], datetime]:
    """A clock that reads each of readings in turn; an exception among them is raised."""
    left = iter(readings)

    def clock() -> datetime:
        reading = next(left)
        if isinstance(reading, BaseException):
            raise reading
        return reading

    return clock


class Receipt(Result):
    """A result with a constructor of its own, so no copy of it can be made by field."""

    def __init__(self, number: str) -> None:
        super().__init__(Status.SUCCESS, number)


class Unsendable(Result):
    """A result whose every copy says, as only a tool may, that the bytes never left."""

    def __init__(self, **members: object) -> None:
        if members:
            raise NotSent("copying the result")
        super().__init__(Status.SUCCESS)


class Rules(unittest.TestCase):
    """A scripted receiver, one client, and the requests it was sent."""

    def serve(self, *script: Scripted, clock: Callable[[], datetime] | None = None) -> Client:
        self.receiver = harness.Receiver(list(script))
        self.addCleanup(self.receiver.close)
        self.entered = False
        return Client(self.receiver.socket, "tok", 5.0, clock=clock or self.clock)

    def clock(self) -> datetime:
        return harness.AFTER if self.entered else harness.BEFORE

    def untouched(self, _authorized: bytes) -> Result:
        self.entered = True
        self.fail("the tool was run")

    def entering(self, does: Callable[[bytes], Result | None]) -> Callable[[bytes], Result | None]:
        def tool(authorized: bytes) -> Result | None:
            self.entered = True
            return does(authorized)

        return tool

    def sent(self) -> list[tuple[str, object]]:
        """Each request's path and its body as a JSON value."""
        requests = self.receiver.requests()
        for number, request in enumerate(requests, start=1):
            self.assertEqual(harness.request_misses(number, request, "tok"), [])
        return [(request.path, harness.strict_json(request.body)) for request in requests]

    def completed(self, status: str, **times: str) -> tuple[str, object]:
        """The complete of a run that reported status, at the clock's times but for those given."""
        return (
            COMPLETE,
            {
                "handle": "h-1",
                "sentArguments": "eyJhIjoxfQ==",
                "status": status,
                "startedAt": harness.BEFORE_TEXT,
                "endedAt": harness.AFTER_TEXT,
            }
            | times,
        )

    admitted = (ADMIT, {"tool": "t", "arguments": "eyJhIjoxfQ=="})
    # What an exception carries when the tool ran, nothing of it could be told, and that landed.
    ran_unreported = Answer(
        outcome="OUTCOME_EXECUTE",
        decision={"schemaVersion": "1.0", "decisionId": "d-1", "verdict": 1},
        held=None,
        ran=True,
        result=None,
        ending="ENDING_RECORDED",
    )


class Construction(unittest.TestCase):
    """A client needs a socket, a token and a finite positive timeout."""

    def test_an_empty_or_missing_socket_or_token_is_refused(self) -> None:
        for socket, token in (
            ("", "t"),
            ("s", ""),
            (None, "t"),
            ("s", None),
            (b"s", "t"),
            ("s", b"t"),
        ):
            with self.subTest(socket=socket, token=token), self.assertRaises(ValueError):
                Client(socket, token, 1.0)  # type: ignore[arg-type]

    def test_a_timeout_that_is_no_finite_positive_number_is_refused(self) -> None:
        for timeout in (
            None,
            True,
            False,
            0,
            0.0,
            -1,
            -0.5,
            math.nan,
            math.inf,
            -math.inf,
            "1",
            10**400,
        ):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(ValueError, "timeout"):
                Client("s", "t", timeout)  # type: ignore[arg-type]

    def test_the_smallest_timeouts_are_taken(self) -> None:
        for timeout in (1, 0.5, 1e-9, 5e-324):
            with self.subTest(timeout=timeout):
                self.assertIsInstance(Client("s", "t", timeout), Client)

    def test_a_token_a_header_cannot_carry_is_refused(self) -> None:
        for token in (
            "a\nb",
            "a\rb",
            "a\r\nInjected: 1",
            "a\x00b",
            "za\u017c\u00f3\u0142\u0107",
            "a\x7fb",
            "\ttab",
        ):
            with self.subTest(token=token), self.assertRaisesRegex(ValueError, "run token"):
                Client("s", token, 1.0)
        self.assertIsInstance(Client("s", "run-1.A b~!", 1.0), Client)

    def test_the_module_exports_the_interface_and_nothing_else(self) -> None:
        names = [
            "Answer",
            "BadResult",
            "CONTRACT",
            "CallAborted",
            "CallBlocked",
            "CallPending",
            "CallRefused",
            "CallerGone",
            "Client",
            "EnforceError",
            "Held",
            "MalformedAnswer",
            "NoAnswer",
            "NotRecorded",
            "NotSent",
            "Result",
            "Status",
            "ToolRaised",
        ]
        self.assertEqual(sorted(enforce.__all__), names)
        self.assertEqual(sorted(n for n in vars(enforce) if not n.startswith("_")), names)
        self.assertEqual(enforce.CONTRACT, "v1alpha1")
        self.assertEqual(
            {n: v for n, v in vars(Status).items() if not n.startswith("_")},
            {
                "SUCCESS": "COMPLETION_STATUS_SUCCESS",
                "FAILURE": "COMPLETION_STATUS_FAILURE",
                "TIMEOUT": "COMPLETION_STATUS_TIMEOUT",
                "CANCELLED": "COMPLETION_STATUS_CANCELLED",
                "UNKNOWN": "COMPLETION_STATUS_UNKNOWN",
            },
        )
        raised: tuple[type[Exception], ...] = (
            CallerGone,
            CallBlocked,
            CallPending,
            CallRefused,
            MalformedAnswer,
            CallAborted,
            NotRecorded,
            NoAnswer,
            BadResult,
            ToolRaised,
        )
        for error in raised:
            self.assertTrue(issubclass(error, EnforceError), error)
            self.assertEqual(issubclass(error, TypeError), error is BadResult, error)
        self.assertFalse(issubclass(NotSent, EnforceError))


class Returning(Rules):
    """What a call returns, and what each exception carries."""

    def test_a_recorded_run_returns_what_the_call_learned(self) -> None:
        client = self.serve(admit(EXECUTE), complete())
        receipt = object()
        answer = client.call(
            "t", ARGUMENTS, self.entering(returning(Result(Status.FAILURE, receipt)))
        )
        self.assertEqual(
            answer,
            Answer(
                outcome="OUTCOME_EXECUTE",
                decision={"schemaVersion": "1.0", "decisionId": "d-1", "verdict": 1},
                held=None,
                ran=True,
                result=Result(Status.FAILURE, receipt, harness.BEFORE, harness.AFTER),
                ending="ENDING_RECORDED",
            ),
        )
        self.assertIs(result_of(answer).value, receipt)
        self.assertEqual(self.sent(), [self.admitted, self.completed("COMPLETION_STATUS_FAILURE")])

    def test_the_decision_cannot_be_changed_by_the_caller(self) -> None:
        client = self.serve(
            admit(EXECUTE.replace(b'"verdict":1', b'"verdict":1,"reasonCodes":["A"]')), complete()
        )
        answer = client.call("t", ARGUMENTS, succeed)
        decision = answer.decision or {}
        self.assertEqual(decision["reasonCodes"], ("A",))
        with self.assertRaises(TypeError):
            decision["verdict"] = 2  # type: ignore[index]

    def test_only_recorded_says_the_record_landed(self) -> None:
        for written, named in (
            (b'{"ending":"ENDING_UNRECORDED"}', "ENDING_UNRECORDED"),
            (b'{"ending":"ENDING_ABANDONED"}', "ENDING_ABANDONED"),
            (b'{"ending":"ENDING_RECORD_FAILED"}', "ENDING_RECORD_FAILED"),
            (b'{"ending":3}', "ENDING_UNRECORDED"),
            (b'{"ending":9}', "9"),
            (b'{"ending":"ENDING_UNSPECIFIED"}', ""),
            (b'{"ending":0}', ""),
            (b"{}", ""),
        ):
            with self.subTest(written=written):
                client = self.serve(admit(EXECUTE), complete(written))
                with self.assertRaises(NotRecorded) as raised:
                    client.call("t", ARGUMENTS, self.entering(succeed))
                answer = raised.exception.answer
                self.assertEqual(
                    (answer.ran, answer.ending, answer.outcome), (True, named, "OUTCOME_EXECUTE")
                )
                self.assertEqual(
                    answer.result, Result(Status.SUCCESS, None, harness.BEFORE, harness.AFTER)
                )
                self.assertEqual(
                    answer.decision, {"schemaVersion": "1.0", "decisionId": "d-1", "verdict": 1}
                )
                self.assertEqual(len(self.sent()), 2)

    def test_the_integer_of_recorded_is_recorded(self) -> None:
        client = self.serve(admit(EXECUTE), complete(b'{"ending":1}'))
        self.assertEqual(client.call("t", ARGUMENTS, succeed).ending, "ENDING_RECORDED")

    def test_a_blocked_call_carries_the_decision_and_did_not_run(self) -> None:
        for written in (
            b'{"outcome":"OUTCOME_BLOCK","decision":{"schemaVersion":"1.0","verdict":"VERDICT_DENY","reasonCodes":["RULE_DENY"]}}',
            b'{"decision":{"schemaVersion":"1.0","verdict":"VERDICT_DENY","reasonCodes":["RULE_DENY"]}}',
            b'{"outcome":7,"decision":{"schemaVersion":"1.0","verdict":"VERDICT_DENY","reasonCodes":["RULE_DENY"]},'
            b'"execution":{"handle":"h-1","authorizedArguments":"eyJhIjoxfQ=="}}',
        ):
            with self.subTest(written=written):
                client = self.serve(admit(written), complete())
                with self.assertRaises(CallBlocked) as raised:
                    client.call("t", ARGUMENTS, self.untouched)
                self.assertEqual(
                    raised.exception.answer,
                    Answer(
                        outcome="OUTCOME_BLOCK",
                        decision={
                            "schemaVersion": "1.0",
                            "verdict": "VERDICT_DENY",
                            "reasonCodes": ("RULE_DENY",),
                        },
                        held=None,
                        ran=False,
                        result=None,
                        ending="",
                    ),
                )
                self.assertEqual(self.sent(), [self.admitted])

    def test_a_pending_call_says_when_to_ask_again(self) -> None:
        client = self.serve(
            admit(
                b'{"outcome":"OUTCOME_PENDING","decision":{"schemaVersion":"1.0","verdict":3},"pending":{"approvalId":"ap-1",'
                b'"actionDigest":"sha256:9f2c","expiresAt":"2026-10-11T13:00:00.250Z","retryAfter":"1.500s"}}'
            )
        )
        with self.assertRaises(CallPending) as raised:
            client.call("t", ARGUMENTS, self.untouched)
        answer = raised.exception.answer
        self.assertEqual(
            answer.held,
            Held(
                approval_id="ap-1",
                action_digest="sha256:9f2c",
                expires_at=datetime(2026, 10, 11, 13, 0, 0, 250000, tzinfo=UTC),
                retry_after=timedelta(seconds=1, milliseconds=500),
            ),
        )
        self.assertEqual(
            (answer.outcome, answer.ran, answer.decision),
            ("OUTCOME_PENDING", False, {"schemaVersion": "1.0", "verdict": 3}),
        )
        self.assertEqual(self.sent(), [self.admitted])

    def test_a_held_call_keeps_its_times_to_the_microsecond(self) -> None:
        for written, kept in (
            ("0.000000001s", timedelta(0)),
            ("1.999999999s", timedelta(seconds=1, microseconds=999999)),
            ("-1.999999999s", timedelta(seconds=-1, microseconds=-999999)),
        ):
            with self.subTest(written=written):
                body = (
                    b'{"outcome":"OUTCOME_PENDING","pending":{"expiresAt":'
                    b'"2026-10-11T13:00:00.999999999Z","retryAfter":"' + written.encode() + b'"}}'
                )
                with self.assertRaises(CallPending) as raised:
                    self.serve(admit(body)).call("t", ARGUMENTS, self.untouched)
                expires = datetime(2026, 10, 11, 13, 0, 0, 999999, tzinfo=UTC)
                self.assertEqual(raised.exception.answer.held, Held("", "", expires, kept))

    def test_a_pending_answer_that_names_nothing_is_still_held(self) -> None:
        client = self.serve(admit(b'{"outcome":3}'))
        with self.assertRaises(CallPending) as raised:
            client.call("t", ARGUMENTS, self.untouched)
        self.assertEqual(raised.exception.answer.held, Held("", "", None, None))

    def test_a_refusal_carries_its_status_code_message_and_ending(self) -> None:
        client = self.serve(admit(b'{"code":"ERROR_CODE_UNAVAILABLE","message":"down"}', 503))
        with self.assertRaises(CallRefused) as raised:
            client.call("t", ARGUMENTS, self.untouched)
        refused = raised.exception
        self.assertEqual(
            (refused.status, refused.code, refused.message), (503, "ERROR_CODE_UNAVAILABLE", "down")
        )
        self.assertEqual(refused.answer, Answer("OUTCOME_BLOCK", None, None, False, None, ""))
        self.assertEqual(self.sent(), [self.admitted])

        client = self.serve(
            admit(EXECUTE),
            complete(b'{"code":5,"message":"spent","ending":"ENDING_ABANDONED"}', 409),
            complete(),
        )
        with self.assertRaises(CallRefused) as raised:
            client.call("t", ARGUMENTS, self.entering(succeed))
        refused = raised.exception
        self.assertEqual(
            (refused.status, refused.code, refused.message),
            (409, "ERROR_CODE_HANDLE_SPENT", "spent"),
        )
        self.assertEqual((refused.answer.ran, refused.answer.ending), (True, "ENDING_ABANDONED"))
        self.assertEqual(
            refused.answer.result, Result(Status.SUCCESS, None, harness.BEFORE, harness.AFTER)
        )
        self.assertEqual(len(self.sent()), 2)

    def test_a_long_refusal_keeps_its_message_and_quotes_a_bounded_part(self) -> None:
        written = b'{"code":"ERROR_CODE_UNAVAILABLE","message":"' + b"m" * 100000 + b'"}'
        client = self.serve(admit(written, 503))
        with self.assertRaises(CallRefused) as raised:
            client.call("t", ARGUMENTS, self.untouched)
        refused = raised.exception
        self.assertEqual(refused.message, "m" * 100000)
        quoted = "503 ERROR_CODE_UNAVAILABLE: '" + "m" * 120 + "... (cut from 100000 characters)'"
        self.assertEqual(str(refused), "the receiver refused the request: " + quoted)
        self.assertEqual(str(refused.__cause__), quoted)
        self.assertLess(len("".join(traceback.format_exception(refused))), 10000)

    def test_a_long_malformed_answer_is_quoted_in_a_bounded_part(self) -> None:
        cut = "g" * 120 + "... (cut from 100000 characters)"
        for status, said in (
            (200, f"{cut}: no member of AdmitResponse"),
            (500, f"status 500 with no readable error body: {cut}: no member of Error"),
        ):
            with self.subTest(status=status):
                client = self.serve(admit(b'{"' + b"g" * 100000 + b'":1}', status))
                with self.assertRaises(MalformedAnswer) as raised:
                    client.call("t", ARGUMENTS, self.untouched)
                self.assertEqual(
                    str(raised.exception), "the receiver's answer is malformed: " + said
                )
                self.assertLess(len("".join(traceback.format_exception(raised.exception))), 10000)

    def test_a_refusal_with_no_code_or_an_undeclared_one(self) -> None:
        for written, code in ((b"{}", ""), (b'{"code":0}', ""), (b'{"code":42}', "42")):
            with self.subTest(written=written):
                client = self.serve(admit(written, 500))
                with self.assertRaises(CallRefused) as raised:
                    client.call("t", ARGUMENTS, self.untouched)
                self.assertEqual((raised.exception.status, raised.exception.code), (500, code))

    def test_an_answer_the_client_cannot_act_on_sends_nothing(self) -> None:
        for what, written, names in (
            (
                "no handle",
                b'{"outcome":"OUTCOME_EXECUTE","decision":{"schemaVersion":"1.0","verdict":1},"execution":{"authorizedArguments":"eyJhIjoxfQ=="}}',
                "no handle",
            ),
            (
                "an empty handle",
                b'{"outcome":1,"decision":{"schemaVersion":"1.0","verdict":1},"execution":{"handle":""}}',
                "no handle",
            ),
            (
                "no execution",
                b'{"outcome":"OUTCOME_EXECUTE","decision":{"schemaVersion":"1.0","verdict":1}}',
                "no handle",
            ),
            (
                "an error body under 200",
                b'{"code":"ERROR_CODE_UNAVAILABLE"}',
                "code: no member of AdmitResponse",
            ),
            (
                "a member it does not know",
                EXECUTE[:-1] + b',"grant":"all"}',
                "grant: no member of AdmitResponse",
            ),
            (
                "an enum name it does not know",
                EXECUTE.replace(b'"verdict":1', b'"verdict":"VERDICT_LATER"'),
                "'VERDICT_LATER' is no name of Verdict",
            ),
        ):
            with self.subTest(what=what):
                client = self.serve(admit(written), complete())
                with self.assertRaisesRegex(MalformedAnswer, names) as raised:
                    client.call("t", ARGUMENTS, self.untouched)
                answer = raised.exception.answer
                self.assertEqual(
                    (answer.ran, answer.outcome, answer.ending), (False, "OUTCOME_BLOCK", "")
                )
                self.assertEqual(self.sent(), [self.admitted])

    def test_an_execute_with_no_handle_still_carries_its_decision(self) -> None:
        client = self.serve(
            admit(b'{"outcome":1,"decision":{"schemaVersion":"1.0","verdict":1},"execution":{}}')
        )
        with self.assertRaises(MalformedAnswer) as raised:
            client.call("t", ARGUMENTS, self.untouched)
        self.assertEqual(raised.exception.answer.decision, {"schemaVersion": "1.0", "verdict": 1})

    def test_a_malformed_answer_to_complete_says_the_tool_ran(self) -> None:
        client = self.serve(
            admit(EXECUTE), complete(b'{"ending":"ENDING_RECORDED","grant":"all"}'), complete()
        )
        with self.assertRaisesRegex(
            MalformedAnswer, "grant: no member of CompleteResponse"
        ) as raised:
            client.call("t", ARGUMENTS, self.entering(succeed))
        self.assertEqual((raised.exception.answer.ran, raised.exception.answer.ending), (True, ""))
        self.assertEqual(len(self.sent()), 2)


class Aborting(Rules):
    """When a held handle is given up, and that it is given up once."""

    def test_an_obligation_outranks_missing_bytes_and_a_gone_caller(self) -> None:
        answers = iter((False, True))
        client = self.serve(
            admit(OBLIGED.replace(b'"authorizedArguments":"eyJhIjoxfQ==",', b"")), abort()
        )
        with self.assertRaises(CallAborted) as raised:
            client.call("t", ARGUMENTS, self.untouched, gone=lambda: next(answers))
        self.assertEqual(raised.exception.cause, "ABORT_CAUSE_OBLIGATION")
        self.assertEqual(
            self.sent(),
            [self.admitted, (ABORT, {"handle": "h-1", "cause": "ABORT_CAUSE_OBLIGATION"})],
        )
        self.assertEqual(
            next(answers), True, "the caller was read again though the answer forbade the run"
        )

    def test_missing_bytes_outrank_a_gone_caller(self) -> None:
        answers = iter((False, True))
        client = self.serve(admit(b'{"outcome":1,"execution":{"handle":"h-1"}}'), abort())
        with self.assertRaises(CallAborted) as raised:
            client.call("t", ARGUMENTS, self.untouched, gone=lambda: next(answers))
        self.assertEqual(raised.exception.cause, "ABORT_CAUSE_ARGUMENTS_DIFFER")
        self.assertEqual(
            (raised.exception.answer.ran, raised.exception.answer.ending),
            (False, "ENDING_RECORDED"),
        )
        self.assertEqual(
            self.sent(),
            [self.admitted, (ABORT, {"handle": "h-1", "cause": "ABORT_CAUSE_ARGUMENTS_DIFFER"})],
        )

    def test_a_call_that_proposed_no_bytes_runs_with_none(self) -> None:
        client = self.serve(admit(b'{"outcome":1,"execution":{"handle":"h-1"}}'), complete())
        got: list[bytes] = []
        answer = client.call("t", b"", got.append)
        self.assertEqual((got, answer.ran), ([b""], True))
        self.assertEqual(self.sent()[0], (ADMIT, {"tool": "t"}))
        self.assertNotIn("sentArguments", harness.as_object(self.sent()[1][1], "the complete"))

    def test_a_refused_abort_is_still_an_abort(self) -> None:
        client = self.serve(
            admit(OBLIGED),
            abort(b'{"code":"ERROR_CODE_HANDLE_UNKNOWN","message":"gone"}', 404),
            abort(),
        )
        with self.assertRaises(CallAborted) as raised:
            client.call("t", ARGUMENTS, self.untouched)
        aborted, refusal = raised.exception, raised.exception.__cause__
        self.assertEqual(
            (aborted.cause, aborted.answer.ran, aborted.answer.ending),
            ("ABORT_CAUSE_OBLIGATION", False, ""),
        )
        if not isinstance(refusal, CallRefused):
            self.fail(f"the abort was raised from {refusal!r}, not from its refusal")
        self.assertEqual(
            (refusal.status, refusal.code, refusal.message),
            (404, "ERROR_CODE_HANDLE_UNKNOWN", "gone"),
        )
        self.assertEqual(len(self.sent()), 2)

    def test_a_refused_abort_carries_the_ending_the_refusal_names(self) -> None:
        client = self.serve(
            admit(OBLIGED),
            abort(b'{"code":"ERROR_CODE_HANDLE_SPENT","ending":"ENDING_ABANDONED"}', 409),
        )
        with self.assertRaises(CallAborted) as raised:
            client.call("t", ARGUMENTS, self.untouched)
        self.assertEqual(raised.exception.answer.ending, "ENDING_ABANDONED")

    def test_an_abort_whose_answer_is_malformed_is_a_malformed_answer(self) -> None:
        client = self.serve(
            admit(OBLIGED), abort(b'{"ending":"ENDING_RECORDED","grant":"all"}'), abort()
        )
        with self.assertRaisesRegex(MalformedAnswer, "grant: no member of AbortResponse") as raised:
            client.call("t", ARGUMENTS, self.untouched)
        self.assertEqual(raised.exception.answer.ran, False)
        self.assertEqual(len(self.sent()), 2)

    def test_an_abort_names_whatever_ending_the_receiver_did(self) -> None:
        for written, named in (
            (b'{"ending":"ENDING_UNRECORDED"}', "ENDING_UNRECORDED"),
            (b'{"ending":9}', "9"),
            (b"{}", ""),
        ):
            with self.subTest(written=written):
                client = self.serve(admit(OBLIGED), abort(written))
                with self.assertRaises(CallAborted) as raised:
                    client.call("t", ARGUMENTS, self.untouched)
                self.assertEqual(raised.exception.answer.ending, named)

    def test_a_caller_gone_before_admit_sends_nothing(self) -> None:
        def raises() -> object:
            raise RuntimeError("the caller's check broke")

        for name, gone in (
            ("True", lambda: True),
            ("None", lambda: None),
            ("zero", lambda: 0),
            ("an empty string", lambda: ""),
            ("a word", lambda: "no"),
            ("an exception", raises),
        ):
            with self.subTest(gone=name):
                client = self.serve(admit(EXECUTE), complete())
                with self.assertRaises(CallerGone) as raised:
                    client.call("t", ARGUMENTS, self.untouched, gone=gone)
                self.assertEqual(
                    raised.exception.answer, Answer("OUTCOME_BLOCK", None, None, False, None, "")
                )
                self.assertEqual(self.sent(), [])

    def test_the_caller_is_read_before_admit_and_before_the_tool(self) -> None:
        client = self.serve(admit(EXECUTE), complete())
        seen: list[int] = []

        def gone() -> bool:
            seen.append(len(self.receiver.requests()))
            return False

        answer = client.call("t", ARGUMENTS, self.entering(lambda _: seen.append(-1)), gone=gone)
        self.assertEqual((answer.ran, seen), (True, [0, 1, -1]))

    def test_a_caller_gone_after_admit_gets_its_abort_sent(self) -> None:
        for name, second in (("True", True), ("None", None), ("an exception", ValueError("broke"))):
            with self.subTest(gone=name):
                client = self.serve(admit(EXECUTE), abort(), complete())
                answers: Iterator[object] = iter((False, second))

                def gone(answers: Iterator[object] = answers) -> object:
                    answer = next(answers)
                    if isinstance(answer, Exception):
                        raise answer
                    return answer

                with self.assertRaises(CallAborted) as raised:
                    client.call("t", ARGUMENTS, self.untouched, gone=gone)
                self.assertEqual(
                    (raised.exception.cause, raised.exception.answer.ran),
                    ("ABORT_CAUSE_NOT_SENT", False),
                )
                self.assertEqual(self.sent(), [self.admitted, (ABORT, ABORT_NOT_SENT)])

    def test_an_interrupt_between_admit_and_the_tool_aborts_and_is_raised_again(self) -> None:
        for interrupt, where in (
            (KeyboardInterrupt(), "the caller's check"),
            (SystemExit(3), "the caller's check"),
            (asyncio.CancelledError(), "the caller's check"),
            (KeyboardInterrupt(), "the clock"),
            (SystemExit(3), "the clock"),
            (asyncio.CancelledError(), "the clock"),
            (RuntimeError("the clock broke"), "the clock"),
        ):
            with self.subTest(interrupt=interrupt, where=where):
                self.receiver = harness.Receiver([admit(EXECUTE), abort(), complete()])
                self.addCleanup(self.receiver.close)
                answers = iter((False,))

                def gone(
                    answers: Iterator[bool] = answers, interrupt: BaseException = interrupt
                ) -> bool:
                    try:
                        return next(answers)
                    except StopIteration:
                        raise interrupt from None

                def clock(interrupt: BaseException = interrupt) -> datetime:
                    raise interrupt

                if where == "the clock":
                    client = Client(self.receiver.socket, "tok", 5.0, clock=clock)
                    call = functools.partial(client.call, "t", ARGUMENTS, self.untouched)
                else:
                    client = Client(self.receiver.socket, "tok", 5.0)
                    call = functools.partial(client.call, "t", ARGUMENTS, self.untouched, gone=gone)
                with self.assertRaises(type(interrupt)) as raised:
                    call()
                self.assertIs(raised.exception, interrupt)
                self.assertEqual(self.sent(), [self.admitted, (ABORT, ABORT_NOT_SENT)])

    def test_an_interrupt_is_raised_again_whatever_became_of_its_abort(self) -> None:
        interrupt = KeyboardInterrupt()

        def clock() -> datetime:
            raise interrupt

        for answer in (
            abort(b'{"code":"ERROR_CODE_HANDLE_UNKNOWN"}', 404),
            abort(b"not json"),
            complete(),
        ):
            with self.subTest(answer=answer):
                self.receiver = harness.Receiver([admit(EXECUTE), answer, abort()])
                self.addCleanup(self.receiver.close)
                with self.assertRaises(KeyboardInterrupt) as raised:
                    Client(self.receiver.socket, "tok", 5.0, clock=clock).call(
                        "t", ARGUMENTS, self.untouched
                    )
                self.assertIs(raised.exception, interrupt)
                self.assertEqual(self.sent(), [self.admitted, (ABORT, ABORT_NOT_SENT)])

    def test_a_clock_that_reads_no_aware_time_aborts_before_the_tool(self) -> None:
        for reading in (
            datetime(2026, 10, 11, 12, 0, 0),
            "2026-10-11T12:00:00Z",
            None,
            1791720300.0,
        ):
            with self.subTest(reading=reading):
                self.receiver = harness.Receiver([admit(EXECUTE), abort()])
                self.addCleanup(self.receiver.close)
                client = Client(self.receiver.socket, "tok", 5.0, clock=lambda r=reading: r)  # type: ignore[misc]
                with self.assertRaisesRegex(TypeError, "clock"):
                    client.call("t", ARGUMENTS, self.untouched)
                self.assertEqual(self.sent(), [self.admitted, (ABORT, ABORT_NOT_SENT)])


class Running(Rules):
    """What the tool gets, and what becomes of what it does."""

    def test_the_tool_cannot_change_what_complete_reports_as_sent(self) -> None:
        client = self.serve(admit(EXECUTE), complete())
        got: list[object] = []

        def tool(authorized: bytes) -> Result:
            self.entered = True
            got.append(authorized)
            try:
                memoryview(authorized)[0:7] = b"XXXXXXX"
            except TypeError:
                got.append("read-only")
            return Result(Status.SUCCESS)

        client.call("t", ARGUMENTS, tool)
        self.assertEqual(got, [b'{"a":1}', "read-only"])
        self.assertIs(type(got[0]), bytes)
        self.assertEqual(self.sent()[1], self.completed("COMPLETION_STATUS_SUCCESS"))

    def test_the_tool_gets_the_authorized_bytes_and_complete_reports_them(self) -> None:
        rewritten = EXECUTE.replace(b"eyJhIjoxfQ==", b"eyJhIjoyfQ==")
        client = self.serve(admit(rewritten), complete())
        got: list[bytes] = []
        client.call("t", ARGUMENTS, got.append)
        self.assertEqual(got, [b'{"a":2}'])
        self.assertEqual(
            harness.as_object(self.sent()[1][1], "complete")["sentArguments"], "eyJhIjoyfQ=="
        )

    def test_a_status_is_reported_only_when_it_is_declared(self) -> None:
        for reported, sent in (
            (Result(Status.SUCCESS), "COMPLETION_STATUS_SUCCESS"),
            (Result(Status.FAILURE), "COMPLETION_STATUS_FAILURE"),
            (Result(Status.TIMEOUT), "COMPLETION_STATUS_TIMEOUT"),
            (Result(Status.CANCELLED), "COMPLETION_STATUS_CANCELLED"),
            (Result(Status.UNKNOWN), "COMPLETION_STATUS_UNKNOWN"),
            (Result(), "COMPLETION_STATUS_UNKNOWN"),
            (Result("COMPLETION_STATUS_UNSPECIFIED"), "COMPLETION_STATUS_UNKNOWN"),
            (Result("SUCCESS"), "COMPLETION_STATUS_UNKNOWN"),
            (Result("completion_status_success"), "COMPLETION_STATUS_UNKNOWN"),
            (misstating(1), "COMPLETION_STATUS_UNKNOWN"),
            (misstating(["COMPLETION_STATUS_SUCCESS"]), "COMPLETION_STATUS_UNKNOWN"),
            (None, "COMPLETION_STATUS_UNKNOWN"),
        ):
            with self.subTest(reported=reported):
                client = self.serve(admit(EXECUTE), complete())
                answer = client.call("t", ARGUMENTS, self.entering(returning(reported)))
                self.assertEqual(self.sent(), [self.admitted, self.completed(sent)])
                result = result_of(answer)
                self.assertEqual(result.status, reported.status if reported else "")
                self.assertEqual(
                    (result.started_at, result.ended_at), (harness.BEFORE, harness.AFTER)
                )

    def test_the_tools_own_times_and_words_are_reported(self) -> None:
        client = self.serve(admit(EXECUTE), complete())
        reported = Result(
            Status.SUCCESS,
            started_at=datetime(2026, 10, 11, 14, 0, 1, tzinfo=PLUS_TWO),
            ended_at=datetime(2026, 10, 11, 12, 0, 3, 250, tzinfo=UTC),
            result_hash="sha256:77aa",
            side_effect_confirmation="za\u017c\u00f3\u0142\u0107 r-1",
        )
        answer = client.call("t", ARGUMENTS, lambda _: reported)
        self.assertEqual(answer.result, reported)
        self.assertEqual(
            self.sent()[1],
            (
                COMPLETE,
                {
                    "handle": "h-1",
                    "sentArguments": "eyJhIjoxfQ==",
                    "status": "COMPLETION_STATUS_SUCCESS",
                    "startedAt": "2026-10-11T12:00:01Z",
                    "endedAt": "2026-10-11T12:00:03.000250Z",
                    "resultHash": "sha256:77aa",
                    "sideEffectConfirmation": "za\u017c\u00f3\u0142\u0107 r-1",
                },
            ),
        )

    def test_not_sent_aborts_and_says_the_tool_did_not_run(self) -> None:
        class Unreachable(NotSent):
            pass

        for said in (NotSent("dialling"), Unreachable("dialling")):
            with self.subTest(said=said):
                client = self.serve(admit(EXECUTE), abort(), complete())

                def tool(_authorized: bytes, said: NotSent = said) -> Result:
                    raise said

                with self.assertRaises(CallAborted) as raised:
                    client.call("t", ARGUMENTS, tool)
                aborted = raised.exception
                self.assertEqual(
                    (aborted.cause, aborted.answer.ran, aborted.answer.result),
                    ("ABORT_CAUSE_NOT_SENT", False, None),
                )
                self.assertEqual(aborted.answer.ending, "ENDING_RECORDED")
                self.assertIs(aborted.__cause__, said)
                self.assertEqual(self.sent(), [self.admitted, (ABORT, ABORT_NOT_SENT)])

    def test_not_sent_aborts_without_reading_the_clock_again(self) -> None:
        self.receiver = harness.Receiver([admit(EXECUTE), abort(), complete()])
        self.addCleanup(self.receiver.close)
        readings: list[datetime] = []
        said = NotSent("dialling")

        def clock() -> datetime:
            readings.append(harness.BEFORE)
            return harness.BEFORE

        def tool(_authorized: bytes) -> Result:
            raise said

        client = Client(self.receiver.socket, "tok", 5.0, clock=clock)
        with self.assertRaises(CallAborted) as raised:
            client.call("t", ARGUMENTS, tool)
        self.assertIs(raised.exception.__cause__, said)
        self.assertEqual(readings, [harness.BEFORE])
        self.assertEqual(self.sent(), [self.admitted, (ABORT, ABORT_NOT_SENT)])

    def test_not_sent_met_only_in_a_chain_completes(self) -> None:
        def from_cause(_authorized: bytes) -> Result:
            self.entered = True
            raise RuntimeError("lost") from NotSent("dialling")

        def from_context(_authorized: bytes) -> Result:
            self.entered = True
            try:
                raise NotSent("dialling")
            except NotSent:
                raise RuntimeError("lost")  # noqa: B904

        for tool in (from_cause, from_context):
            with self.subTest(tool=tool.__name__):
                client = self.serve(admit(EXECUTE), complete(), abort())
                with self.assertRaisesRegex(RuntimeError, "lost"):
                    client.call("t", ARGUMENTS, tool)
                self.assertEqual(
                    self.sent(), [self.admitted, self.completed("COMPLETION_STATUS_UNKNOWN")]
                )

    def test_any_exception_of_the_tool_is_completed_unknown_and_raised_again(self) -> None:
        for error in (
            ValueError("lost"),
            TimeoutError("waiting"),
            KeyboardInterrupt(),
            SystemExit(3),
            asyncio.CancelledError(),
            GeneratorExit(),
        ):
            with self.subTest(error=error):
                client = self.serve(admit(EXECUTE), complete(), abort())

                def tool(_authorized: bytes, error: BaseException = error) -> Result:
                    self.entered = True
                    raise error

                with self.assertRaises(type(error)) as raised:
                    client.call("t", ARGUMENTS, tool)
                self.assertIs(raised.exception, error)
                self.assertEqual(
                    self.sent(), [self.admitted, self.completed("COMPLETION_STATUS_UNKNOWN")]
                )

    def test_an_exception_over_a_complete_that_did_not_land_is_replaced(self) -> None:
        for answer, replaced, ending in (
            (complete(b'{"ending":"ENDING_RECORD_FAILED"}'), NotRecorded, "ENDING_RECORD_FAILED"),
            (
                complete(b'{"code":"ERROR_CODE_HANDLE_SPENT","ending":"ENDING_ABANDONED"}', 409),
                CallRefused,
                "ENDING_ABANDONED",
            ),
            (complete(b"not json"), MalformedAnswer, ""),
        ):
            with self.subTest(replaced=replaced.__name__):
                client = self.serve(admit(EXECUTE), answer, complete())
                error = ValueError("lost")

                def tool(_authorized: bytes, error: Exception = error) -> Result:
                    self.entered = True
                    raise error

                with self.assertRaises(replaced) as raised:
                    client.call("t", ARGUMENTS, tool)
                failure = raised.exception
                self.assertIs(failure.__cause__, error)
                self.assertEqual(
                    (failure.answer.ran, failure.answer.result, failure.answer.ending),
                    (True, None, ending),
                )
                self.assertEqual(
                    self.sent(), [self.admitted, self.completed("COMPLETION_STATUS_UNKNOWN")]
                )

    def test_an_interrupt_over_a_complete_that_did_not_land_is_raised_unchanged(self) -> None:
        for error in (KeyboardInterrupt(), SystemExit(3), asyncio.CancelledError()):
            with self.subTest(error=error):
                client = self.serve(
                    admit(EXECUTE), complete(b'{"ending":"ENDING_RECORD_FAILED"}'), complete()
                )

                def tool(_authorized: bytes, error: BaseException = error) -> Result:
                    self.entered = True
                    raise error

                with self.assertRaises(type(error)) as raised:
                    client.call("t", ARGUMENTS, tool)
                self.assertIs(raised.exception, error)
                self.assertEqual(
                    self.sent(), [self.admitted, self.completed("COMPLETION_STATUS_UNKNOWN")]
                )

    def test_a_tool_that_cannot_return_a_result_is_refused_before_admit(self) -> None:
        async def coroutine(_authorized: bytes) -> Result:
            return Result(Status.SUCCESS)

        def generator(_authorized: bytes) -> Iterator[Result]:
            yield Result(Status.SUCCESS)

        async def async_generator(_authorized: bytes) -> AsyncIterator[Result]:
            yield Result(Status.SUCCESS)

        class Awaited:
            async def __call__(self, _authorized: bytes) -> Result:
                return Result(Status.SUCCESS)

        class Method:
            async def run(self, _authorized: bytes) -> Result:
                return Result(Status.SUCCESS)

        for name, run in (
            ("a coroutine function", coroutine),
            ("a generator function", generator),
            ("an async generator function", async_generator),
            ("an object awaited when called", Awaited()),
            ("a coroutine method", Method().run),
            ("a partial of a coroutine function", functools.partial(coroutine)),
            ("None", None),
            ("a result", Result(Status.SUCCESS)),
        ):
            with self.subTest(run=name):
                client = self.serve(admit(EXECUTE), complete())
                with self.assertRaisesRegex(TypeError, "run must") as raised:
                    client.call("t", ARGUMENTS, run)  # type: ignore[arg-type]
                self.assertNotIsInstance(raised.exception, EnforceError)
                self.assertEqual(self.sent(), [])

    def test_a_tool_or_arguments_of_another_type_are_refused_before_admit(self) -> None:
        for tool, arguments in (
            ("t", '{"a":1}'),
            ("t", bytearray(b'{"a":1}')),
            ("t", memoryview(b'{"a":1}')),
            ("t", None),
            (b"t", b"{}"),
            (None, b"{}"),
            ("\ud800", b"{}"),
        ):
            with self.subTest(tool=tool, arguments=arguments):
                client = self.serve(admit(EXECUTE), complete())
                with self.assertRaisesRegex(TypeError, "must be") as raised:
                    client.call(tool, arguments, self.untouched)  # type: ignore[arg-type]
                self.assertNotIsInstance(raised.exception, EnforceError)
                self.assertEqual(self.sent(), [])

    def test_a_tool_that_returns_anything_but_a_result_is_completed_unknown(self) -> None:
        async def coroutine() -> Result:
            return Result(Status.SUCCESS)

        def generator() -> Iterator[Result]:
            yield Result(Status.SUCCESS)

        for make, named in (
            (lambda: {"status": "COMPLETION_STATUS_SUCCESS"}, "dict"),
            (lambda: "COMPLETION_STATUS_SUCCESS", "str"),
            (lambda: True, "bool"),
            (coroutine, "coroutine"),
            (generator, "generator"),
        ):
            with self.subTest(returned=named):
                client = self.serve(admit(EXECUTE), complete(), abort())
                returned: list[object] = []

                def tool(
                    _authorized: bytes,
                    make: Callable[[], object] = make,
                    returned: list[object] = returned,
                ) -> Result:
                    self.entered = True
                    returned.append(make())
                    return returned[0]  # type: ignore[return-value]

                with warnings.catch_warnings(record=True) as warned:
                    warnings.simplefilter("always")
                    with self.assertRaisesRegex(
                        BadResult, f"the tool returned {named}, not a Result or None"
                    ) as raised:
                        client.call("t", ARGUMENTS, tool)
                    if inspect.iscoroutine(returned[0]):
                        self.assertEqual(
                            inspect.getcoroutinestate(returned[0]), inspect.CORO_CLOSED
                        )
                    if inspect.isgenerator(returned[0]):
                        self.assertEqual(inspect.getgeneratorstate(returned[0]), inspect.GEN_CLOSED)
                    returned.clear()
                    gc.collect()
                self.assertEqual([str(w.message) for w in warned], [])
                self.assertEqual(raised.exception.answer, self.ran_unreported)
                self.assertEqual(
                    self.sent(), [self.admitted, self.completed("COMPLETION_STATUS_UNKNOWN")]
                )

    def test_a_result_that_cannot_be_reported_is_completed_unknown(self) -> None:
        for reported, names in (
            (misreporting(result_hash=7), "Result.result_hash"),
            (misreporting(side_effect_confirmation=b"r-1"), "Result.side_effect_confirmation"),
            (misreporting(result_hash="\udc00"), "Result.result_hash"),
            (misreporting(started_at=datetime(2026, 10, 11, 12, 0, 1)), "Result.started_at"),
            (misreporting(ended_at="2026-10-11T12:00:01Z"), "Result.ended_at"),
            (misreporting(ended_at=datetime.min.replace(tzinfo=PLUS_TWO)), "Result.ended_at"),
        ):
            with self.subTest(names=names):
                client = self.serve(admit(EXECUTE), complete(), abort())
                with self.assertRaisesRegex(BadResult, names) as raised:
                    client.call("t", ARGUMENTS, self.entering(returning(reported)))
                self.assertEqual(raised.exception.answer, self.ran_unreported)
                self.assertEqual(
                    self.sent(), [self.admitted, self.completed("COMPLETION_STATUS_UNKNOWN")]
                )

    def test_a_time_whose_zone_cannot_say_its_offset_is_completed_unknown(self) -> None:
        for says in (NotImplementedError("no offset"), 7200, "+02:00", timedelta(hours=30)):
            for member in ("started_at", "ended_at"):
                with self.subTest(says=says, member=member):
                    client = self.serve(admit(EXECUTE), complete(), abort())
                    at = datetime(2026, 10, 11, 12, 0, 1, tzinfo=Zone(says))
                    tool = self.entering(returning(misreporting(**{member: at})))
                    with self.assertRaisesRegex(BadResult, f"Result.{member}") as raised:
                        client.call("t", ARGUMENTS, tool)
                    self.assertEqual(raised.exception.answer, self.ran_unreported)
                    self.assertEqual(
                        self.sent(), [self.admitted, self.completed("COMPLETION_STATUS_UNKNOWN")]
                    )

    def test_a_zone_that_stops_saying_its_offset_still_gets_the_one_complete(self) -> None:
        reported: list[str] = []
        for times in range(8):
            with self.subTest(times=times):
                client = self.serve(admit(EXECUTE), complete(), complete())
                zone = Zone(RuntimeError("no offset any more"), times)
                result = Result(
                    Status.SUCCESS, started_at=datetime(2026, 10, 11, 12, 0, 1, 0, zone)
                )
                try:
                    answer = client.call("t", ARGUMENTS, self.entering(returning(result)))
                    want = self.completed(
                        "COMPLETION_STATUS_SUCCESS", startedAt="2026-10-11T12:00:01Z"
                    )
                    reported.append("its own")
                except BadResult as bad:
                    answer = bad.answer
                    want = self.completed("COMPLETION_STATUS_UNKNOWN")
                    reported.append("unknown")
                self.assertEqual(self.sent(), [self.admitted, want])
                self.assertEqual((answer.ran, answer.ending), (True, "ENDING_RECORDED"))
        self.assertEqual((reported[0], reported[-1]), ("unknown", "its own"))

    def test_a_result_no_copy_can_be_made_of_is_completed_unknown(self) -> None:
        for reported, cause in ((Receipt("r-1"), TypeError), (Unsendable(), NotSent)):
            with self.subTest(reported=type(reported).__name__):
                client = self.serve(admit(EXECUTE), complete(), abort())
                with self.assertRaisesRegex(BadResult, "cannot be reported") as raised:
                    client.call("t", ARGUMENTS, self.entering(returning(reported)))
                self.assertIsInstance(raised.exception.__cause__, cause)
                self.assertEqual(raised.exception.answer, self.ran_unreported)
                self.assertEqual(
                    self.sent(), [self.admitted, self.completed("COMPLETION_STATUS_UNKNOWN")]
                )

    def test_an_interrupt_after_the_tool_is_completed_unknown_and_raised_again(self) -> None:
        def lose(_authorized: bytes) -> Result:
            raise ValueError("lost")

        for interrupt in (KeyboardInterrupt(), SystemExit(3), asyncio.CancelledError()):
            unread = misreporting(started_at=datetime(2026, 10, 11, 12, 0, 1, 0, Zone(interrupt)))
            for where, tool, landed in (
                ("the clock", succeed, complete()),
                ("the clock", lose, complete()),
                ("the result", returning(unread), complete()),
                ("the clock", succeed, complete(b'{"ending":"ENDING_UNRECORDED"}')),
                ("the clock", succeed, complete(b'{"code":"ERROR_CODE_UNAVAILABLE"}', 503)),
            ):
                with self.subTest(interrupt=interrupt, where=where, tool=tool, landed=landed):
                    # The clock reads the start; in it, the interrupt comes with the end.
                    clock = scripted(harness.BEFORE, interrupt) if where == "the clock" else None
                    client = self.serve(admit(EXECUTE), landed, complete(), clock=clock)
                    with self.assertRaises(type(interrupt)) as raised:
                        client.call("t", ARGUMENTS, self.entering(tool))
                    self.assertIs(raised.exception, interrupt)
                    self.assertEqual(self.entered, True)
                    ended = harness.BEFORE_TEXT if clock else harness.AFTER_TEXT
                    unknown = self.completed("COMPLETION_STATUS_UNKNOWN", endedAt=ended)
                    self.assertEqual(self.sent(), [self.admitted, unknown])

    def test_a_wrong_return_over_a_complete_that_did_not_land_is_replaced(self) -> None:
        for answer, replaced, ending in (
            (complete(b'{"ending":"ENDING_UNRECORDED"}'), NotRecorded, "ENDING_UNRECORDED"),
            (
                complete(b'{"code":"ERROR_CODE_HANDLE_SPENT","ending":"ENDING_ABANDONED"}', 409),
                CallRefused,
                "ENDING_ABANDONED",
            ),
            (complete(b"not json"), MalformedAnswer, ""),
        ):
            for returned in ({"a": 1}, Receipt("r-1")):
                with self.subTest(replaced=replaced.__name__, returned=type(returned).__name__):
                    client = self.serve(admit(EXECUTE), answer, complete())
                    with self.assertRaises(replaced) as raised:
                        client.call("t", ARGUMENTS, self.entering(returning(returned)))
                    bad = raised.exception.__cause__
                    if not isinstance(bad, BadResult):
                        self.fail(f"the failure was raised from {bad!r}, not from a BadResult")
                    for carried in (bad.answer, raised.exception.answer):
                        self.assertEqual(
                            (carried.ran, carried.result, carried.ending), (True, None, ending)
                        )
                    self.assertEqual(
                        self.sent(), [self.admitted, self.completed("COMPLETION_STATUS_UNKNOWN")]
                    )

    def test_the_end_of_a_run_is_its_start_when_the_clock_fails_after_the_tool(self) -> None:
        self.receiver = harness.Receiver([admit(EXECUTE), complete()])
        self.addCleanup(self.receiver.close)
        readings = iter((harness.BEFORE,))
        client = Client(self.receiver.socket, "tok", 5.0, clock=lambda: next(readings))
        answer = client.call("t", ARGUMENTS, succeed)
        self.assertEqual(
            answer.result, Result(Status.SUCCESS, None, harness.BEFORE, harness.BEFORE)
        )
        sent = harness.as_object(self.sent()[1][1], "the complete")
        self.assertEqual(
            (sent["startedAt"], sent["endedAt"]), (harness.BEFORE_TEXT, harness.BEFORE_TEXT)
        )

    def test_the_default_clock_reads_now_in_utc(self) -> None:
        self.receiver = harness.Receiver([admit(EXECUTE), complete()])
        self.addCleanup(self.receiver.close)
        before = datetime.now(UTC)
        answer = Client(self.receiver.socket, "tok", 5.0).call("t", ARGUMENTS, succeed)
        after = datetime.now(UTC)
        started, ended = result_of(answer).started_at, result_of(answer).ended_at
        if started is None or ended is None:
            self.fail("the answer's result carries no times")
        self.assertEqual(started.utcoffset(), timedelta(0))
        self.assertTrue(before <= started <= ended <= after)

    def test_one_client_serves_concurrent_calls_from_threads(self) -> None:
        receiver = harness.EchoReceiver()
        self.addCleanup(receiver.close)
        client = Client(receiver.socket, "tok", 10.0)
        problems: list[str] = []

        def one(number: int) -> None:
            want = b'{"n":%d}' % number
            got: list[bytes] = []
            try:
                for _ in range(3):
                    answer = client.call(str(number), want, got.append)
                    if not answer.ran or answer.ending != "ENDING_RECORDED":
                        problems.append(f"call {number}: {answer}")
            except Exception as error:
                problems.append(f"call {number}: {error!r}")
            if got != [want] * 3:
                problems.append(f"call {number} ran with {got!r}")

        threads = [threading.Thread(target=one, args=(number,)) for number in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(problems, [])
        self.assertEqual(len(receiver.requests()), 48)


def dialling(_authorized: bytes) -> Result:
    raise NotSent("dialling")


class Nested(Rules):
    """A tool that makes a governed call of its own, and what then leaves the outer call."""

    inner_admitted = (ADMIT, {"tool": "inner", "arguments": "eyJhIjoxfQ=="})
    inner_aborted = (ABORT, {"handle": "h-2", "cause": "ABORT_CAUSE_NOT_SENT"})
    # The inner tool is entered after the outer one, so the clock reads the later time twice.
    inner_completed = (
        COMPLETE,
        {
            "handle": "h-2",
            "sentArguments": "eyJhIjoxfQ==",
            "status": "COMPLETION_STATUS_UNKNOWN",
            "startedAt": harness.AFTER_TEXT,
            "endedAt": harness.AFTER_TEXT,
        },
    )

    def calling(
        self, client: Client, inner: Callable[[bytes], Result | None]
    ) -> Callable[[bytes], Result | None]:
        """A tool that is entered and then calls inner through the same client."""

        def tool(_authorized: bytes) -> Result:
            self.entered = True
            client.call("inner", ARGUMENTS, inner)
            return Result(Status.SUCCESS)

        return tool

    def test_an_exception_of_a_call_the_tool_made_leaves_as_the_outer_calls_own(self) -> None:
        for name, script, inner, cause, inner_ran, between in (
            ("blocked", (admit(INNER_BLOCK),), None, CallBlocked, False, ()),
            ("pending", (admit(INNER_PENDING),), None, CallPending, False, ()),
            (
                "aborted as not sent",
                (admit(INNER_EXECUTE), abort()),
                dialling,
                CallAborted,
                False,
                (self.inner_aborted,),
            ),
            (
                "a wrong return",
                (admit(INNER_EXECUTE), complete()),
                returning({"a": 1}),
                BadResult,
                True,
                (self.inner_completed,),
            ),
        ):
            with self.subTest(inner=name):
                client = self.serve(admit(EXECUTE), *script, complete())
                reached: list[bytes] = []
                with self.assertRaises(EnforceError) as raised:
                    client.call("t", ARGUMENTS, self.calling(client, inner or reached.append))
                left, made = raised.exception, raised.exception.__cause__
                self.assertIs(type(left), ToolRaised)
                self.assertEqual(left.answer, self.ran_unreported)
                if not isinstance(made, EnforceError):
                    self.fail(f"the outer call's exception was raised from {made!r}")
                self.assertIs(type(made), cause)
                self.assertEqual(made.answer.ran, inner_ran)
                self.assertEqual((self.entered, reached), (True, []))
                self.assertEqual(
                    self.sent(),
                    [
                        self.admitted,
                        self.inner_admitted,
                        *between,
                        self.completed("COMPLETION_STATUS_UNKNOWN"),
                    ],
                )

    def test_an_outer_complete_that_did_not_land_is_raised_from_the_outer_calls_own(self) -> None:
        client = self.serve(
            admit(EXECUTE),
            admit(INNER_BLOCK),
            complete(b'{"ending":"ENDING_RECORD_FAILED"}'),
            complete(),
        )
        reached: list[bytes] = []
        with self.assertRaises(NotRecorded) as raised:
            client.call("t", ARGUMENTS, self.calling(client, reached.append))
        failure, own = raised.exception, raised.exception.__cause__
        if not isinstance(own, EnforceError):
            self.fail(f"the failure was raised from {own!r}")
        self.assertIs(type(own), ToolRaised)
        for carried in (failure.answer, own.answer):
            self.assertEqual(
                (carried.ran, carried.result, carried.ending), (True, None, "ENDING_RECORD_FAILED")
            )
        self.assertIs(type(own.__cause__), CallBlocked)
        self.assertEqual(reached, [])
        self.assertEqual(
            self.sent(),
            [self.admitted, self.inner_admitted, self.completed("COMPLETION_STATUS_UNKNOWN")],
        )

    def grouping(
        self, client: Client, group: Callable[[EnforceError], BaseException]
    ) -> Callable[[bytes], Result | None]:
        """A tool that is entered, makes a blocked call, and raises what group makes of it."""

        def tool(_authorized: bytes) -> Result:
            self.entered = True
            try:
                client.call("inner", ARGUMENTS, self.untouched)
            except CallBlocked as blocked:
                raise group(blocked) from None
            return Result(Status.SUCCESS)

        return tool

    def leaving(self, client: Client, tool: Callable[[bytes], Result | None]) -> BaseException:
        """What a call raised, of whatever kind."""
        try:
            client.call("t", ARGUMENTS, tool)
        except BaseException as left:
            return left
        self.fail("the call returned")

    GROUPS: tuple[tuple[str, Callable[[EnforceError], BaseException]], ...] = (
        ("a group of exceptions", lambda made: ExceptionGroup("calls", [made])),
        (
            "a group made as a base group",
            lambda made: BaseExceptionGroup("calls", [made, ValueError("lost")]),
        ),
        (
            "a group within a group",
            lambda made: ExceptionGroup(
                "calls", [ValueError("lost"), ExceptionGroup("more", [made])]
            ),
        ),
    )

    def test_a_group_holding_an_exception_of_a_call_leaves_as_the_outer_calls_own(self) -> None:
        for name, group in self.GROUPS:
            with self.subTest(group=name):
                client = self.serve(admit(EXECUTE), admit(INNER_BLOCK), complete())
                left = self.leaving(client, self.grouping(client, group))
                if not isinstance(left, EnforceError):
                    self.fail(f"the call raised {left!r}")
                self.assertIs(type(left), ToolRaised)
                self.assertEqual(left.answer, self.ran_unreported)
                made = left.__cause__
                if not isinstance(made, BaseExceptionGroup):
                    self.fail(f"the outer call's exception was raised from {made!r}")
                self.assertEqual(made.message, "calls")
                self.assertEqual(
                    self.sent(),
                    [
                        self.admitted,
                        self.inner_admitted,
                        self.completed("COMPLETION_STATUS_UNKNOWN"),
                    ],
                )

    def test_a_group_over_a_complete_that_did_not_land_is_raised_from_the_outer_calls_own(
        self,
    ) -> None:
        for name, group in self.GROUPS:
            with self.subTest(group=name):
                client = self.serve(
                    admit(EXECUTE),
                    admit(INNER_BLOCK),
                    complete(b'{"ending":"ENDING_RECORD_FAILED"}'),
                    complete(),
                )
                failure = self.leaving(client, self.grouping(client, group))
                if not isinstance(failure, EnforceError):
                    self.fail(f"the call raised {failure!r}")
                own = failure.__cause__
                if not isinstance(own, EnforceError):
                    self.fail(f"the failure was raised from {own!r}")
                self.assertEqual((type(failure), type(own)), (NotRecorded, ToolRaised))
                for carried in (failure.answer, own.answer):
                    self.assertEqual(
                        (carried.ran, carried.result, carried.ending),
                        (True, None, "ENDING_RECORD_FAILED"),
                    )
                self.assertIsInstance(own.__cause__, BaseExceptionGroup)
                self.assertEqual(
                    self.sent(),
                    [
                        self.admitted,
                        self.inner_admitted,
                        self.completed("COMPLETION_STATUS_UNKNOWN"),
                    ],
                )

    def test_a_group_that_holds_an_interrupt_leaves_as_raised(self) -> None:
        for name, closing in (
            ("a complete that landed", complete()),
            ("a complete that did not", complete(b'{"ending":"ENDING_RECORD_FAILED"}')),
        ):
            with self.subTest(closing=name):
                client = self.serve(admit(EXECUTE), admit(INNER_BLOCK), closing, complete())
                left = self.leaving(
                    client,
                    self.grouping(
                        client,
                        lambda made: BaseExceptionGroup("calls", [made, KeyboardInterrupt()]),
                    ),
                )
                if isinstance(left, Exception) or not isinstance(left, BaseExceptionGroup):
                    self.fail(f"the call raised {left!r}")
                self.assertEqual(
                    [type(held) for held in left.exceptions], [CallBlocked, KeyboardInterrupt]
                )
                self.assertEqual(
                    self.sent(),
                    [
                        self.admitted,
                        self.inner_admitted,
                        self.completed("COMPLETION_STATUS_UNKNOWN"),
                    ],
                )

    def test_a_group_holding_no_exception_of_this_module_leaves_unchanged(self) -> None:
        for error in (
            ExceptionGroup("calls", [ValueError("lost")]),
            ExceptionGroup("calls", [ExceptionGroup("more", [TimeoutError("waiting")])]),
            BaseExceptionGroup("calls", [ValueError("lost"), KeyboardInterrupt()]),
        ):
            with self.subTest(error=error):
                client = self.serve(admit(EXECUTE), complete())

                def tool(_authorized: bytes, error: BaseException = error) -> Result:
                    self.entered = True
                    raise error

                self.assertIs(self.leaving(client, tool), error)
                self.assertEqual(
                    self.sent(), [self.admitted, self.completed("COMPLETION_STATUS_UNKNOWN")]
                )
