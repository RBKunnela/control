"""The rules of a call that no case file holds: when a held handle is given up."""

from __future__ import annotations

import asyncio
import functools
from collections.abc import Iterator
from datetime import datetime

from guardana_control.enforce import (
    Answer,
    CallAborted,
    CallerGone,
    CallRefused,
    Client,
    MalformedAnswer,
)
from tests import harness
from tests.harness import ABORT, ADMIT
from tests.rules import ABORT_NOT_SENT, ARGUMENTS, EXECUTE, OBLIGED, Rules, abort, admit, complete


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
