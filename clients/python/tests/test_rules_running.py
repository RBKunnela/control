"""The rules of a call that no case file holds: what the tool gets, and what becomes of it."""

from __future__ import annotations

import asyncio
import functools
import gc
import inspect
import threading
import warnings
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import UTC, datetime, timedelta

from guardana_control.enforce import (
    BadResult,
    CallAborted,
    CallRefused,
    Client,
    EnforceError,
    MalformedAnswer,
    NotRecorded,
    NotSent,
    Result,
    Status,
)
from tests import harness
from tests.harness import ABORT, COMPLETE
from tests.rules import (
    ABORT_NOT_SENT,
    ARGUMENTS,
    EXECUTE,
    PLUS_TWO,
    Receipt,
    Rules,
    Unsendable,
    Zone,
    abort,
    admit,
    complete,
    misreporting,
    misstating,
    result_of,
    returning,
    scripted,
    succeed,
)


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
