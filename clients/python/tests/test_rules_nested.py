"""The rules of a call that no case file holds: a tool that makes a governed call of its own."""

from __future__ import annotations

from collections.abc import Callable

from guardana_control.enforce import (
    BadResult,
    CallAborted,
    CallBlocked,
    CallPending,
    Client,
    EnforceError,
    NotRecorded,
    NotSent,
    Result,
    Status,
    ToolRaised,
)
from tests import harness
from tests.harness import ABORT, ADMIT, COMPLETE
from tests.rules import (
    ARGUMENTS,
    EXECUTE,
    INNER_BLOCK,
    INNER_EXECUTE,
    INNER_PENDING,
    Rules,
    abort,
    admit,
    complete,
    returning,
)


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
