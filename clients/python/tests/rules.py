"""What the tests of a call's rules share: scripted answers, tools, clocks and a served client."""

from __future__ import annotations

import unittest
from collections.abc import Callable
from datetime import datetime, timedelta, timezone, tzinfo

from guardana_control.enforce import Answer, Client, NotSent, Result, Status
from tests import cases, harness
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
            self.assertEqual(cases.request_misses(number, request, "tok"), [])
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
