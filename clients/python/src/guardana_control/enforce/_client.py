"""The one call that owns an execution from its admit to its closing request."""

from __future__ import annotations

import contextlib
import inspect
import math
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import NoReturn

from . import _ops
from ._transport import Transport, TransportError
from ._types import (
    BLOCK,
    EXECUTE,
    PENDING,
    RECORDED,
    Answer,
    BadResult,
    CallAborted,
    CallBlocked,
    CallerGone,
    CallPending,
    CallRefused,
    EnforceError,
    MalformedAnswer,
    NoAnswer,
    NotRecorded,
    NotSent,
    Result,
    Status,
    ToolRaised,
)
from ._wire import WireError

_TOKEN = re.compile(r"[\x20-\x7e]+")
_DECLARED = (Status.SUCCESS, Status.FAILURE, Status.TIMEOUT, Status.CANCELLED, Status.UNKNOWN)
_NOTHING = Answer(outcome=BLOCK, decision=None, held=None, ran=False, result=None, ending="")
_FAILURES = (_ops.RefusalError, WireError, TransportError)


def _seconds(timeout: object) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, int | float):
        raise ValueError("the request timeout must be a number of seconds")
    try:
        seconds = float(timeout)
    except OverflowError:
        seconds = math.inf
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("the request timeout must be finite and positive")
    return seconds


def _now() -> datetime:
    return datetime.now(UTC)


def _is_gone(gone: Callable[[], object] | None) -> bool:
    """Whether the caller is gone; only a plain False says it is still there."""
    if gone is None:
        return False
    try:
        return gone() is not False
    except Exception:
        return True


def _encodable(text: object) -> bool:
    if not isinstance(text, str):
        return False
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _refuse_before_admit(tool: object, arguments: object, run: object) -> None:
    if not _encodable(tool):
        raise TypeError("tool must be a string that UTF-8 can carry")
    if not isinstance(arguments, bytes):
        raise TypeError("arguments must be bytes")
    if not callable(run):
        raise TypeError("run must be a function taking the authorized bytes")
    for function in (run, run.__call__):
        if (
            inspect.iscoroutinefunction(function)
            or inspect.isgeneratorfunction(function)
            or inspect.isasyncgenfunction(function)
        ):
            raise TypeError("run must return a Result or None, not a coroutine or a generator")


def _aware(at: object) -> bool:
    """Whether at is a time that can be told in UTC; a zone may fail to say its offset."""
    if not isinstance(at, datetime):
        return False
    try:
        if at.utcoffset() is None:
            return False
        at.astimezone(UTC)
    except Exception:
        return False
    return True


def _misreported(returned: object) -> str:
    """Why what the tool returned cannot be reported, or nothing."""
    if not isinstance(returned, Result):
        return f"the tool returned {type(returned).__name__}, not a Result or None"
    for name in ("result_hash", "side_effect_confirmation"):
        if not _encodable(getattr(returned, name)):
            return f"the tool's Result.{name} is not a string that UTF-8 can carry"
    for name in ("started_at", "ended_at"):
        if getattr(returned, name) is not None and not _aware(getattr(returned, name)):
            return f"the tool's Result.{name} is not an aware datetime"
    return ""


def _report(told: Result, started: datetime, ended: datetime) -> tuple[_ops.Report, Result]:
    """What a complete says of the tool's result, and that result with its times filled in."""
    started, ended = told.started_at or started, told.ended_at or ended
    declared = isinstance(told.status, str) and told.status in _DECLARED
    report = _ops.Report(
        told.status if declared else Status.UNKNOWN,
        started,
        ended,
        told.result_hash,
        told.side_effect_confirmation,
    )
    return report, replace(told, started_at=started, ended_at=ended)


def _close(returned: object) -> None:
    """Closes what a tool wrongly returned, so that nothing warns of it later."""
    if inspect.iscoroutine(returned) or inspect.isgenerator(returned):
        with contextlib.suppress(Exception):
            returned.close()


@dataclass
class _Run:
    """How far one run of the tool got.

    It is filled as the run goes, so that whatever is raised on the way
    leaves a complete that can be sent: request is written before the tool
    is entered and written again as more is known. fault is what the tool
    raised; problem says why what it returned cannot be reported.
    """

    request: bytes = b""
    entered: bool = False
    returned: object = None
    result: Result | None = None
    fault: BaseException | None = None
    problem: str = ""


def _own(fault: BaseException | None) -> bool:
    """Whether fault is an exception of this module or a group of exceptions holding one."""
    if isinstance(fault, ExceptionGroup):
        return fault.subgroup(EnforceError) is not None
    return isinstance(fault, EnforceError)


def _leaving(ran: _Run, raised: BaseException | None, answer: Answer) -> BaseException | None:
    """What leaves a call whose tool was entered, or None.

    An interrupt comes before the tool's own exception, and that before a
    BadResult for what the tool returned. An exception of this module carries
    the answer of the call that raised it, so one the tool raised, alone or
    in a group of exceptions, leaves as a ToolRaised with this call's. A group
    that holds an interrupt is one, and leaves as raised.
    """
    if raised is not None and not isinstance(raised, Exception):
        return raised
    if _own(ran.fault):
        own = ToolRaised(f"the tool ran and raised {type(ran.fault).__name__}", answer)
        own.__cause__ = ran.fault
        return own
    if ran.fault is not None:
        return ran.fault
    if raised is None and not ran.problem:
        return None
    text = ran.problem or f"what the tool returned cannot be reported: {raised!r}"
    bad = BadResult(text, answer)
    bad.__cause__ = raised
    return bad


def _failure(exc: Exception, answer: Answer) -> EnforceError:
    """The module's exception for a request that brought no answer to act on."""
    if isinstance(exc, _ops.RefusalError):
        named = replace(answer, ending=exc.ending)
        return CallRefused(named, status=exc.status, code=exc.code, message=exc.message)
    if isinstance(exc, WireError):
        return MalformedAnswer(f"the receiver's answer is malformed: {exc}", answer)
    return NoAnswer(f"no answer from the receiver: {exc}", answer)


class Client:
    """Speaks the enforcement API to one receiver as one run.

    One client serves calls from any number of threads: every request opens
    a connection of its own.
    """

    def __init__(
        self,
        socket: str,
        token: str,
        timeout: float,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Refuses, with ValueError, a missing socket or token and an unbounded timeout.

        timeout, in seconds, bounds each request as a whole. clock reads the
        start and the end of a tool run that does not report its own.
        """
        if not isinstance(socket, str) or not socket:
            raise ValueError("no socket path")
        if not isinstance(token, str) or not token:
            raise ValueError("no run token")
        if not _TOKEN.fullmatch(token):
            raise ValueError("the run token holds a character a header cannot carry")
        self._transport = Transport(socket, token, _seconds(timeout))
        self._clock = clock or _now

    def _instant(self) -> datetime:
        now = self._clock()
        if not _aware(now):
            raise TypeError("the clock must return an aware datetime")
        return now

    def call(
        self,
        tool: str,
        arguments: bytes,
        run: Callable[[bytes], Result | None],
        *,
        gone: Callable[[], object] | None = None,
    ) -> Answer:
        """Asks before tool acts, runs it on an EXECUTE answer, and reports the run.

        run gets exactly the authorized bytes, which differ from arguments
        when a rule rewrote them. It raises NotSent only when it knows the
        bytes never left; any other exception is reported as UNKNOWN and
        raised again, one of this module's or a group of exceptions that
        holds one as the cause of a ToolRaised. A return that is neither a Result nor None, or
        a Result that cannot be reported, is reported as UNKNOWN and raises
        BadResult. gone is read before admit and before the tool, and
        anything but False ends the call there.

        Returns only when the tool ran and the closing record landed, which
        is not to say the tool succeeded: answer.result.status says that.
        Everything else raises, and an EnforceError's answer.ran says whether
        the tool was entered.
        """
        _refuse_before_admit(tool, arguments, run)
        if _is_gone(gone):
            raise CallerGone("the caller was gone before admit", _NOTHING)
        try:
            admitted = _ops.admit(self._transport.post, tool, arguments)
        except _FAILURES as exc:
            raise _failure(exc, _NOTHING) from exc
        answer = replace(
            _NOTHING, outcome=admitted.outcome, decision=admitted.decision, held=admitted.held
        )
        if admitted.unreadable:
            raise MalformedAnswer(
                f"the receiver's answer is malformed: {admitted.unreadable}", answer
            )
        if admitted.outcome == PENDING:
            raise CallPending("the call is held for approval", answer)
        if admitted.outcome != EXECUTE:
            raise CallBlocked("the call was blocked", answer)
        return self._execute(admitted, answer, run, gone)

    def _execute(
        self,
        admitted: _ops.Admitted,
        answer: Answer,
        run: Callable[[bytes], Result | None],
        gone: Callable[[], object] | None,
    ) -> Answer:
        """Closes a held handle with exactly one request: abort before the tool, complete after."""
        cause = admitted.abort_cause
        ran = _Run()
        raised: BaseException | None = None
        try:
            if not cause and _is_gone(gone):
                cause = _ops.NOT_SENT
            if not cause:
                self._run(admitted, run, ran)
        except BaseException as exc:
            raised = exc
        if not ran.entered:
            self._abort(admitted.handle, cause or _ops.NOT_SENT, answer, interrupt=raised)
        if isinstance(ran.fault, NotSent):
            self._abort(admitted.handle, _ops.NOT_SENT, answer, interrupt=raised, said=ran.fault)
        return self._complete(answer, ran, raised)

    def _run(
        self, admitted: _ops.Admitted, run: Callable[[bytes], Result | None], ran: _Run
    ) -> None:
        """Enters the tool; whatever is raised here, ran holds a complete that can be sent."""
        handle, sent = admitted.handle, admitted.authorized
        started = self._instant()
        ran.request = _ops.completion(handle, sent, _ops.Report(Status.UNKNOWN, started, started))
        ran.entered = True
        try:
            ran.returned = run(sent)
        except BaseException as exc:
            ran.fault = exc
            if isinstance(exc, NotSent):
                return
        try:
            ended = self._instant()
        except Exception:
            # The tool was entered, so its complete is owed whatever the clock does.
            ended = started
        ran.request = _ops.completion(handle, sent, _ops.Report(Status.UNKNOWN, started, ended))
        if ran.fault is not None:
            return
        told = Result() if ran.returned is None else ran.returned
        ran.problem = _misreported(told)
        if isinstance(told, Result) and not ran.problem:
            report, result = _report(told, started, ended)
            ran.request = _ops.completion(handle, sent, report)
            ran.result = result

    def _abort(
        self,
        handle: str,
        cause: str,
        answer: Answer,
        *,
        interrupt: BaseException | None = None,
        said: NotSent | None = None,
    ) -> NoReturn:
        """Sends the one abort and raises: the interrupt that forced it, else what became of it."""
        text = f"the execution was aborted: {cause}"
        unanswered: EnforceError | None = None
        aborted: EnforceError
        try:
            ending = _ops.abort(self._transport.post, handle, cause)
            aborted = CallAborted(text, replace(answer, ending=ending), cause=cause)
        except WireError as exc:
            aborted = _failure(exc, answer)
        except (_ops.RefusalError, TransportError) as exc:
            unanswered = _failure(exc, answer)
            aborted = CallAborted(text, unanswered.answer, cause=cause)
        if interrupt is not None:
            raise interrupt
        raise aborted from (unanswered or said)

    def _complete(self, answer: Answer, ran: _Run, raised: BaseException | None) -> Answer:
        """Sends the one complete of a tool that was entered, and says how the call ended."""
        answer = replace(answer, ran=True, result=ran.result)
        failure: EnforceError | None = None
        try:
            ending = _ops.complete(self._transport.post, ran.request)
            if ending != RECORDED:
                failure = NotRecorded(
                    f"the closing record did not land: {ending or 'no ending named'}",
                    replace(answer, ending=ending),
                )
        except _FAILURES as exc:
            failure = _failure(exc, answer)
        finally:
            _close(ran.returned)
        answer = replace(answer, ending=RECORDED) if failure is None else failure.answer
        fault = _leaving(ran, raised, answer)
        if fault is None:
            if failure is None:
                return answer
            raise failure
        # The tool's own exception leaves only over a recorded complete; an
        # interrupt leaves whatever became of the record.
        if failure is None or not isinstance(fault, Exception):
            raise fault
        raise failure from fault
