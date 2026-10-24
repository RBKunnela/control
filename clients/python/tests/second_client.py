"""A second client, written apart from the first, that breaks one rule when told to.

It takes from the module only the public result and exception types: the
socket code, the reading and the members of each message are its own.
"""

from __future__ import annotations

import binascii
import http.client
import json
import socket
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import NoReturn

from guardana_control.enforce import (
    Answer,
    CallAborted,
    CallBlocked,
    CallerGone,
    CallPending,
    CallRefused,
    EnforceError,
    Held,
    MalformedAnswer,
    NoAnswer,
    NotRecorded,
    NotSent,
    Result,
)
from tests.second_reader import (
    ADMITTED,
    ENDED,
    LIMIT,
    REFUSED,
    STATUSES,
    Reader,
    UnreadError,
    decode,
    named,
)

DEFECTS = (
    "block-executes-with-handle",
    "unspecified-executes",
    "unknown-executes",
    "skips-complete",
    "sends-proposed",
    "sends-proposed-when-empty",
    "ignores-obligations",
    "resumes-itself",
    "ignores-context",
    "aborts-on-tool-error",
    "completes-under-caller-context",
    "completes-when-not-sent",
    "reports-success",
    "retries-unauthenticated",
    "lenient-decoding",
    "retries-complete",
)

UINT32_MAX = 4294967295


class UnansweredError(Exception):
    """A request the second client got no answer to."""


def stamp(at: datetime) -> str:
    at = at.astimezone(UTC)
    text = at.strftime("%Y-%m-%dT%H:%M:%S")
    if at.microsecond % 1000:
        text += f".{at.microsecond:06d}"
    elif at.microsecond:
        text += f".{at.microsecond // 1000:03d}"
    return text + "Z"


def encoded(data: bytes) -> str:
    return binascii.b2a_base64(data, newline=False).decode("ascii")


class Connection(http.client.HTTPConnection):
    """An HTTP connection to a Unix socket."""

    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("enforce", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


class SecondClient:
    """Makes the same call as the client, by its own means, with one rule broken on request."""

    def __init__(
        self,
        socket_path: str,
        token: str,
        timeout: float,
        *,
        clock: Callable[[], datetime] | None = None,
        defect: str = "",
    ) -> None:
        if defect and defect not in DEFECTS:
            raise ValueError(f"no defect {defect!r}")
        self._socket = socket_path
        self._token = token
        self._timeout = timeout
        self._clock = clock or (lambda: datetime.now(UTC))
        self._defect = defect

    def _is(self, defect: str) -> bool:
        return self._defect == defect

    def _post(self, operation: str, body: dict[str, str], reader: Reader) -> dict[str, object]:
        connection = Connection(self._socket, self._timeout)
        try:
            connection.request(
                "POST",
                f"/enforce/v1alpha1/{operation}",
                json.dumps(body).encode("utf-8"),
                {"Run-Token": self._token, "Content-Type": "application/json"},
            )
            response = connection.getresponse()
            status, data = response.status, response.read(LIMIT + 1)
        except (OSError, http.client.HTTPException) as exc:
            raise UnansweredError(str(exc)) from exc
        finally:
            connection.close()
        lenient = self._is("lenient-decoding")
        if status != http.client.OK:
            refusal = decode(data, REFUSED, lenient)
            raise RefusalError(status, refusal)
        return decode(data, reader, lenient)

    def _admit(self, tool: str, arguments: bytes) -> dict[str, object]:
        body = {"tool": tool}
        if arguments:
            body["arguments"] = encoded(arguments)
        try:
            admitted = self._post("admit", body, ADMITTED)
        except RefusalError:
            if not self._is("retries-unauthenticated"):
                raise
            return self._post("admit", body, ADMITTED)
        if admitted.get("outcome") == "OUTCOME_PENDING" and self._is("resumes-itself"):
            return self._post("admit", body, ADMITTED)
        return admitted

    def _executes(self, admitted: dict[str, object]) -> bool:
        outcome, with_execution = admitted.get("outcome"), "execution" in admitted
        if outcome == "OUTCOME_EXECUTE":
            return True
        if outcome == "OUTCOME_BLOCK":
            return with_execution and self._is("block-executes-with-handle")
        if outcome in (None, "OUTCOME_UNSPECIFIED"):
            return with_execution and self._is("unspecified-executes")
        return self._is("unknown-executes")

    def call(
        self,
        tool: str,
        arguments: bytes,
        run: Callable[[bytes], Result | None],
        *,
        gone: Callable[[], object] | None = None,
    ) -> Answer:
        nothing = Answer("OUTCOME_BLOCK", None, None, False, None, "")
        if _left(gone):
            raise CallerGone("the caller left before admit", nothing)
        try:
            admitted = self._admit(tool, arguments)
        except (RefusalError, UnreadError, UnansweredError) as exc:
            raise _public(exc, nothing) from exc
        decision = admitted.get("decision")
        answer = replace(nothing, decision=decision if isinstance(decision, dict) else None)
        if not _version_read(decision):
            raise MalformedAnswer("a decision of a version this client does not read", answer)
        if admitted.get("outcome") == "OUTCOME_PENDING":
            held = admitted.get("pending")
            raise CallPending("held", replace(answer, outcome="OUTCOME_PENDING", held=_held(held)))
        if not self._executes(admitted):
            raise CallBlocked("blocked", answer)
        execution = admitted.get("execution")
        if not isinstance(execution, dict) or not execution.get("handle"):
            raise MalformedAnswer("nothing to execute under", answer)
        return self._execute(
            replace(answer, outcome="OUTCOME_EXECUTE"), execution, arguments, run, gone
        )

    def _execute(
        self,
        answer: Answer,
        execution: dict[str, object],
        arguments: bytes,
        run: Callable[[bytes], Result | None],
        gone: Callable[[], object] | None,
    ) -> Answer:
        handle = str(execution["handle"])
        authorized = execution.get("authorizedArguments", b"")
        if not isinstance(authorized, bytes):
            raise TypeError("the reader left no bytes")
        if execution.get("obligations") and not self._is("ignores-obligations"):
            self._abort(answer, handle, "ABORT_CAUSE_OBLIGATION")
        if not authorized and arguments and not self._is("sends-proposed-when-empty"):
            self._abort(answer, handle, "ABORT_CAUSE_ARGUMENTS_DIFFER")
        if _left(gone) and not self._is("ignores-context"):
            self._abort(answer, handle, "ABORT_CAUSE_NOT_SENT")
        if self._is("sends-proposed") or not authorized:
            authorized = arguments
        started = self._clock()
        result: Result | None = None
        error: Exception | None = None
        try:
            result = run(bytes(authorized))
        except Exception as exc:
            error = exc
        ended = self._clock()
        not_sent = isinstance(error, NotSent)
        if (not_sent and not self._is("completes-when-not-sent")) or (
            error is not None and self._is("aborts-on-tool-error")
        ):
            self._abort(answer, handle, "ABORT_CAUSE_NOT_SENT")
        answer = replace(answer, ran=True, result=result)
        if not self._is("skips-complete"):
            report = {
                "handle": handle,
                "sentArguments": encoded(authorized),
                "status": self._status(result, error),
                "startedAt": stamp(result.started_at if result and result.started_at else started),
                "endedAt": stamp(result.ended_at if result and result.ended_at else ended),
                "resultHash": result.result_hash if result else "",
                "sideEffectConfirmation": result.side_effect_confirmation if result else "",
            }
            caller_left = _left(gone) and self._is("completes-under-caller-context")
            answer = self._complete(
                answer, {k: v for k, v in report.items() if v}, error, caller_left
            )
        if error is not None:
            raise error
        return answer

    def _status(self, result: Result | None, error: Exception | None) -> str:
        if isinstance(error, NotSent):
            return "COMPLETION_STATUS_FAILURE"
        if error is not None:
            return "COMPLETION_STATUS_UNKNOWN"
        if self._is("reports-success"):
            return "COMPLETION_STATUS_SUCCESS"
        if result is None or result.status not in STATUSES:
            return "COMPLETION_STATUS_UNKNOWN"
        return result.status

    def _complete(
        self, answer: Answer, report: dict[str, str], error: Exception | None, caller_left: bool
    ) -> Answer:
        try:
            if caller_left:
                raise UnansweredError("the caller's context is cancelled")
            try:
                ended = self._post("complete", report, ENDED)
            except RefusalError:
                if not self._is("retries-complete"):
                    raise
                ended = self._post("complete", report, ENDED)
        except (RefusalError, UnreadError, UnansweredError) as exc:
            raise _public(exc, answer) from error
        answer = replace(answer, ending=named(ended.get("ending")))
        if answer.ending != "ENDING_RECORDED":
            raise NotRecorded("not recorded", answer) from error
        return answer

    def _abort(self, answer: Answer, handle: str, cause: str) -> NoReturn:
        try:
            ended = self._post("abort", {"handle": handle, "cause": cause}, ENDED)
        except UnreadError as exc:
            raise _public(exc, answer) from exc
        except (RefusalError, UnansweredError) as exc:
            failure = _public(exc, answer)
            raise CallAborted("aborted", failure.answer, cause=cause) from failure
        raise CallAborted(
            "aborted", replace(answer, ending=named(ended.get("ending"))), cause=cause
        )


class RefusalError(Exception):
    """A receiver's error body under a status other than 200."""

    def __init__(self, status: int, body: dict[str, object]) -> None:
        super().__init__(f"refused with {status}")
        self.status = status
        self.code = named(body.get("code"))
        self.message = str(body.get("message", ""))
        self.ending = named(body.get("ending"))


def _version_read(decision: object) -> bool:
    """No decision, or one of major 1 and a minor of decimal digits within 32 bits."""
    if not isinstance(decision, dict):
        return True
    version = decision.get("schemaVersion", "")
    if not isinstance(version, str):
        return False
    minor = version[2:] if version.startswith("1.") else ""
    significant = minor.lstrip("0") or "0"
    return (
        minor.isascii()
        and minor.isdigit()
        and len(significant) <= len(str(UINT32_MAX))
        and int(significant) <= UINT32_MAX
    )


def _left(gone: Callable[[], object] | None) -> bool:
    if gone is None:
        return False
    try:
        return gone() is not False
    except Exception:
        return True


def _held(pending: object) -> Held:
    members = pending if isinstance(pending, dict) else {}
    expires, retry = members.get("expiresAt"), members.get("retryAfter")
    return Held(
        approval_id=str(members.get("approvalId", "")),
        action_digest=str(members.get("actionDigest", "")),
        expires_at=expires if isinstance(expires, datetime) else None,
        retry_after=retry if isinstance(retry, timedelta) else None,
    )


def _public(exc: Exception, answer: Answer) -> EnforceError:
    if isinstance(exc, RefusalError):
        return CallRefused(
            replace(answer, ending=exc.ending),
            status=exc.status,
            code=exc.code,
            message=exc.message,
        )
    if isinstance(exc, UnreadError):
        return MalformedAnswer(f"unread: {exc}", answer)
    return NoAnswer(f"unanswered: {exc}", answer)
