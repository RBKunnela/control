"""A second client, written apart from the first, that breaks one rule when told to.

It takes from the module only the public result and exception types: the
socket code, the reading and the members of each message are its own.
"""

from __future__ import annotations

import binascii
import http.client
import json
import socket
import string
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

LIMIT = 262144
INT32_MIN, INT32_MAX = -2147483648, 2147483647
UINT32_MAX = 4294967295
INT64_MIN, INT64_MAX = -9223372036854775808, 9223372036854775807
LONGEST_SPAN = 315576000000
# No value in range has more digits, and the interpreter converts no string of thousands.
INT64_DIGITS = 19
SPAN_DIGITS = 12
NANO_DIGITS = 9
MOST_PADDING = 2
BASE64 = frozenset(string.ascii_letters + string.digits + "+/")
SURROGATES = frozenset(map(chr, range(0xD800, 0xE000)))

OUTCOMES = ("OUTCOME_UNSPECIFIED", "OUTCOME_EXECUTE", "OUTCOME_BLOCK", "OUTCOME_PENDING")
ENDINGS = (
    "ENDING_UNSPECIFIED",
    "ENDING_RECORDED",
    "ENDING_RECORD_FAILED",
    "ENDING_UNRECORDED",
    "ENDING_ABANDONED",
)
CODES = (
    "ERROR_CODE_UNSPECIFIED",
    "ERROR_CODE_UNAUTHENTICATED",
    "ERROR_CODE_MALFORMED",
    "ERROR_CODE_UNSUPPORTED_VERSION",
    "ERROR_CODE_HANDLE_UNKNOWN",
    "ERROR_CODE_HANDLE_SPENT",
    "ERROR_CODE_DUPLICATE_REQUEST",
    "ERROR_CODE_UNAVAILABLE",
)
VERDICTS = (
    "VERDICT_UNSPECIFIED",
    "VERDICT_ALLOW",
    "VERDICT_DENY",
    "VERDICT_REQUIRE_APPROVAL",
    "VERDICT_ALLOW_WITH_OBLIGATIONS",
    "VERDICT_INDETERMINATE",
)
MODES = (
    "ENFORCEMENT_MODE_UNSPECIFIED",
    "ENFORCEMENT_MODE_OBSERVE",
    "ENFORCEMENT_MODE_SHADOW",
    "ENFORCEMENT_MODE_WARN",
    "ENFORCEMENT_MODE_APPROVE",
    "ENFORCEMENT_MODE_ENFORCE",
    "ENFORCEMENT_MODE_LOCKDOWN",
)
FRESHNESS = ("POLICY_FRESHNESS_UNSPECIFIED", "POLICY_FRESHNESS_FRESH", "POLICY_FRESHNESS_STALE")
STATUSES = (
    "COMPLETION_STATUS_SUCCESS",
    "COMPLETION_STATUS_FAILURE",
    "COMPLETION_STATUS_TIMEOUT",
    "COMPLETION_STATUS_CANCELLED",
    "COMPLETION_STATUS_UNKNOWN",
)


class UnreadError(Exception):
    """An answer the second client does not read."""


class UnansweredError(Exception):
    """A request the second client got no answer to."""


Reader = Callable[[object, bool], object]
Members = dict[str, Reader]

# What a lenient reader makes of an enum name it does not know.
SKIPPED = object()


def digits(text: str) -> bool:
    return text.isascii() and text.isdigit()


def text_of(value: object, _lenient: bool) -> str:
    if type(value) is not str:
        raise UnreadError("no string")
    if any(char in SURROGATES for char in value):
        raise UnreadError("half of a surrogate pair")
    return value


def flag_of(value: object, _lenient: bool) -> bool:
    if not isinstance(value, bool):
        raise UnreadError("no boolean")
    return value


def integer_of(value: object, _lenient: bool) -> int:
    if type(value) is not str:
        raise UnreadError("an int64 outside a string")
    unsigned = value.removeprefix("-")
    if not digits(unsigned) or (unsigned != "0" and unsigned.startswith("0")):
        raise UnreadError("no decimal integer")
    if len(unsigned) > INT64_DIGITS or not INT64_MIN <= int(value) <= INT64_MAX:
        raise UnreadError("past int64")
    return int(value)


def octets_of(value: object, _lenient: bool) -> bytes:
    if type(value) is not str:
        raise UnreadError("bytes outside a string")
    # The decoder's own strictness differs between interpreter versions.
    unpadded = value.rstrip("=")
    padding = len(value) - len(unpadded)
    if len(value) % 4 or padding > MOST_PADDING or not BASE64.issuperset(unpadded):
        raise UnreadError("no padded standard base64")
    return binascii.a2b_base64(value.encode("ascii"))


def instant_of(value: object, _lenient: bool) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise UnreadError("no time ending in Z")
    clock, point, fraction = value[:-1].partition(".")
    if point and not (digits(fraction) and len(fraction) <= NANO_DIGITS):
        raise UnreadError("a fraction of no or too many digits")
    shape = "".join("0" if digits(char) else char for char in clock)
    if shape != "0000-00-00T00:00:00":
        raise UnreadError("no RFC 3339 time")
    numbers = [int(part) for part in clock.replace("T", "-").replace(":", "-").split("-")]
    try:
        year, month, day, hour, minute, second = numbers
        micros = int(fraction.ljust(NANO_DIGITS, "0")[:6])
        return datetime(year, month, day, hour, minute, second, micros, tzinfo=UTC)
    except ValueError as exc:
        raise UnreadError(f"no such time: {exc}") from exc


def span_of(value: object, _lenient: bool) -> timedelta:
    if type(value) is not str or not value.endswith("s"):
        raise UnreadError("no seconds ending in s")
    whole, point, fraction = value[:-1].removeprefix("-").partition(".")
    if not digits(whole) or (whole != "0" and whole.startswith("0")):
        raise UnreadError("no whole seconds")
    if point and not (digits(fraction) and len(fraction) <= NANO_DIGITS):
        raise UnreadError("a fraction of no or too many digits")
    nanos = int(fraction.ljust(NANO_DIGITS, "0"))
    past = len(whole) > SPAN_DIGITS or int(whole) > LONGEST_SPAN
    if past or (int(whole) == LONGEST_SPAN and nanos):
        raise UnreadError("past a Duration")
    span = timedelta(seconds=int(whole), microseconds=nanos // 1000)
    return -span if value.startswith("-") else span


def one_of(names: tuple[str, ...]) -> Reader:
    def read(value: object, lenient: bool) -> object:
        if type(value) is str:
            if value in names:
                return value
            if lenient:
                return SKIPPED
            raise UnreadError(f"no declared name: {value}")
        if type(value) is not int or value < INT32_MIN or value > INT32_MAX:
            raise UnreadError("neither a name nor an int32")
        return names[value] if 0 <= value < len(names) else value

    return read


def each(reader: Reader) -> Reader:
    def read(value: object, lenient: bool) -> object:
        if type(value) is not list:
            raise UnreadError("no list")
        return [reader(item, lenient) for item in value]

    return read


def keyed(reader: Reader) -> Reader:
    def read(value: object, lenient: bool) -> object:
        if type(value) is not dict:
            raise UnreadError("no map")
        return {text_of(key, lenient): reader(item, lenient) for key, item in value.items()}

    return read


def message(members: Members) -> Reader:
    def read(value: object, lenient: bool) -> object:
        if type(value) is not dict:
            raise UnreadError("no object")
        held: dict[str, object] = {}
        for name, item in value.items():
            if name not in members:
                if lenient:
                    continue
                raise UnreadError(f"no such member: {name}")
            if item is None:
                raise UnreadError(f"null in {name}")
            got = members[name](item, lenient)
            if got is not SKIPPED:
                held[name] = got
        return held

    return read


OBLIGATION: Members = {"type": text_of, "params": keyed(text_of), "advisory": flag_of}
DECISION: Members = {
    "schemaVersion": text_of,
    "decisionId": text_of,
    "requestId": text_of,
    "actionDigest": text_of,
    "policyBundleDigest": text_of,
    "policyRuleIds": each(text_of),
    "verdict": one_of(VERDICTS),
    "reasonCodes": each(text_of),
    "obligations": each(message(OBLIGATION)),
    "expiresAt": instant_of,
    "decisionLatencyUs": integer_of,
    "pdpType": text_of,
    "pdpInstance": text_of,
    "pdpVersion": text_of,
    "enforcementMode": one_of(MODES),
    "policyFreshness": one_of(FRESHNESS),
    "policyLoadedAt": instant_of,
    "decidedAt": instant_of,
}
EXECUTION: Members = {
    "handle": text_of,
    "expiresAt": instant_of,
    "authorizedArguments": octets_of,
    "obligations": each(message(OBLIGATION)),
}
PENDING: Members = {
    "approvalId": text_of,
    "actionDigest": text_of,
    "expiresAt": instant_of,
    "retryAfter": span_of,
}
ADMITTED = message(
    {
        "outcome": one_of(OUTCOMES),
        "decision": message(DECISION),
        "execution": message(EXECUTION),
        "pending": message(PENDING),
    }
)
ENDED = message({"ending": one_of(ENDINGS)})
REFUSED = message({"code": one_of(CODES), "message": text_of, "ending": one_of(ENDINGS)})


def once(pairs: list[tuple[str, object]]) -> dict[str, object]:
    members = dict(pairs)
    if len(members) != len(pairs):
        raise UnreadError("a member named twice")
    return members


def no_number(text: str) -> object:
    raise UnreadError(f"no integer: {text}")


def decode(body: bytes, reader: Reader, lenient: bool) -> dict[str, object]:
    if len(body) > LIMIT:
        raise UnreadError("past the bound")
    try:
        text = str(body, "utf-8", "strict")
        if text.startswith("\ufeff"):
            raise UnreadError("a byte order mark")
        value = json.loads(
            text, object_pairs_hook=once, parse_float=no_number, parse_constant=no_number
        )
    except (ValueError, RecursionError) as exc:
        raise UnreadError(f"no JSON: {exc}") from exc
    read = reader(value, lenient)
    if not isinstance(read, dict):
        raise UnreadError("no object")
    return read


def named(value: object) -> str:
    """An enum as text: nothing for an absent or unspecified one."""
    if value is None or (isinstance(value, str) and value.endswith("_UNSPECIFIED")):
        return ""
    return str(value)


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
