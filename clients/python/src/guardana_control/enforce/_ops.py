"""The contract's three requests, one answer each, and every rule that needs no tool."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Final

from . import _wire
from ._schema import MESSAGES
from ._types import BLOCK, CONTRACT, EXECUTE, PENDING, Held, cut

# Posts a body to a path and returns the status and at most so many bytes of the answer.
Post = Callable[[str, bytes, int], tuple[int, bytes]]

OBLIGATION: Final = "ABORT_CAUSE_OBLIGATION"
ARGUMENTS_DIFFER: Final = "ABORT_CAUSE_ARGUMENTS_DIFFER"
NOT_SENT: Final = "ABORT_CAUSE_NOT_SENT"

_OK: Final = 200

# The major the generated Decision's package names, as the Go client reads it.
_DECISION_MAJOR: Final = (
    MESSAGES[_wire.ADMIT_RESPONSE]["decision"][2].split(".")[-2].removeprefix("v")
)
_DECIMAL: Final = re.compile(r"[0-9]+")
_UINT32_MAX: Final = 0xFFFFFFFF
_UINT32_DIGITS: Final = 10


class RefusalError(Exception):
    """A receiver's Error body under a status other than 200."""

    def __init__(self, status: int, code: str, message: str, ending: str) -> None:
        super().__init__(f"{status} {code or 'no code'}: {cut(message)!r}")
        self.status = status
        self.code = code
        self.message = message
        self.ending = ending


@dataclass(frozen=True)
class Admitted:
    """An admit answer as the client acts on it.

    outcome is EXECUTE only with a handle to close. abort_cause is set when
    the answer itself forbids the run; unreadable when it cannot be acted on.
    """

    outcome: str
    decision: Mapping[str, object] | None
    held: Held | None = None
    handle: str = ""
    authorized: bytes = b""
    abort_cause: str = ""
    unreadable: str = ""


@dataclass(frozen=True)
class Report:
    """What a complete says of one run."""

    status: str
    started_at: datetime
    ended_at: datetime
    result_hash: str = ""
    side_effect_confirmation: str = ""


def _name(value: object) -> str:
    """An enum as a word: empty for none and UNSPECIFIED, digits for an undeclared number."""
    if value is None or (isinstance(value, str) and value.endswith("_UNSPECIFIED")):
        return ""
    return str(value)


def _text(members: Mapping[str, object], name: str) -> str:
    value = members.get(name, "")
    return value if isinstance(value, str) else ""


def _nested(members: Mapping[str, object], name: str) -> Mapping[str, object]:
    value = members.get(name)
    return value if isinstance(value, dict) else {}


def _frozen(members: dict[str, object]) -> Mapping[str, object]:
    return MappingProxyType({name: _frozen_value(held) for name, held in members.items()})


def _frozen_value(value: object) -> object:
    if isinstance(value, dict):
        return _frozen(value)
    if isinstance(value, list):
        return tuple(_frozen_value(item) for item in value)
    return value


def _ask(
    post: Post, operation: str, request: bytes, response: str
) -> tuple[dict[str, object], dict[str, object]]:
    """The answer to one request, as written and as read; a refusal raises."""
    status, body = post(f"/enforce/{CONTRACT}/{operation}", request, _wire.MAX_ANSWER_BYTES + 1)
    if status == _OK:
        written = _wire.parse(body)
        return written, _wire.check(response, written)
    try:
        error = _wire.read(_wire.ERROR, body)
    except _wire.WireError as exc:
        raise _wire.WireError(f"status {status} with no readable error body: {exc}") from exc
    raise RefusalError(
        status, _name(error.get("code")), _text(error, "message"), _name(error.get("ending"))
    )


def _held(pending: Mapping[str, object]) -> Held:
    expires, retry = pending.get("expiresAt"), pending.get("retryAfter")
    return Held(
        approval_id=_text(pending, "approvalId"),
        action_digest=_text(pending, "actionDigest"),
        expires_at=expires if isinstance(expires, datetime) else None,
        retry_after=retry if isinstance(retry, timedelta) else None,
    )


def admit(post: Post, tool: str, arguments: bytes) -> Admitted:
    """Asks whether tool may act on arguments."""
    request = _wire.write(_wire.ADMIT_REQUEST, {"tool": tool, "arguments": arguments})
    written, answer = _ask(post, "admit", request, _wire.ADMIT_RESPONSE)
    wrote = written.get("decision")
    decision = _frozen(wrote) if isinstance(wrote, dict) else None
    if not _readable_decision(answer):
        return Admitted(
            BLOCK, decision, unreadable="a decision of a schema version this client does not read"
        )
    outcome = answer.get("outcome")
    if outcome == PENDING:
        return Admitted(PENDING, decision, held=_held(_nested(answer, "pending")))
    if outcome != EXECUTE:
        return Admitted(BLOCK, decision)
    execution = _nested(answer, "execution")
    handle = _text(execution, "handle")
    if not handle:
        # Nothing can be aborted without a handle, so nothing is sent.
        return Admitted(BLOCK, decision, unreadable="an EXECUTE answer with no handle")
    held = execution.get("authorizedArguments")
    authorized = held if isinstance(held, bytes) else b""
    cause = ""
    if execution.get("obligations"):
        cause = OBLIGATION
    elif not authorized and arguments:
        cause = ARGUMENTS_DIFFER
    return Admitted(EXECUTE, decision, handle=handle, authorized=authorized, abort_cause=cause)


def _readable_decision(answer: Mapping[str, object]) -> bool:
    """An answer with no decision is left to its outcome."""
    nested = answer.get("decision")
    if not isinstance(nested, Mapping):
        return True
    version = nested.get("schemaVersion", "")
    if not isinstance(version, str):
        return False
    major, dot, minor = version.partition(".")
    return bool(dot) and _decimal(major) and _decimal(minor) and major == _DECISION_MAJOR


def _decimal(text: str) -> bool:
    # Leading zeros are taken, as Go's ParseUint takes them; the rest is
    # bounded before int(), which refuses a string of thousands of digits.
    digits = text.lstrip("0") or "0"
    return (
        _DECIMAL.fullmatch(text) is not None
        and len(digits) <= _UINT32_DIGITS
        and int(digits) <= _UINT32_MAX
    )


def completion(handle: str, sent: bytes, report: Report) -> bytes:
    """The complete request that reports a run; writing it sends nothing."""
    return _wire.write(
        _wire.COMPLETE_REQUEST,
        {
            "handle": handle,
            "sentArguments": sent,
            "status": report.status,
            "startedAt": report.started_at,
            "endedAt": report.ended_at,
            "resultHash": report.result_hash,
            "sideEffectConfirmation": report.side_effect_confirmation,
        },
    )


def complete(post: Post, request: bytes) -> str:
    """Sends a written complete of a run that was entered; returns the ending the receiver named."""
    _, answer = _ask(post, "complete", request, _wire.COMPLETE_RESPONSE)
    return _name(answer.get("ending"))


def abort(post: Post, handle: str, cause: str) -> str:
    """Gives up an execution that was not entered; returns the ending the receiver named."""
    request = _wire.write(_wire.ABORT_REQUEST, {"handle": handle, "cause": cause})
    _, answer = _ask(post, "abort", request, _wire.ABORT_RESPONSE)
    return _name(answer.get("ending"))
