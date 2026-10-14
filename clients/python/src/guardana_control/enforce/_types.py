"""The values a call hands back and the exceptions it raises."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

CONTRACT: Final = "v1alpha1"

EXECUTE: Final = "OUTCOME_EXECUTE"
BLOCK: Final = "OUTCOME_BLOCK"
PENDING: Final = "OUTCOME_PENDING"
RECORDED: Final = "ENDING_RECORDED"

_QUOTED: Final = 120


class Status:
    """The completion statuses a tool may report."""

    SUCCESS: Final = "COMPLETION_STATUS_SUCCESS"
    FAILURE: Final = "COMPLETION_STATUS_FAILURE"
    TIMEOUT: Final = "COMPLETION_STATUS_TIMEOUT"
    CANCELLED: Final = "COMPLETION_STATUS_CANCELLED"
    UNKNOWN: Final = "COMPLETION_STATUS_UNKNOWN"


@dataclass(frozen=True)
class Result:
    """What the tool reports of one run.

    An empty status, or one the contract does not declare, is completed as
    UNKNOWN. value is handed back to the caller and never sent. A time left
    as None is read from the client's clock; one given must be aware.
    """

    status: str = ""
    value: object = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    result_hash: str = ""
    side_effect_confirmation: str = ""


@dataclass(frozen=True)
class Held:
    """A PENDING answer: who decides, and when to ask again.

    Both times keep microseconds: digits the receiver wrote past them are dropped.
    """

    approval_id: str
    action_digest: str
    expires_at: datetime | None
    retry_after: timedelta | None


@dataclass(frozen=True)
class Answer:
    """What one call learned.

    outcome is the admit outcome as the client read it, so anything but
    EXECUTE or PENDING reads as BLOCK. decision is the receiver's decision
    as it wrote it, by JSON name. ran says the tool was entered, so an effect
    may have happened. ending is the receiver's word on the closing record,
    empty when it named none.
    """

    outcome: str
    decision: Mapping[str, object] | None
    held: Held | None
    ran: bool
    result: Result | None
    ending: str


def cut(text: str) -> str:
    """text as a message may quote it: a receiver's own words can be as long as its answer."""
    if len(text) <= _QUOTED:
        return text
    return f"{text[:_QUOTED]}... (cut from {len(text)} characters)"


# The interface names these after what happened to the call, so none of them
# carries the Error suffix the linter asks of an exception.
class NotSent(Exception):  # noqa: N818
    """Raised by a tool, and only by a tool, to say its bytes never left."""


class EnforceError(Exception):
    """Every exception of the module; answer says whether the tool ran."""

    def __init__(self, message: str, answer: Answer) -> None:
        super().__init__(message)
        self.answer = answer


class CallerGone(EnforceError):  # noqa: N818
    """The caller was gone before admit; nothing was sent."""


class CallBlocked(EnforceError):  # noqa: N818
    """The answer was BLOCK, UNSPECIFIED or an outcome this client does not know."""


class CallPending(EnforceError):  # noqa: N818
    """The call is held for an approval; answer.held says when to ask again."""


class CallRefused(EnforceError):  # noqa: N818
    """A receiver's Error body under a status other than 200; message is its message, whole."""

    def __init__(self, answer: Answer, *, status: int, code: str, message: str) -> None:
        super().__init__(
            f"the receiver refused the request: {status} {code or 'no code'}: {cut(message)!r}",
            answer,
        )
        self.status = status
        self.code = code
        self.message = message


class MalformedAnswer(EnforceError):  # noqa: N818
    """An answer this client does not read; nothing is run on it."""


class CallAborted(EnforceError):  # noqa: N818
    """The execution was aborted; the tool did not run."""

    def __init__(self, message: str, answer: Answer, *, cause: str) -> None:
        super().__init__(message, answer)
        self.cause = cause


class NotRecorded(EnforceError):  # noqa: N818
    """The tool ran; the closing record is not known to have landed."""


class NoAnswer(EnforceError):  # noqa: N818
    """A request got no answer in time."""


class BadResult(EnforceError, TypeError):  # noqa: N818
    """The tool ran and returned what cannot be reported; its complete said UNKNOWN."""


class ToolRaised(EnforceError):  # noqa: N818
    """The tool ran and raised an exception of this module, kept as __cause__.

    answer is this call's own, so it says the tool ran whatever the cause's says.
    """
