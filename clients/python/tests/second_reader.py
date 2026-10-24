"""The second client's reader of the answers, written apart from the module's.

It takes nothing from the module: the members of each message, the names of
each enum and the reading of their JSON are its own.
"""

from __future__ import annotations

import binascii
import json
import string
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

LIMIT = 262144
INT32_MIN, INT32_MAX = -2147483648, 2147483647
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
