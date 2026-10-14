"""Reads an answer in the one form the receiver writes it, and writes a request."""

from __future__ import annotations

import base64
import codecs
import json
import re
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Final

from ._schema import ENUMS, MESSAGES
from ._types import cut

MAX_ANSWER_BYTES: Final = 262144

_INT32: Final = (-(2**31), 2**31 - 1)
_INT64: Final = (-(2**63), 2**63 - 1)
_DURATION_SECONDS: Final = 315576000000

_SURROGATE = re.compile("[\\ud800-\\udfff]")
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_TIMESTAMP = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z"
)
# Digits are counted where they are matched: the interpreter refuses to
# convert a string of thousands of them, and no value in range has more.
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})")
_DURATION = re.compile(r"(-?)(0|[1-9][0-9]{0,11})(?:\.([0-9]{1,9}))?s")


class WireError(Exception):
    """An answer this reader does not read; the text names what it met."""


def _message(suffix: str) -> str:
    """The one message of the table whose full name ends with suffix."""
    (name,) = [n for n in MESSAGES if n.endswith("." + suffix)]
    return name


ADMIT_REQUEST: Final = _message("enforce.v1alpha1.AdmitRequest")
ADMIT_RESPONSE: Final = _message("enforce.v1alpha1.AdmitResponse")
COMPLETE_REQUEST: Final = _message("enforce.v1alpha1.CompleteRequest")
COMPLETE_RESPONSE: Final = _message("enforce.v1alpha1.CompleteResponse")
ABORT_REQUEST: Final = _message("enforce.v1alpha1.AbortRequest")
ABORT_RESPONSE: Final = _message("enforce.v1alpha1.AbortResponse")
ERROR: Final = _message("enforce.v1alpha1.Error")


def _members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    members: dict[str, object] = {}
    for name, value in pairs:
        if name in members:
            raise WireError(f"member {cut(name)!r} is repeated")
        members[name] = value
    return members


def _constant(name: str) -> object:
    raise WireError(f"{name} is no JSON number")


def parse(body: bytes) -> dict[str, object]:
    """The JSON object body holds, read strictly; no member is checked yet."""
    if len(body) > MAX_ANSWER_BYTES:
        raise WireError(f"more than {MAX_ANSWER_BYTES} bytes")
    if body.startswith(codecs.BOM_UTF8):
        raise WireError("a byte order mark")
    try:
        # Bytes handed to the decoder would be sniffed for UTF-16 and UTF-32.
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WireError(f"not UTF-8: {exc.reason}") from exc
    try:
        value = json.loads(text, object_pairs_hook=_members, parse_constant=_constant)
    except RecursionError as exc:
        raise WireError("nested too deeply") from exc
    except ValueError as exc:
        raise WireError(f"not JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise WireError("not a JSON object")
    return value


def _string(value: object, at: str, _type: str = "") -> str:
    if not isinstance(value, str):
        raise WireError(f"{at}: not a string")
    if _SURROGATE.search(value):
        raise WireError(f"{at}: a lone surrogate")
    return value


def _bool(value: object, at: str, _type: str) -> bool:
    if not isinstance(value, bool):
        raise WireError(f"{at}: not true or false")
    return value


def _enum(value: object, at: str, type_name: str) -> str | int:
    names = ENUMS[type_name]
    short = type_name.rpartition(".")[2]
    if isinstance(value, str):
        if value not in names:
            raise WireError(f"{at}: {cut(value)!r} is no name of {short}")
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise WireError(f"{at}: neither a name of {short} nor an integer")
    if not _INT32[0] <= value <= _INT32[1]:
        raise WireError(f"{at}: {cut(str(value))} is outside int32")
    return next((name for name, number in names.items() if number == value), value)


def _int64(value: object, at: str, _type: str) -> int:
    if not isinstance(value, str) or not _INTEGER.fullmatch(value):
        raise WireError(f"{at}: not an int64 in a decimal string")
    number = int(value)
    if not _INT64[0] <= number <= _INT64[1]:
        raise WireError(f"{at}: outside int64")
    return number


def _bytes(value: object, at: str, _type: str) -> bytes:
    if not isinstance(value, str) or not _BASE64.fullmatch(value):
        raise WireError(f"{at}: not padded standard base64")
    return base64.b64decode(value, validate=True)


def _timestamp(value: object, at: str, _type: str) -> datetime:
    found = _TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if found is None:
        raise WireError(f"{at}: not an RFC 3339 time ending in Z")
    year, month, day, hour, minute, second = (int(part) for part in found.groups()[:6])
    micros = int((found.group(7) or "").ljust(9, "0")) // 1000
    try:
        return datetime(year, month, day, hour, minute, second, micros, tzinfo=UTC)
    except ValueError as exc:
        raise WireError(f"{at}: no such time: {exc}") from exc


def _duration(value: object, at: str, _type: str) -> timedelta:
    found = _DURATION.fullmatch(value) if isinstance(value, str) else None
    if found is None:
        raise WireError(f"{at}: not a Duration in decimal seconds ending in s")
    seconds, nanos = int(found.group(2)), int((found.group(3) or "").ljust(9, "0"))
    if seconds > _DURATION_SECONDS or (seconds == _DURATION_SECONDS and nanos):
        raise WireError(f"{at}: outside a Duration's range")
    span = timedelta(seconds=seconds, microseconds=nanos // 1000)
    return -span if found.group(1) else span


def _nested(value: object, at: str, type_name: str) -> dict[str, object]:
    return check(type_name, value, at + ".")


_ONE: Final[Mapping[str, Callable[[object, str, str], object]]] = {
    "string": _string,
    "bool": _bool,
    "enum": _enum,
    "int64": _int64,
    "bytes": _bytes,
    "timestamp": _timestamp,
    "duration": _duration,
    "message": _nested,
}


def _member(value: object, at: str, declared: tuple[str, str, str]) -> object:
    kind, shape, type_name = declared
    one = _ONE.get(kind)
    if one is None or shape not in ("one", "list", "map"):
        raise WireError(f"{at}: no rule for a {shape} of {kind}")
    if value is None:
        raise WireError(f"{at}: null")
    if shape == "one":
        return one(value, at, type_name)
    if shape == "list":
        if not isinstance(value, list):
            raise WireError(f"{at}: not a list")
        return tuple(_item(item, f"{at}[{i}]", one, type_name) for i, item in enumerate(value))
    if not isinstance(value, dict):
        raise WireError(f"{at}: not an object")
    return {
        _string(key, at): _item(item, f"{at}.{cut(key)}", one, type_name)
        for key, item in value.items()
    }


def _item(
    value: object, at: str, one: Callable[[object, str, str], object], type_name: str
) -> object:
    if value is None:
        raise WireError(f"{at}: null")
    return one(value, at, type_name)


def check(message: str, value: object, at: str = "") -> dict[str, object]:
    """value as a message of the table, each member converted by its kind."""
    if not isinstance(value, dict):
        raise WireError(f"{at.rstrip('.') or 'the answer'}: not an object")
    declared = MESSAGES[message]
    read: dict[str, object] = {}
    for name, held in value.items():
        if name not in declared:
            short = message.rpartition(".")[2]
            raise WireError(f"{at}{cut(name)}: no member of {short}")
        read[name] = _member(held, at + name, declared[name])
    return read


def read(message: str, body: bytes) -> dict[str, object]:
    """body as a message of the table."""
    return check(message, parse(body))


def _write_string(value: object, at: str, _type: str) -> object:
    if not isinstance(value, str):
        raise TypeError(f"{at}: not a string")
    return value or None


def _write_bytes(value: object, at: str, _type: str) -> object:
    if not isinstance(value, bytes):
        raise TypeError(f"{at}: not bytes")
    return base64.b64encode(value).decode("ascii") or None


def _write_enum(value: object, at: str, type_name: str) -> object:
    if not isinstance(value, str) or value not in ENUMS[type_name]:
        raise TypeError(f"{at}: {value!r} is no name of its enum")
    return value if ENUMS[type_name][value] else None


def _write_timestamp(value: object, at: str, _type: str) -> object:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise TypeError(f"{at}: not an aware time")
    utc = value.astimezone(UTC)
    micros = utc.microsecond
    fraction = ""
    if micros:
        fraction = f".{micros:06d}" if micros % 1000 else f".{micros // 1000:03d}"
    return (
        f"{utc.year:04d}-{utc.month:02d}-{utc.day:02d}"
        f"T{utc.hour:02d}:{utc.minute:02d}:{utc.second:02d}{fraction}Z"
    )


_WRITE: Final[Mapping[str, Callable[[object, str, str], object]]] = {
    "string": _write_string,
    "bytes": _write_bytes,
    "enum": _write_enum,
    "timestamp": _write_timestamp,
}


def write(message: str, values: Mapping[str, object]) -> bytes:
    """values as a request message: JSON names, a default value left out."""
    declared = MESSAGES[message]
    members: dict[str, object] = {}
    for name, value in values.items():
        kind, _, type_name = declared[name]
        written = _WRITE[kind](value, name, type_name)
        if written is not None:
            members[name] = written
    return json.dumps(members, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
