"""The answer vectors of the shared files, for the client and for the second client."""

from __future__ import annotations

import unittest
from collections.abc import Callable
from dataclasses import dataclass

from guardana_control.enforce import Result, Status
from tests import cases, harness
from tests.test_conformance import method_name, reference, second

TOOL = "refund"
ARGUMENTS = b'{"amount":10,"to":"acct-7"}'
RUN = "run-token-1"

# Every may_refuse vector is one the client refuses: it reads no null, no
# snake_case name, no enum or int64 written as a float, no base64 outside the
# padded standard alphabet, no time but RFC 3339 with Z, and no duration
# without whole seconds and a fraction after its point.
REFUSED_BY_THE_CLIENT = (
    "abort-ending-float",
    "abort-ending-null",
    "admit-base64-carriage-return",
    "admit-base64-newline",
    "admit-base64-unpadded",
    "admit-base64-url-safe",
    "admit-base64-url-safe-unpadded",
    "admit-duration-bare-point",
    "admit-duration-plus-sign",
    "admit-duration-without-whole-seconds",
    "admit-int64-as-a-number",
    "admit-int64-exponent",
    "admit-int64-exponent-in-a-string",
    "admit-int64-float",
    "admit-int64-float-in-a-string",
    "admit-null-authorized-arguments",
    "admit-null-decision",
    "admit-null-in-execution",
    "admit-null-outcome",
    "admit-null-pending",
    "admit-outcome-exponent",
    "admit-outcome-float",
    "admit-outcome-float-block",
    "admit-refusal-snake-case",
    "admit-snake-case-names",
    "admit-timestamp-comma-fraction",
    "admit-timestamp-numeric-offset",
    "admit-timestamp-one-digit-hour",
    "admit-timestamp-zero-offset",
    "complete-ending-float",
    "complete-ending-null",
)


@dataclass(frozen=True)
class Vector:
    """One line of answers/vectors.jsonl."""

    id: str
    operation: str
    status: int
    body: bytes
    kind: str
    expect: dict[str, object]


def expand(parts: object) -> bytes:
    """The body raw_repeat spells: each part's text, so many times, in order."""
    if not isinstance(parts, list) or not parts:
        raise ValueError("raw_repeat is no list of parts")
    body = bytearray()
    for part in parts:
        members = harness.as_object(part, "a part of raw_repeat")
        text, times = members.get("text"), members.get("times")
        if set(members) != {"text", "times"} or not isinstance(text, str) or not text:
            raise ValueError("a part of raw_repeat needs a text and its times, and nothing else")
        if isinstance(times, bool) or not isinstance(times, int) or times < 1:
            raise ValueError(f"a part of raw_repeat is repeated {times!r} times")
        if len(text.encode("utf-8")) * times > harness.MAX_VECTOR_BODY - len(body):
            raise ValueError("raw_repeat spells a body over 1 MiB")
        body += text.encode("utf-8") * times
    return bytes(body)


def vector_of(line: dict[str, object]) -> Vector:
    """line as a vector; a member this harness does not know is refused."""
    if set(line) - {"id", "for", "status", "raw", "raw_repeat", "class", "expect"}:
        raise ValueError(f"vector {line.get('id')!r} names a member this harness does not know")
    if ("raw" in line) == ("raw_repeat" in line):
        raise ValueError(f"vector {line.get('id')!r} needs exactly one of raw and raw_repeat")
    if "raw" in line:
        body = harness.as_text(line["raw"], "raw").encode("utf-8")
    else:
        body = expand(line["raw_repeat"])
    if len(body) > harness.MAX_VECTOR_BODY:
        raise ValueError(f"vector {line.get('id')!r} holds a body over 1 MiB")
    status, operation, kind = line["status"], line["for"], line["class"]
    if isinstance(status, bool) or not isinstance(status, int):
        raise ValueError(f"status {status!r}")
    if operation not in harness.PATHS or kind not in ("read", "refused", "may_refuse"):
        raise ValueError(f"vector {line.get('id')!r} is for {operation!r}, of class {kind!r}")
    expect = harness.as_object(line["expect"], "expect")
    known = {"tool_reached", "tool_received", "requests", "returns", "code", "ending"}
    if set(expect) - known or not isinstance(expect.get("tool_reached"), bool):
        raise ValueError(f"vector {line.get('id')!r}: expect needs tool_reached and known members")
    return Vector(
        id=harness.as_text(line["id"], "id"),
        operation=harness.as_text(operation, "for"),
        status=status,
        body=body,
        kind=harness.as_text(kind, "class"),
        expect=expect,
    )


def load_vectors() -> list[Vector]:
    return [
        vector_of(line)
        for line in harness.read_lines(harness.TESTDATA / "answers" / "vectors.jsonl")
    ]


def script_of(vector: Vector) -> list[harness.Scripted]:
    """The vector's own answer, after the admit answer of the case that leads to it."""
    # A redirect names a place to go, so that a client that follows one is seen to.
    location = harness.ADMIT if str(vector.status).startswith("3") else ""
    own = harness.Scripted(
        harness.PATHS[vector.operation], vector.status, vector.body, location=location
    )
    leading = {"admit": None, "complete": "execute-plain", "abort": "unknown-obligation"}
    case = leading[vector.operation]
    return [own] if case is None else [cases.load_script(case)[0], own]


def run_vector(make: harness.Maker, vector: Vector) -> cases.Told:
    """Makes the vectors' one call and returns what it told its caller."""
    reached: list[bytes] = []

    def tool(authorized: bytes) -> Result:
        reached.append(bytes(authorized))
        return Result(Status.SUCCESS)

    receiver = harness.Receiver(script_of(vector), goes_on=vector.operation == "admit")
    try:
        client = make(receiver.socket, RUN, lambda: harness.AFTER if reached else harness.BEFORE)
        outcome = cases.attempt(client, TOOL, ARGUMENTS, tool)
        requests = receiver.requests()
    finally:
        receiver.close()
    if isinstance(outcome, BaseException):
        told = cases.describe(None, outcome, None)
    else:
        told = cases.describe(outcome, None, None)
    told.reached, told.requests = bool(reached), requests
    told.received = reached[0] if reached else None
    return told


def as_expected(vector: Vector) -> dict[str, object]:
    """What a client that reads the vector does."""
    expect = vector.expect
    received = expect.get("tool_received")
    return {
        "reached": expect["tool_reached"],
        "received": received.encode("utf-8") if isinstance(received, str) else None,
        "requests": expect["requests"],
        "returns": expect["returns"],
        "code": expect.get("code", ""),
        "ending": expect.get("ending", ""),
    }


def as_refused(vector: Vector) -> dict[str, object]:
    """What a client that refuses the vector does: nothing after the answer it did not read."""
    requests = {
        "admit": ["admit"],
        "complete": ["admit", "complete"],
        "abort": ["admit", "abort"],
    }[vector.operation]
    reached = vector.operation == "complete"
    return {
        "reached": reached,
        "received": ARGUMENTS if reached else None,
        "requests": requests,
        "returns": "malformed_answer",
        "code": "",
        "ending": "",
    }


def behaviour(told: cases.Told) -> dict[str, object]:
    """What the client did, in the shape of an expectation."""
    operations = {path: name for name, path in harness.PATHS.items()}
    return {
        "reached": told.reached,
        "received": told.received,
        "requests": [operations.get(request.path, request.path) for request in told.requests],
        "returns": told.kind,
        "code": told.code,
        "ending": told.ending,
    }


def request_misses(told: cases.Told) -> list[str]:
    misses: list[str] = []
    for number, request in enumerate(told.requests, start=1):
        misses += cases.request_misses(number, request, RUN)
    return misses


def _reads(
    make: harness.Maker, vector: Vector, pinned: bool
) -> Callable[[unittest.TestCase], None]:
    def test(self: unittest.TestCase) -> None:
        told = run_vector(make, vector)
        self.assertEqual(request_misses(told), [])
        did = behaviour(told)
        if vector.kind == "refused":
            self.assertEqual(vector.expect["returns"], "malformed_answer")
        if vector.kind != "may_refuse":
            self.assertEqual(did, as_expected(vector), repr(told.error))
        elif pinned:
            refuses = vector.id in REFUSED_BY_THE_CLIENT
            want = as_refused(vector) if refuses else as_expected(vector)
            self.assertEqual(did, want, repr(told.error))
        else:
            self.assertIn(did, (as_expected(vector), as_refused(vector)), repr(told.error))

    return test


class ReferenceClient(unittest.TestCase):
    """The client reads every vector as expected and refuses the ones it is pinned to refuse."""


class SecondClient(unittest.TestCase):
    """The second client reads every vector as expected, or refuses where a client may."""


for _vector in load_vectors():
    setattr(ReferenceClient, method_name(_vector.id), _reads(reference, _vector, True))
    setattr(SecondClient, method_name(_vector.id), _reads(second(), _vector, False))


class VectorFile(unittest.TestCase):
    """The file is what this harness takes it for, and the harness refuses what it is not."""

    def test_the_file_holds_every_kind_of_vector_once(self) -> None:
        vectors = load_vectors()
        ids = [vector.id for vector in vectors]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len({method_name(i) for i in ids}), len(ids))
        held = {(v.operation, v.kind) for v in vectors}
        kinds = ("read", "refused", "may_refuse")
        self.assertEqual(held, {(o, k) for o in harness.PATHS for k in kinds})

    def test_the_pinned_refusals_are_the_files_may_refuse_vectors(self) -> None:
        may = sorted(v.id for v in load_vectors() if v.kind == "may_refuse")
        self.assertEqual(sorted(REFUSED_BY_THE_CLIENT), may)

    def test_a_vector_with_both_bodies_or_neither_is_refused(self) -> None:
        line: dict[str, object] = {
            "id": "x",
            "for": "admit",
            "status": 200,
            "class": "read",
            "expect": {"tool_reached": False, "requests": ["admit"], "returns": "blocked"},
        }
        part: dict[str, object] = {"text": "{}", "times": 1}
        self.assertEqual(vector_of({**line, "raw": "{}"}).body, b"{}")
        self.assertEqual(vector_of({**line, "raw_repeat": [part]}).body, b"{}")
        with self.assertRaisesRegex(ValueError, "exactly one of raw and raw_repeat"):
            vector_of(line)
        with self.assertRaisesRegex(ValueError, "exactly one of raw and raw_repeat"):
            vector_of({**line, "raw": "{}", "raw_repeat": [part]})
        with self.assertRaisesRegex(ValueError, "does not know"):
            vector_of({**line, "raw": "{}", "body": {}})

    def test_raw_repeat_joins_its_parts_in_order(self) -> None:
        parts = [
            {"text": "ab", "times": 2},
            {"text": "c", "times": 3},
            {"text": "\u00e9", "times": 1},
        ]
        self.assertEqual(expand(parts), b"ababccc\xc3\xa9")

    def test_raw_repeat_refuses_an_empty_text_and_no_repetition(self) -> None:
        for parts in (
            [{"text": "", "times": 1}],
            [{"text": "a", "times": 0}],
            [{"text": "a", "times": -1}],
            [{"text": "a", "times": True}],
            [{"text": "a", "times": 1.0}],
            [{"text": "a"}],
            [{"text": "a", "times": 1, "more": 1}],
            [],
            "a",
        ):
            with self.subTest(parts=parts), self.assertRaises(ValueError):
                expand(parts)

    def test_raw_repeat_refuses_a_body_over_a_mebibyte(self) -> None:
        self.assertEqual(len(expand([{"text": "a", "times": 1048576}])), 1048576)
        with self.assertRaisesRegex(ValueError, "over 1 MiB"):
            expand([{"text": "a", "times": 1048577}])
        with self.assertRaisesRegex(ValueError, "over 1 MiB"):
            expand([{"text": "ab", "times": 524288}, {"text": "a", "times": 1}])
        line: dict[str, object] = {
            "id": "x",
            "for": "admit",
            "status": 200,
            "class": "read",
            "expect": {"tool_reached": False, "requests": ["admit"], "returns": "blocked"},
        }
        with self.assertRaisesRegex(ValueError, "over 1 MiB"):
            vector_of({**line, "raw": "a" * 1048577})
