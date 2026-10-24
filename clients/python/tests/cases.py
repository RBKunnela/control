"""The client cases of the shared files, and the comparison every client is held to.

Nothing here reads the client's reader, its table or its transport: the declared
names are spelled out, and a request is compared with its expectation as a JSON value.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime

from guardana_control.enforce import (
    Answer,
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
)
from tests.harness import (
    ABORT,
    AFTER,
    AFTER_TEXT,
    BEFORE,
    BEFORE_TEXT,
    COMPLETE,
    TESTDATA,
    Caller,
    Gone,
    Got,
    Maker,
    Receiver,
    Scripted,
    Tool,
    as_object,
    as_text,
    read_lines,
    read_object,
    strict_json,
)

DECLARED_ENDINGS = (
    "ENDING_RECORDED",
    "ENDING_RECORD_FAILED",
    "ENDING_UNRECORDED",
    "ENDING_ABANDONED",
)
DECLARED_CODES = (
    "ERROR_CODE_UNAUTHENTICATED",
    "ERROR_CODE_MALFORMED",
    "ERROR_CODE_UNSUPPORTED_VERSION",
    "ERROR_CODE_HANDLE_UNKNOWN",
    "ERROR_CODE_HANDLE_SPENT",
    "ERROR_CODE_DUPLICATE_REQUEST",
    "ERROR_CODE_UNAVAILABLE",
)

_RFC3339_Z = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{3}|\.[0-9]{6}|\.[0-9]{9})?Z"
)


@dataclass
class Told:
    """What one call told its caller, in the words of the shared files."""

    kind: str = ""
    code: str = ""
    ending: str = ""
    approval_id: str = ""
    retry_after: str = ""
    reached: bool = False
    received: bytes | None = None
    answer: Answer | None = None
    error: BaseException | None = None
    requests: list[Got] = field(default_factory=list)


def _kind(error: BaseException | None, tool_error: BaseException | None) -> str:
    kinds: tuple[tuple[type[BaseException], str], ...] = (
        (MalformedAnswer, "malformed_answer"),
        (CallAborted, "aborted"),
        (CallRefused, "refused"),
        (CallPending, "pending"),
        (CallBlocked, "blocked"),
        (NotRecorded, "not_recorded"),
        (NoAnswer, "transport"),
        (CallerGone, "caller_gone"),
    )
    if error is None:
        return "none"
    if error is tool_error:
        return "tool_error"
    for kind_type, name in kinds:
        if isinstance(error, kind_type):
            return name
    return f"another exception: {error!r}"


def _declared(name: str, names: tuple[str, ...]) -> str:
    """name when the contract declares it; the shared files name nothing else."""
    return name if name in names else ""


def describe(
    answer: Answer | None, error: BaseException | None, tool_error: BaseException | None
) -> Told:
    """The outcome of one call as expect.json words it."""
    told = Told(kind=_kind(error, tool_error), answer=answer, error=error)
    if isinstance(error, EnforceError):
        told.answer = error.answer
    refusal = error.__cause__ if isinstance(error, CallAborted) else error
    if isinstance(refusal, CallRefused):
        told.code = _declared(refusal.code, DECLARED_CODES)
    if told.kind == "tool_error":
        # The tool's own exception leaves a call only over a recorded complete.
        told.ending = "ENDING_RECORDED"
    elif told.answer is not None:
        told.ending = _declared(told.answer.ending, DECLARED_ENDINGS)
    held = told.answer.held if told.answer is not None else None
    if held is not None:
        told.approval_id = held.approval_id
        if held.retry_after is not None:
            told.retry_after = f"{held.retry_after.total_seconds():g}s"
    return told


def match_json(at: str, want: object, got: object, absent: bool = False) -> list[str]:
    """Every way got departs from want; "*" matches any value that is present."""
    if want == "*":
        return [f"{at}: absent, want a value"] if absent else []
    if absent:
        return [f"{at}: absent, want {want!r}"]
    if not isinstance(want, dict) or not isinstance(got, dict):
        same = type(want) is type(got) and want == got
        return [] if same else [f"{at}: {got!r}, want {want!r}"]
    misses: list[str] = []
    for name, wanted in want.items():
        misses += match_json(f"{at}.{name}", wanted, got.get(name), name not in got)
    misses += [f"{at}.{name}: present, want absent" for name in got if name not in want]
    return misses


def request_misses(number: int, got: Got, token: str) -> list[str]:
    """How one request departs from what every request of the contract is."""
    misses = []
    if got.method != "POST" or got.version != "HTTP/1.1":
        misses.append(
            f"request {number} is {got.method} over {got.version}, want POST over HTTP/1.1"
        )
    if got.tokens != (token,):
        misses.append(f"request {number} presented the run token as {got.tokens!r}")
    if got.content_type != "application/json":
        misses.append(f"request {number} has content type {got.content_type!r}")
    return misses


def _times_misses(number: int, wanted: dict[str, object], body: dict[str, object]) -> list[str]:
    misses = []
    for name, reading in (("startedAt", BEFORE_TEXT), ("endedAt", AFTER_TEXT)):
        text = body.get(name)
        if name not in wanted:
            continue
        if not isinstance(text, str) or not _RFC3339_Z.fullmatch(text):
            misses.append(f"request {number}.{name}: {text!r} is no RFC 3339 time ending in Z")
        elif wanted[name] == "*" and text != reading:
            misses.append(f"request {number}.{name}: {text}, want the clock's {reading}")
    return misses


def _last_field(what: str, bodies: list[dict[str, object]], name: str, want: str) -> list[str]:
    if not want:
        return [f"{what} sent, want none"] if bodies else []
    if len(bodies) != 1:
        return [f"{len(bodies)} requests carrying the {what}, want 1"]
    return [] if bodies[0].get(name) == want else [f"{what} {bodies[0].get(name)!r}, want {want}"]


def compare_requests(got: list[Got], token: str, expect: dict[str, object]) -> list[str]:
    """Every way the requests depart from expect.json's, member for member."""
    wanted = expect["requests"]
    if not isinstance(wanted, list):
        raise ValueError("expect.requests is no list")
    misses = []
    if len(got) != len(wanted):
        misses.append(f"{len(got)} requests, want {len(wanted)}")
    sent: dict[str, list[dict[str, object]]] = {ABORT: [], COMPLETE: []}
    for number, request in enumerate(got, start=1):
        misses += request_misses(number, request, token)
        try:
            body = as_object(strict_json(request.body), f"request {number}")
        except ValueError as exc:
            misses.append(f"request {number} to {request.path}: {exc}")
            continue
        sent.setdefault(request.path, []).append(body)
        if number > len(wanted):
            misses.append(f"request {number} to {request.path} not expected")
            continue
        want = as_object(wanted[number - 1], "an expected request")
        if request.path != want["path"]:
            misses.append(f"request {number} to {request.path}, want {want['path']}")
            continue
        want_body = as_object(want["body"], "an expected body")
        misses += match_json(f"request {number}", want_body, body)
        misses += _times_misses(number, want_body, body)
    cause, status = expect.get("abort_cause", ""), expect.get("completion_status", "")
    misses += _last_field("abort cause", sent[ABORT], "cause", as_text(cause, "abort_cause"))
    misses += _last_field(
        "completion status", sent[COMPLETE], "status", as_text(status, "completion_status")
    )
    return misses


@dataclass
class _Caller:
    """The caller of one case: whether it is gone, and what its tool saw."""

    gone: bool = False
    entered: bool = False
    reached: bool = False
    received: bytes | None = None
    tool_error: BaseException | None = None

    def is_gone(self) -> bool:
        return self.gone

    def leave(self, then: str) -> None:
        if then not in ("cancel_caller", "await_caller"):
            raise ValueError(f"then {then!r}")
        self.gone = True

    def clock(self) -> datetime:
        return AFTER if self.entered else BEFORE


class CallerLeftError(Exception):
    """What a case's tool raises after its caller was cancelled."""


def _case_tool(does: dict[str, object], caller: _Caller) -> Tool:
    known = {
        "status",
        "started_at",
        "ended_at",
        "result_hash",
        "side_effect_confirmation",
        "error",
        "cancel_caller",
    }
    if set(does) - known:
        raise ValueError(f"tool_does names {sorted(set(does) - known)}")
    error = does.get("error", "")
    raises: dict[object, BaseException] = {
        "timed_out": TimeoutError("waiting for the tool"),
        "context": CallerLeftError("the caller is gone"),
    }
    if error not in ("", "not_sent", *raises):
        raise ValueError(f"tool_does.error {error!r}")

    def tool(authorized: bytes) -> Result | None:
        caller.entered = True
        if error == "not_sent":
            raise NotSent("dialling the tool")
        caller.reached, caller.received = True, bytes(authorized)
        if does.get("cancel_caller") is True:
            caller.gone = True
        if error:
            caller.tool_error = raises[error]
            raise caller.tool_error
        if "status" not in does:
            return None
        times = [does.get(name) for name in ("started_at", "ended_at")]
        started, ended = (datetime.fromisoformat(t) if isinstance(t, str) else None for t in times)
        return Result(
            status=as_text(does["status"], "tool_does.status"),
            started_at=started,
            ended_at=ended,
            result_hash=as_text(does.get("result_hash", ""), "tool_does.result_hash"),
            side_effect_confirmation=as_text(
                does.get("side_effect_confirmation", ""), "tool_does.side_effect_confirmation"
            ),
        )

    return tool


def load_script(case_id: str) -> list[Scripted]:
    """The receiver's script of a client case."""
    script = []
    for line in read_lines(TESTDATA / "client" / case_id / "answers.jsonl"):
        if set(line) - {"for", "status", "body", "raw", "then"} or ("body" in line) == (
            "raw" in line
        ):
            raise ValueError(f"{case_id}: an answer needs for, status and one of body and raw")
        status = line["status"]
        if not isinstance(status, int):
            raise ValueError(f"{case_id}: status {status!r}")
        raw = line["raw"] if "raw" in line else json.dumps(line["body"])
        script.append(
            Scripted(
                path=as_text(line["for"], "for"),
                status=status,
                body=as_text(raw, "raw").encode("utf-8"),
                then=as_text(line.get("then", ""), "then"),
            )
        )
    return script


def client_cases() -> list[dict[str, object]]:
    """The client cases cases.json lists."""
    listed = read_object(TESTDATA / "cases.json")["cases"]
    if not isinstance(listed, list):
        raise ValueError("cases.json lists no cases")
    cases = [as_object(case, "a case") for case in listed]
    return [case for case in cases if case["side"] == "client"]


def attempt(
    caller: Caller, tool: str, arguments: bytes, run: Tool, gone: Gone | None = None
) -> Answer | BaseException:
    """The answer a call returned, or what it raised."""
    try:
        return caller.call(tool, arguments, run, gone=gone)
    except BaseException as error:
        return error


def run_case(make: Maker, case_id: str) -> list[str]:
    """Runs one client case and returns every way the client departed from expect.json."""
    directory = TESTDATA / "client" / case_id
    call = read_object(directory / "call.json")
    expect = read_object(directory / "expect.json")
    if set(call) - {"tool", "arguments", "run_token", "deadline_ms", "tool_does"}:
        raise ValueError(f"{case_id}: call.json names a member this harness does not know")
    script = load_script(case_id)
    if any(s.then == "await_caller" for s in script) and not call.get("deadline_ms"):
        raise ValueError(f"{case_id}: await_caller needs deadline_ms")
    caller = _Caller()
    token = as_text(call["run_token"], "run_token")
    does = as_object(call.get("tool_does", {}), "tool_does")
    receiver = Receiver(script, then=caller.leave)
    try:
        client = make(receiver.socket, token, caller.clock)
        outcome = attempt(
            client,
            as_text(call["tool"], "tool"),
            as_text(call["arguments"], "arguments").encode("utf-8"),
            _case_tool(does, caller),
            caller.is_gone,
        )
        requests = receiver.requests()
    finally:
        receiver.close()
    if isinstance(outcome, BaseException):
        told = describe(None, outcome, caller.tool_error)
    else:
        told = describe(outcome, None, None)
    return case_misses(told, caller, requests, token, expect)


def case_misses(
    told: Told, caller: _Caller, requests: list[Got], token: str, expect: dict[str, object]
) -> list[str]:
    known = {
        "tool_reached",
        "tool_received",
        "requests",
        "abort_cause",
        "completion_status",
        "returns",
    }
    returns = as_object(expect["returns"], "returns")
    if set(expect) - known or set(returns) - {
        "error",
        "code",
        "ending",
        "approval_id",
        "retry_after",
    }:
        raise ValueError("expect.json names a member this harness does not know")
    misses = []
    if caller.reached is not expect["tool_reached"]:
        misses.append(f"tool reached {caller.reached}, want {expect['tool_reached']}")
    if "tool_received" in expect:
        received = as_text(expect["tool_received"], "tool_received").encode("utf-8")
        if caller.received != received:
            misses.append(f"tool received {caller.received!r}, want {received!r}")
    misses += compare_requests(requests, token, expect)
    for what, got, name in (
        ("returned", told.kind, "error"),
        ("code", told.code, "code"),
        ("ending", told.ending, "ending"),
        ("approval", told.approval_id, "approval_id"),
        ("retry after", told.retry_after, "retry_after"),
    ):
        if got != returns.get(name, ""):
            misses.append(f"{what} {got!r}, want {returns.get(name, '')!r} ({told.error!r})")
    return misses
