"""A scripted receiver, the shared files, and the comparison every client is held to.

Nothing here reads the client's reader, its table or its transport: the paths,
the header and the declared names are spelled out, and a request is compared
with its expectation as a JSON value.
"""

from __future__ import annotations

import json
import re
import shutil
import socket
import socketserver
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Protocol

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

TESTDATA = Path(__file__).resolve().parents[3] / "testdata" / "enforce"

ADMIT = "/enforce/v1alpha1/admit"
COMPLETE = "/enforce/v1alpha1/complete"
ABORT = "/enforce/v1alpha1/abort"
PATHS = {"admit": ADMIT, "complete": COMPLETE, "abort": ABORT}
RECORDED = b'{"ending":"ENDING_RECORDED"}'
UNSCRIPTED = b'{"code":"ERROR_CODE_MALFORMED","message":"unscripted request"}'

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

# The injected clock reads BEFORE until the tool is entered and AFTER from then on.
BEFORE = datetime(2026, 10, 11, 12, 0, 10, tzinfo=UTC)
AFTER = datetime(2026, 10, 11, 12, 0, 11, 500000, tzinfo=UTC)
BEFORE_TEXT = "2026-10-11T12:00:10Z"
AFTER_TEXT = "2026-10-11T12:00:11.500Z"

_RFC3339_Z = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{3}|\.[0-9]{6}|\.[0-9]{9})?Z"
)
MAX_VECTOR_BODY = 1048576

Tool = Callable[[bytes], Result | None]
Gone = Callable[[], object]


class Caller(Protocol):
    """A client under test, bound to a socket, a token and a clock."""

    def call(
        self, tool: str, arguments: bytes, run: Tool, *, gone: Gone | None = None
    ) -> Answer: ...


Maker = Callable[[str, str, Callable[[], datetime]], Caller]


class RepeatedMemberError(ValueError):
    """A JSON object that names a member twice."""


def _once(pairs: list[tuple[str, object]]) -> dict[str, object]:
    members: dict[str, object] = {}
    for name, value in pairs:
        if name in members:
            raise RepeatedMemberError(f"member {name!r} is repeated")
        members[name] = value
    return members


def _no_constant(name: str) -> object:
    raise ValueError(f"{name} is no JSON number")


def strict_json(text: str | bytes) -> object:
    """text as a JSON value; a repeated member or a NaN is refused."""
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    return json.loads(text, object_pairs_hook=_once, parse_constant=_no_constant)


def as_object(value: object, what: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{what} is no JSON object")
    return value


def as_text(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{what} is no string")
    return value


def read_object(path: Path) -> dict[str, object]:
    return as_object(strict_json(path.read_text(encoding="utf-8")), str(path))


def read_lines(path: Path) -> list[dict[str, object]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [as_object(strict_json(line), f"{path} line {n + 1}") for n, line in enumerate(lines)]


@dataclass(frozen=True)
class Scripted:
    """One answer of a receiver's script."""

    path: str
    status: int
    body: bytes
    then: str = ""
    location: str = ""


@dataclass(frozen=True)
class Got:
    """One request as the receiver saw it."""

    method: str
    path: str
    version: str
    tokens: tuple[str, ...]
    content_type: str
    body: bytes


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    # More clients than this at once would be refused before any of them is served.
    request_queue_size = 64
    receiver: Receiver


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        if not isinstance(self.server, _Server):
            raise TypeError("the handler serves a scripted receiver only")
        receiver = self.server.receiver
        length = int(self.headers.get("Content-Length") or 0)
        got = Got(
            method=self.command,
            path=self.path,
            version=self.request_version,
            tokens=tuple(self.headers.get_all("Run-Token") or ()),
            content_type=self.headers.get("Content-Type") or "",
            body=self.rfile.read(length),
        )
        answer = receiver.next_answer(got)
        if answer.then:
            receiver.then(answer.then)
        self.send_response(answer.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(answer.body)))
        self.send_header("Connection", "close")
        if answer.location:
            self.send_header("Location", answer.location)
        self.close_connection = True
        try:
            self.end_headers()
            self.wfile.write(answer.body)
        except (BrokenPipeError, ConnectionResetError):
            # A client that has read enough of a long answer hangs up on the rest.
            return


class Receiver:
    """Answers each request with the next scripted answer and records what it was sent.

    A request to another path or past the script gets 400 ERROR_CODE_MALFORMED;
    with goes_on, one past the script is answered as recorded, so that a client
    that wrongly goes on is not stopped here.
    """

    def __init__(
        self,
        script: list[Scripted],
        *,
        then: Callable[[str], None] | None = None,
        goes_on: bool = False,
    ) -> None:
        if then is None and any(scripted.then for scripted in script):
            raise ValueError("the script acts on a caller and nothing can do it")
        self._script = list(script)
        self._goes_on = goes_on
        self._then = then
        self._lock = threading.Lock()
        self._got: list[Got] = []
        # A socket path is bounded at about 104 bytes, so the directory is a short one.
        self._dir = tempfile.mkdtemp(prefix="enf", dir="/tmp")
        self.socket = str(Path(self._dir) / "s")
        self._server = _Server(self.socket, _Handler)
        self._server.receiver = self
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        self._thread.start()

    def next_answer(self, got: Got) -> Scripted:
        with self._lock:
            position = len(self._got)
            self._got.append(got)
        if position < len(self._script):
            scripted = self._script[position]
            if scripted.path == got.path:
                return scripted
        elif self._goes_on:
            return Scripted(got.path, 200, RECORDED)
        return Scripted(got.path, 400, UNSCRIPTED)

    def then(self, name: str) -> None:
        if self._then is not None:
            self._then(name)

    def requests(self) -> list[Got]:
        with self._lock:
            return list(self._got)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()
        shutil.rmtree(self._dir)


class EchoReceiver(Receiver):
    """Authorizes whatever bytes an admit proposes under a handle named after its tool.

    A complete is recorded only when it reports the bytes its handle was
    given, so calls that share a client cannot trade answers unseen.
    """

    def __init__(self) -> None:
        super().__init__([])
        self._authorized: dict[object, object] = {}

    def next_answer(self, got: Got) -> Scripted:
        asked = as_object(strict_json(got.body), "a request")
        with self._lock:
            self._got.append(got)
            if got.path == ADMIT:
                self._authorized[asked["tool"]] = asked["arguments"]
                execution = {"handle": asked["tool"], "authorizedArguments": asked["arguments"]}
                answer = json.dumps({"outcome": "OUTCOME_EXECUTE", "execution": execution})
                return Scripted(ADMIT, 200, answer.encode("utf-8"))
            reported = self._authorized.get(asked["handle"]) == asked.get("sentArguments")
        if got.path == COMPLETE and reported:
            return Scripted(COMPLETE, 200, RECORDED)
        return Scripted(got.path, 400, UNSCRIPTED)


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


def http_answer(status: int, body: bytes, *headers: str) -> bytes:
    """An HTTP/1.1 answer with its length declared, and any further header lines."""
    lines = [f"HTTP/1.1 {status} Scripted", f"Content-Length: {len(body)}", *headers, "", ""]
    return "\r\n".join(lines).encode("ascii") + body


class RawReceiver:
    """A Unix socket that hands each request, and the connection it came on, to a function.

    The function writes whatever bytes it likes, so that an answer can be
    chunked, cut short, trickled or never sent. released is set when the test
    is over: a function that holds a connection open waits on it.
    """

    def __init__(self, serve: Callable[[socket.socket, int, bytes], None]) -> None:
        self._serve = serve
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self.requests: list[bytes] = []
        self.released = threading.Event()
        self._dir = tempfile.mkdtemp(prefix="enf", dir="/tmp")
        self.socket = str(Path(self._dir) / "s")
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(self.socket)
        self._listener.listen()
        self._listener.settimeout(0.02)
        self._accepting = threading.Thread(target=self._accept, daemon=True)
        self._accepting.start()

    def _accept(self) -> None:
        while not self.released.is_set():
            try:
                connection, _ = self._listener.accept()
            except TimeoutError:
                continue
            thread = threading.Thread(target=self._handle, args=(connection,), daemon=True)
            with self._lock:
                self._threads.append(thread)
            thread.start()

    def _handle(self, connection: socket.socket) -> None:
        with connection:
            connection.settimeout(30)
            try:
                request = _read_request(connection)
                with self._lock:
                    number = len(self.requests)
                    self.requests.append(request)
                self._serve(connection, number, request)
            except OSError:
                # The client hung up, which is what some of these tests wait for.
                return

    def close(self) -> None:
        self.released.set()
        self._accepting.join()
        with self._lock:
            threads = list(self._threads)
        for thread in threads:
            thread.join()
        self._listener.close()
        shutil.rmtree(self._dir)


def _read_request(connection: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        more = connection.recv(65536)
        if not more:
            return data
        data += more
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value)
    while len(body) < length:
        more = connection.recv(65536)
        if not more:
            break
        body += more
    return head + b"\r\n\r\n" + body
