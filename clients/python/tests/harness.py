"""Scripted receivers, the directory of the shared files, and a strict reading of JSON.

Nothing here reads the client's reader, its table or its transport: the paths
and the header are spelled out, and a body is read as a JSON value.
"""

from __future__ import annotations

import json
import shutil
import socket
import socketserver
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Protocol

from guardana_control.enforce import Answer, Result

TESTDATA = Path(__file__).resolve().parents[3] / "testdata" / "enforce"

ADMIT = "/enforce/v1alpha1/admit"
COMPLETE = "/enforce/v1alpha1/complete"
ABORT = "/enforce/v1alpha1/abort"
PATHS = {"admit": ADMIT, "complete": COMPLETE, "abort": ABORT}
RECORDED = b'{"ending":"ENDING_RECORDED"}'
UNSCRIPTED = b'{"code":"ERROR_CODE_MALFORMED","message":"unscripted request"}'

# The injected clock reads BEFORE until the tool is entered and AFTER from then on.
BEFORE = datetime(2026, 10, 11, 12, 0, 10, tzinfo=UTC)
AFTER = datetime(2026, 10, 11, 12, 0, 11, 500000, tzinfo=UTC)
BEFORE_TEXT = "2026-10-11T12:00:10Z"
AFTER_TEXT = "2026-10-11T12:00:11.500Z"

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
