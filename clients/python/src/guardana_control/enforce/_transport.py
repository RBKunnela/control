"""One HTTP/1.1 request over a Unix socket, bounded as a whole by one deadline."""

from __future__ import annotations

import re
import socket
import time
from typing import Final

# Go's client counts what it reads ahead past the head, up to one 4 KiB
# buffer, into its 64 KiB for the status line, the headers and the blank line,
# and finds the end of a trailer only within one such buffer.
_HEAD_LIMIT: Final = 65536 - 4096
_TRAILER_LIMIT: Final = 4096
_CHUNK_LINE_LIMIT: Final = 256
# Go's bound on what a chunked body carries besides data, counted its way.
_EXCESS_LIMIT: Final = 16384
_LONGEST_WAIT: Final = 1e9
_FIRST_FINAL_STATUS: Final = 200
_NO_BODY: Final = (204, 304)
_STATUS = re.compile(rb"HTTP/1\.([01]) ([0-9]{3})(?: .*)?")
_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_NUMBER = re.compile(rb"[0-9]{1,18}")
_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]{1,15}")
_CONTROL = re.compile(rb"[\x00-\x08\x0a-\x1f\x7f]")


class TransportError(Exception):
    """A request that got no whole answer in time."""


class _Stream:
    """A connection whose every wait is cut to what is left of one deadline."""

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self._sock = sock
        self._deadline = deadline
        self._buffer = bytearray()

    def _wait(self) -> None:
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("no answer within the timeout")
        # A socket refuses a wait longer than its C clock can hold.
        self._sock.settimeout(min(left, _LONGEST_WAIT))

    def connect(self, path: str) -> None:
        self._wait()
        self._sock.connect(path)

    def send(self, data: bytes) -> None:
        self._wait()
        self._sock.sendall(data)

    def _more(self, most: int) -> bool:
        self._wait()
        got = self._sock.recv(most)
        self._buffer += got
        return bool(got)

    def line(self, limit: int) -> bytes:
        """The next line of at most limit bytes, without its line ending."""
        while (end := self._buffer.find(b"\r\n")) < 0:
            if len(self._buffer) > limit or not self._more(4096):
                raise ValueError("a line of the answer ended early or is too long")
        if end > limit:
            raise ValueError("a line of the answer is too long")
        return self.exactly(end + 2)[:-2]

    def exactly(self, count: int) -> bytes:
        while len(self._buffer) < count:
            if not self._more(min(count - len(self._buffer), 65536)):
                raise ValueError("the answer ended early")
        taken = bytes(self._buffer[:count])
        del self._buffer[:count]
        return taken

    def rest(self, limit: int) -> bytes:
        """What the receiver sends until it closes, cut at limit bytes."""
        while len(self._buffer) < limit and self._more(limit - len(self._buffer)):
            pass
        return bytes(self._buffer[:limit])


def _headers(stream: _Stream, budget: int) -> dict[str, str]:
    """The header lines up to the empty one, all within budget bytes; a trailer is read so too."""
    headers: dict[str, str] = {}
    left = budget - 2
    while line := stream.line(max(left - 2, 0)):
        left -= len(line) + 2
        if _CONTROL.search(line):
            raise ValueError("a control byte in a header line")
        name, colon, value = line.partition(b":")
        if not colon or not _NAME.fullmatch(name):
            raise ValueError("a header line without a name that is a token")
        key = name.decode("ascii").lower()
        text = value.decode("latin-1").strip(" \t")
        if key == "transfer-encoding" and key in headers:
            raise ValueError("two transfer codings for one answer")
        if key == "trailer" and key in headers:
            headers[key] += "," + text
            continue
        if headers.setdefault(key, text) != text and key == "content-length":
            raise ValueError("two lengths for one answer")
    return headers


def _chunked(stream: _Stream, limit: int) -> bytes:
    body = bytearray()
    excess = 0
    while len(body) < limit:
        line = stream.line(_CHUNK_LINE_LIMIT)
        if _CONTROL.search(line):
            raise ValueError("a control byte in a chunk-size line")
        size_text = line.rstrip(b" \t").partition(b";")[0]
        if not _CHUNK_SIZE.fullmatch(size_text):
            raise ValueError("a chunk without a size")
        size = int(size_text, 16)
        excess = max(excess + len(line) + 2 - 16 - 2 * size, 0)
        if excess > _EXCESS_LIMIT:
            raise ValueError("a chunked answer with too much besides data")
        if size == 0:
            _headers(stream, _TRAILER_LIMIT)
            break
        take = min(size, limit - len(body))
        body += stream.exactly(take)
        if take == size and stream.exactly(2) != b"\r\n":
            raise ValueError("a chunk without its end")
    return bytes(body)


def _answer(stream: _Stream, limit: int) -> tuple[int, bytes]:
    first = stream.line(_HEAD_LIMIT - 4)
    status = _STATUS.fullmatch(first)
    if status is None:
        raise ValueError("no HTTP/1 status line")
    code = int(status.group(2))
    if code < _FIRST_FINAL_STATUS or code in _NO_BODY:
        raise ValueError(f"status {code} carries no answer")
    headers = _headers(stream, _HEAD_LIMIT - len(first) - 2)
    # Go's client refuses a malformed length even beside chunked, which then
    # decides the framing.
    length = headers.get("content-length")
    if length is not None and not _NUMBER.fullmatch(length.encode("latin-1")):
        raise ValueError("a length that is no number")
    coding = headers.get("transfer-encoding")
    if coding is not None:
        if status.group(1) == b"0":
            raise ValueError("a transfer coding under HTTP/1.0")
        if coding.lower() != "chunked":
            raise ValueError("a transfer coding other than chunked")
        named = {f.strip(" \t").lower() for f in headers.get("trailer", "").split(",")}
        if named & {"transfer-encoding", "trailer", "content-length"}:
            raise ValueError("a trailer named to carry the answer's own framing")
        return code, _chunked(stream, limit)
    if length is None:
        return code, stream.rest(limit)
    return code, stream.exactly(min(int(length), limit))


class Transport:
    """Posts to one receiver as one run, a connection per request."""

    def __init__(self, socket_path: str, token: str, timeout: float) -> None:
        self._socket = socket_path
        self._token = token
        self._timeout = timeout

    def post(self, path: str, body: bytes, limit: int) -> tuple[int, bytes]:
        """The status of the answer and at most limit bytes of its body.

        A redirect is an answer like any other: nothing is followed, since
        following one would present the run token somewhere else. A framing
        that readers of HTTP do not agree on is no answer, and neither is a
        status that comes before the answer or cannot carry a body.
        """
        deadline = time.monotonic() + self._timeout
        head = (
            f"POST {path} HTTP/1.1\r\nHost: enforce\r\nRun-Token: {self._token}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                stream = _Stream(sock, deadline)
                stream.connect(self._socket)
                stream.send(head + body)
                return _answer(stream, limit)
        except (OSError, ValueError) as exc:
            raise TransportError(f"{path}: {exc}") from exc
