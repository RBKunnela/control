"""One HTTP/1.1 request over a Unix socket, bounded as a whole by one deadline."""

from __future__ import annotations

import re
import socket
import time
from typing import Final

_HEAD_LIMIT: Final = 65536
_CHUNK_LINE_LIMIT: Final = 256
_LONGEST_WAIT: Final = 1e9
_STATUS = re.compile(rb"HTTP/1\.[01] ([0-9]{3})(?: .*)?")
_NUMBER = re.compile(rb"[0-9]{1,18}")
_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]{1,15}")


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


def _headers(stream: _Stream) -> dict[str, str]:
    headers: dict[str, str] = {}
    left = _HEAD_LIMIT
    while line := stream.line(left):
        left -= len(line) + 2
        name, colon, value = line.partition(b":")
        key = name.decode("latin-1").lower()
        if not colon or key != key.strip() or not key:
            raise ValueError("a header line without a name")
        text = value.decode("latin-1").strip()
        if headers.setdefault(key, text) != text and key == "content-length":
            raise ValueError("two lengths for one answer")
    return headers


def _chunked(stream: _Stream, limit: int) -> bytes:
    body = bytearray()
    while len(body) < limit:
        size_text = stream.line(_CHUNK_LINE_LIMIT).partition(b";")[0].strip()
        if not _CHUNK_SIZE.fullmatch(size_text):
            raise ValueError("a chunk without a size")
        size = int(size_text, 16)
        if size == 0:
            break
        take = min(size, limit - len(body))
        body += stream.exactly(take)
        if take == size and stream.exactly(2) != b"\r\n":
            raise ValueError("a chunk without its end")
    return bytes(body)


def _answer(stream: _Stream, limit: int) -> tuple[int, bytes]:
    status = _STATUS.fullmatch(stream.line(_HEAD_LIMIT))
    if status is None:
        raise ValueError("no HTTP/1 status line")
    headers = _headers(stream)
    if "chunked" in headers.get("transfer-encoding", "").lower():
        return int(status.group(1)), _chunked(stream, limit)
    length = headers.get("content-length")
    if length is None:
        return int(status.group(1)), stream.rest(limit)
    if not _NUMBER.fullmatch(length.encode("latin-1")):
        raise ValueError("a length that is no number")
    return int(status.group(1)), stream.exactly(min(int(length), limit))


class Transport:
    """Posts to one receiver as one run, a connection per request."""

    def __init__(self, socket_path: str, token: str, timeout: float) -> None:
        self._socket = socket_path
        self._token = token
        self._timeout = timeout

    def post(self, path: str, body: bytes, limit: int) -> tuple[int, bytes]:
        """The status of the answer and at most limit bytes of its body.

        A redirect is an answer like any other: nothing is followed, since
        following one would present the run token somewhere else.
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
