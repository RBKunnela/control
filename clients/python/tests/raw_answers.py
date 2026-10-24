"""A client over a receiver that writes raw bytes, and the answers the transport tests write."""

from __future__ import annotations

import socket
import unittest
from collections.abc import Callable

from guardana_control.enforce import Client, Result, Status
from tests import harness

ARGUMENTS = b'{"a":1}'
EXECUTE = (
    b'{"outcome":"OUTCOME_EXECUTE","execution":{"handle":"h-1",'
    b'"authorizedArguments":"eyJhIjoxfQ=="}}'
)
OBLIGED = (
    b'{"outcome":"OUTCOME_EXECUTE","execution":{"handle":"h-1",'
    b'"authorizedArguments":"eyJhIjoxfQ==","obligations":[{"type":"x"}]}}'
)
BOUND = 262144
CHUNKED = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"

Serve = Callable[[socket.socket, int, bytes], None]


def padded(length: int) -> bytes:
    return EXECUTE + b" " * (length - len(EXECUTE))


def forty_byte_chunks(line: int) -> bytes:
    """EXECUTE padded to 640 chunks of 40 bytes, each size line line bytes long.

    Go's client allows a chunk 16 bytes and twice its data besides the data, and
    refuses past 16 KiB more: a 120-byte line keeps 26 bytes a chunk, a 90-byte
    line none.
    """
    body = EXECUTE + b" " * (40 * 640 - len(EXECUTE))
    size = b"28;" + b"e" * (line - 3)
    pieces = (size + b"\r\n" + body[i : i + 40] + b"\r\n" for i in range(0, len(body), 40))
    return CHUNKED + b"".join(pieces) + b"0\r\n\r\n"


def chunked(*chunks: bytes) -> bytes:
    """An HTTP/1.1 answer whose body is chunks, each sent as a chunk of its own."""
    parts = [b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"]
    parts += [b"%x\r\n%s\r\n" % (len(chunk), chunk) for chunk in chunks]
    return b"".join(parts) + b"0\r\n\r\n"


def writing(*answers: bytes) -> Serve:
    """Writes the answer of each request's number, whole, and hangs up."""

    def serve(connection: socket.socket, number: int, _request: bytes) -> None:
        connection.sendall(answers[number])

    return serve


class Raw(unittest.TestCase):
    """A client whose receiver writes whatever bytes a test gives it."""

    def raw(self, serve: Serve, timeout: float = 10.0) -> Client:
        self.receiver = harness.RawReceiver(serve)
        self.addCleanup(self.receiver.close)
        self.ran: list[bytes] = []
        return Client(self.receiver.socket, "tok", timeout)

    def tool(self, authorized: bytes) -> Result:
        self.ran.append(authorized)
        return Result(Status.SUCCESS)
