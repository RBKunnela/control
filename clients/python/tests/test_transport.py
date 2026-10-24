"""The transport and its bounds on reading: one bounded HTTP/1.1 request per connection."""

from __future__ import annotations

import socket
import time

from guardana_control.enforce import CallAborted, Client, MalformedAnswer, NoAnswer
from tests import harness
from tests.harness import ADMIT, RECORDED, Scripted, http_answer
from tests.raw_answers import (
    ARGUMENTS,
    BOUND,
    CHUNKED,
    EXECUTE,
    OBLIGED,
    Raw,
    chunked,
    padded,
    writing,
)


class Transport(Raw):
    """One request a connection, bounded in size and in time, and never sent again."""

    def test_a_request_is_http_1_1_on_a_connection_of_its_own(self) -> None:
        client = self.raw(writing(http_answer(200, EXECUTE), http_answer(200, RECORDED)))
        answer = client.call("t", ARGUMENTS, self.tool)
        self.assertEqual(
            (answer.ran, answer.ending, self.ran), (True, "ENDING_RECORDED", [ARGUMENTS])
        )
        self.assertEqual(len(self.receiver.requests), 2)
        head, _, body = self.receiver.requests[0].partition(b"\r\n\r\n")
        self.assertEqual(body, b'{"tool":"t","arguments":"eyJhIjoxfQ=="}')
        self.assertEqual(
            head.split(b"\r\n"),
            [
                b"POST /enforce/v1alpha1/admit HTTP/1.1",
                b"Host: enforce",
                b"Run-Token: tok",
                b"Content-Type: application/json",
                b"Content-Length: 39",
                b"Connection: close",
            ],
        )
        self.assertTrue(
            self.receiver.requests[1].startswith(b"POST /enforce/v1alpha1/complete HTTP/1.1\r\n")
        )
        self.assertIn(b"\r\nRun-Token: tok\r\n", self.receiver.requests[1])
        self.assertIn(b"\r\nContent-Type: application/json\r\n", self.receiver.requests[1])

    def test_an_answer_larger_than_64_kib_is_read_whole(self) -> None:
        large = b"x" * 150000
        body = (
            b'{"outcome":"OUTCOME_EXECUTE","execution":{"handle":"h-1","authorizedArguments":"'
            + b"eHh4" * 50000
            + b'"}}'
        )
        self.assertGreater(len(body), 200000)
        pieces = [body[at : at + 2048] for at in range(0, len(body), 2048)]
        for name, answer in (
            ("with its length", http_answer(200, body)),
            ("chunked", chunked(*pieces)),
            ("until the receiver hangs up", b"HTTP/1.1 200 OK\r\n\r\n" + body),
            ("over HTTP/1.0", b"HTTP/1.0 200 OK\r\n\r\n" + body),
        ):
            with self.subTest(answer=name):
                client = self.raw(writing(answer, http_answer(200, RECORDED)))
                self.assertEqual(client.call("t", large, self.tool).ending, "ENDING_RECORDED")
                self.assertEqual(self.ran, [large])

    def test_an_answer_at_the_bound_is_read_and_one_byte_past_it_is_not(self) -> None:
        for name, frame in (
            ("with its length", lambda body: http_answer(200, body)),
            ("chunked", lambda body: chunked(body[:100000], body[100000:])),
            ("until the receiver hangs up", lambda body: b"HTTP/1.1 200 OK\r\n\r\n" + body),
        ):
            with self.subTest(answer=name):
                client = self.raw(writing(frame(padded(BOUND)), http_answer(200, RECORDED)))
                self.assertEqual(client.call("t", ARGUMENTS, self.tool).ending, "ENDING_RECORDED")
                client = self.raw(writing(frame(padded(BOUND + 1)), http_answer(200, RECORDED)))
                with self.assertRaisesRegex(MalformedAnswer, "more than 262144 bytes") as raised:
                    client.call("t", ARGUMENTS, self.tool)
                self.assertEqual((raised.exception.answer.ran, self.ran), (False, []))
                self.assertEqual(len(self.receiver.requests), 1)

    def test_no_more_than_the_bound_and_one_byte_is_read(self) -> None:
        """An answer that never ends is refused for its size, not waited for."""
        body = padded(BOUND + 1)
        for name, head in (
            (
                "a length it never fills",
                b"HTTP/1.1 200 OK\r\nContent-Length: 10485760\r\n\r\n" + body,
            ),
            ("no length and no end", b"HTTP/1.1 200 OK\r\n\r\n" + body),
            (
                "a chunk it never fills",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na00000\r\n" + body,
            ),
        ):
            with self.subTest(answer=name):

                def serve(
                    connection: socket.socket, _number: int, _request: bytes, head: bytes = head
                ) -> None:
                    connection.sendall(head)
                    self.receiver.released.wait(60)

                client = self.raw(serve, timeout=10.0)
                with self.assertRaisesRegex(MalformedAnswer, "more than 262144 bytes"):
                    client.call("t", ARGUMENTS, self.tool)
                self.assertEqual((self.ran, len(self.receiver.requests)), ([], 1))

    def test_the_timeout_bounds_a_whole_request_not_each_read(self) -> None:
        answer = http_answer(200, EXECUTE)
        pause = 0.05
        slowest = len(answer) * pause

        def trickle(connection: socket.socket, _number: int, _request: bytes) -> None:
            for byte in answer:
                connection.sendall(bytes([byte]))
                if self.receiver.released.wait(pause):
                    return

        client = self.raw(trickle, timeout=0.3)
        started = time.monotonic()
        with self.assertRaises(NoAnswer) as raised:
            client.call("t", ARGUMENTS, self.tool)
        lasted = time.monotonic() - started
        self.assertGreater(slowest, 5.0)
        self.assertLess(lasted, slowest, "the call outlasted the whole trickled answer")
        self.assertEqual((raised.exception.answer.ran, self.ran), (False, []))
        self.assertEqual(len(self.receiver.requests), 1)

    def test_a_receiver_that_never_answers_ends_the_call_by_the_timeout(self) -> None:
        def silent(_connection: socket.socket, _number: int, _request: bytes) -> None:
            self.receiver.released.wait(60)

        client = self.raw(silent, timeout=0.2)
        started = time.monotonic()
        with self.assertRaisesRegex(NoAnswer, "admit"):
            client.call("t", ARGUMENTS, self.tool)
        self.assertLess(time.monotonic() - started, 30.0)
        self.assertEqual((self.ran, len(self.receiver.requests)), ([], 1))

    def test_a_trailer_that_never_ends_ends_the_call_by_the_timeout(self) -> None:
        def serve(connection: socket.socket, _number: int, _request: bytes) -> None:
            connection.sendall(CHUNKED + b"5f\r\n" + EXECUTE + b"\r\n0\r\n")
            self.receiver.released.wait(60)

        self.assertEqual(len(EXECUTE), 0x5F)
        client = self.raw(serve, timeout=0.2)
        started = time.monotonic()
        with self.assertRaisesRegex(NoAnswer, "admit") as raised:
            client.call("t", ARGUMENTS, self.tool)
        self.assertLess(time.monotonic() - started, 30.0)
        self.assertEqual((raised.exception.answer.ran, self.ran), (False, []))
        self.assertEqual(len(self.receiver.requests), 1)

    def test_an_unanswered_complete_is_not_sent_again(self) -> None:
        def serve(connection: socket.socket, number: int, _request: bytes) -> None:
            if number == 0:
                connection.sendall(http_answer(200, EXECUTE))
            else:
                self.receiver.released.wait(60)

        client = self.raw(serve, timeout=2.0)
        with self.assertRaisesRegex(NoAnswer, "complete") as raised:
            client.call("t", ARGUMENTS, self.tool)
        answer = raised.exception.answer
        self.assertEqual((answer.ran, answer.ending, self.ran), (True, "", [ARGUMENTS]))
        self.assertEqual(getattr(answer.result, "status", None), "COMPLETION_STATUS_SUCCESS")
        self.assertEqual(len(self.receiver.requests), 2)

    def test_an_unanswered_abort_is_still_an_abort_and_is_not_sent_again(self) -> None:
        def serve(connection: socket.socket, number: int, _request: bytes) -> None:
            if number == 0:
                connection.sendall(http_answer(200, OBLIGED))

        client = self.raw(serve)
        with self.assertRaises(CallAborted) as raised:
            client.call("t", ARGUMENTS, self.tool)
        self.assertIsInstance(raised.exception.__cause__, NoAnswer)
        self.assertEqual((raised.exception.cause, self.ran), ("ABORT_CAUSE_OBLIGATION", []))
        self.assertEqual(len(self.receiver.requests), 2)

    def test_a_timeout_longer_than_a_socket_can_wait_still_serves(self) -> None:
        for timeout in (1e300, 10**30):
            with self.subTest(timeout=timeout):
                client = self.raw(
                    writing(http_answer(200, EXECUTE), http_answer(200, RECORDED)), timeout
                )
                self.assertEqual(client.call("t", ARGUMENTS, self.tool).ending, "ENDING_RECORDED")

    def test_a_redirect_is_not_followed(self) -> None:
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                receiver = harness.Receiver(
                    [
                        Scripted(ADMIT, status, EXECUTE, location=ADMIT),
                        Scripted(ADMIT, 200, EXECUTE),
                    ]
                )
                self.addCleanup(receiver.close)
                ran: list[bytes] = []
                with self.assertRaisesRegex(MalformedAnswer, f"status {status}"):
                    Client(receiver.socket, "tok", 5.0).call("t", ARGUMENTS, ran.append)
                self.assertEqual((ran, [got.path for got in receiver.requests()]), ([], [ADMIT]))

    def test_a_socket_nothing_listens_on_is_no_answer(self) -> None:
        receiver = harness.RawReceiver(writing())
        gone = receiver.socket
        receiver.close()
        for name, path in (
            ("a path that is gone", gone),
            ("a path longer than a socket's", "/tmp/" + "p" * 200),  # noqa: S108
            ("a path with a NUL", "/tmp/a\x00b"),  # noqa: S108
        ):
            with self.subTest(socket=name), self.assertRaisesRegex(NoAnswer, "admit") as raised:
                Client(path, "tok", 5.0).call("t", ARGUMENTS, self.tool)
            self.assertEqual(raised.exception.answer.ran, False)
