"""The framing of an answer: what is read as a whole HTTP/1.1 answer, and what is no answer."""

from __future__ import annotations

import socket
import time

from guardana_control.enforce import EnforceError, NoAnswer
from tests.harness import RECORDED, http_answer
from tests.raw_answers import ARGUMENTS, CHUNKED, EXECUTE, Raw, chunked, forty_byte_chunks, writing


class Framing(Raw):
    """Chunked and length-framed answers, and the framings a stricter reader refuses."""

    def test_a_chunked_answer_is_read_whole(self) -> None:
        extended = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"1;name=value\r\n{\r\n" + b"%X\r\n%s\r\n" % (len(EXECUTE) - 1, EXECUTE[1:]) + b"0\r\n"
            b"Trailer: 1\r\n\r\n"
        )
        for name, answer in (
            ("one chunk", chunked(EXECUTE)),
            ("a chunk a byte", chunked(*(bytes([byte]) for byte in EXECUTE))),
            ("an extension, upper-case digits and a trailer", extended),
            (
                "beside a length that chunked overrides",
                chunked(EXECUTE).replace(b"\r\n\r\n", b"\r\nContent-Length: 3\r\n\r\n", 1),
            ),
        ):
            with self.subTest(answer=name):
                client = self.raw(writing(answer, chunked(RECORDED[:5], RECORDED[5:])))
                answer_ = client.call("t", ARGUMENTS, self.tool)
                self.assertEqual((answer_.ending, self.ran), ("ENDING_RECORDED", [ARGUMENTS]))

    def test_a_chunked_answer_sent_in_pieces_is_read_whole(self) -> None:
        whole = chunked(EXECUTE[:10], EXECUTE[10:11], EXECUTE[11:])

        def serve(connection: socket.socket, number: int, _request: bytes) -> None:
            if number:
                connection.sendall(http_answer(200, RECORDED))
                return
            for at in range(0, len(whole), 3):
                connection.sendall(whole[at : at + 3])
                self.receiver.released.wait(0.001)

        self.assertEqual(self.raw(serve).call("t", ARGUMENTS, self.tool).ending, "ENDING_RECORDED")
        self.assertEqual(self.ran, [ARGUMENTS])

    def test_an_answer_that_is_no_whole_http_answer_is_no_answer(self) -> None:
        long_header = b"X-Pad: " + b"p" * 70000 + b"\r\n"
        for name, answer in (
            ("nothing at all", b""),
            ("no status line", b"HELLO\r\n\r\n" + EXECUTE),
            ("another protocol", b"HTTP/2.0 200 OK\r\n\r\n" + EXECUTE),
            ("a status of two digits", b"HTTP/1.1 20 OK\r\n\r\n" + EXECUTE),
            ("a head that never ends", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"),
            ("a body shorter than its length", http_answer(200, EXECUTE)[:-1]),
            (
                "a length that is no number",
                b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n" + EXECUTE,
            ),
            ("a negative length", b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n" + EXECUTE),
            (
                "two lengths",
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 97\r\n\r\n" + EXECUTE,
            ),
            ("a header with no name", b"HTTP/1.1 200 OK\r\nno colon here\r\n\r\n" + EXECUTE),
            ("a head past 64 KiB", b"HTTP/1.1 200 OK\r\n" + long_header + b"\r\n" + EXECUTE),
            ("a chunked answer cut short", chunked(EXECUTE)[:-5]),
            ("a chunk shorter than its size", chunked(EXECUTE).replace(b"}}\r\n0", b"}\r\n0")),
            (
                "a chunk with no size",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n" + EXECUTE,
            ),
            (
                "a status line and headers past 60 KiB together",
                b"HTTP/1.1 200 OK " + b"r" * 30000 + b"\r\nX-Pad: " + b"p" * 32000 + b"\r\n"
                b"Content-Length: 95\r\n\r\n" + EXECUTE,
            ),
            (
                "a trailer past 4 KiB",
                chunked(EXECUTE)[:-2] + b"X-Pad: " + b"p" * 5000 + b"\r\n\r\n",
            ),
            (
                "chunk extensions past 16 KiB besides the data",
                CHUNKED
                + b"".join(b"1;" + b"e" * 200 + b"\r\n" + bytes([c]) + b"\r\n" for c in EXECUTE)
                + b"0\r\n\r\n",
            ),
            (
                "chunk extensions that outweigh 40-byte chunks of data",
                forty_byte_chunks(line=120),
            ),
            (
                "a trailer named to carry the length",
                chunked(EXECUTE).replace(b"\r\n\r\n", b"\r\nTrailer: Content-Length\r\n\r\n", 1),
            ),
            (
                "a second trailer line naming the coding",
                chunked(EXECUTE).replace(
                    b"\r\n\r\n", b"\r\nTrailer: X-A\r\nTrailer: x-b, transfer-encoding\r\n\r\n", 1
                ),
            ),
            (
                "a chunked answer beside a length that is no number",
                chunked(EXECUTE).replace(b"\r\n\r\n", b"\r\nContent-Length: nonsense\r\n\r\n", 1),
            ),
            (
                "a chunked answer beside a negative length",
                chunked(EXECUTE).replace(b"\r\n\r\n", b"\r\nContent-Length: -1\r\n\r\n", 1),
            ),
        ):
            with self.subTest(answer=name):
                client = self.raw(writing(answer, http_answer(200, RECORDED)))
                with self.assertRaises(NoAnswer) as raised:
                    client.call("t", ARGUMENTS, self.tool)
                self.assertEqual((raised.exception.answer.ran, self.ran), (False, []))
                self.assertEqual(len(self.receiver.requests), 1)

    def test_a_framing_a_stricter_reader_refuses_is_no_answer(self) -> None:
        """Each answer holds the whole body, so a looser reading of it runs the tool.

        Go's client finds no answer in any of the framings. The statuses are
        another matter: it reads a 204 and a 304 with an empty body and the
        answer that follows a 1xx. The transport refuses those because the
        contract has no such answer: the plane answers a POST only with 200,
        400, 401, 404, 409 and 503.
        """
        self.assertEqual(len(EXECUTE), 95)
        ok = b"HTTP/1.1 200 OK\r\n"
        old = b"HTTP/1.0 200 OK\r\n"
        length = b"Content-Length: 95\r\n\r\n" + EXECUTE
        chunk = b"5f\r\n" + EXECUTE + b"\r\n0\r\n\r\n"
        self.assertEqual(len(chunk), 106)
        last = CHUNKED + b"5f\r\n" + EXECUTE + b"\r\n0\r\n"
        for name, answer in (
            ("a length after a vertical tab", ok + b"Content-Length:\x0b95\r\n\r\n" + EXECUTE),
            ("a length before a form feed", ok + b"Content-Length: 95\x0c\r\n\r\n" + EXECUTE),
            ("a length after a no-break space", ok + b"Content-Length: \xa095\r\n\r\n" + EXECUTE),
            ("a length before a no-break space", ok + b"Content-Length: 95\xa0\r\n\r\n" + EXECUTE),
            (
                "another coding before chunked",
                ok + b"Transfer-Encoding: gzip, chunked\r\n\r\n" + chunk,
            ),
            (
                "a coding that only holds the word",
                ok + b"Transfer-Encoding: xchunkedx\r\n\r\n" + chunk,
            ),
            ("identity beside a length", ok + b"Transfer-Encoding: identity\r\n" + length),
            (
                "chunked and then another coding",
                ok + b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n" + chunk,
            ),
            (
                "chunked twice",
                ok + b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk,
            ),
            ("a chunk size after a space", CHUNKED + b" 5f\r\n" + EXECUTE + b"\r\n0\r\n\r\n"),
            (
                "a chunk size after a vertical tab",
                CHUNKED + b"\x0b5f\r\n" + EXECUTE + b"\r\n0\r\n\r\n",
            ),
            (
                "a chunk size before a vertical tab",
                CHUNKED + b"5f\x0b\r\n" + EXECUTE + b"\r\n0\r\n\r\n",
            ),
            (
                "a space before a chunk extension",
                CHUNKED + b"5f ;x\r\n" + EXECUTE + b"\r\n0\r\n\r\n",
            ),
            ("a NUL in a header value", ok + b"X-A: a\x00b\r\n" + length),
            ("a bare CR in a header value", ok + b"X-A: a\rContent-Length: 2\r\n" + length),
            ("a bare LF in a header value", ok + b"X-A: a\nContent-Length: 2\r\n" + length),
            ("a unit separator in a header value", ok + b"X-A: a\x1fb\r\n" + length),
            ("a DEL in a header value", ok + b"X-A: a\x7fb\r\n" + length),
            ("a 204 with a body", b"HTTP/1.1 204 No Content\r\n" + length),
            ("a 304 with a body", b"HTTP/1.1 304 Not Modified\r\n" + length),
            ("a 100 before the answer", b"HTTP/1.1 100 Continue\r\n\r\n" + ok + length),
            ("a 103 before the answer", b"HTTP/1.1 103 Early Hints\r\n\r\n" + ok + length),
            ("a 199 with a body", b"HTTP/1.1 199 Odd\r\n" + length),
            ("chunked under HTTP/1.0", old + b"Transfer-Encoding: chunked\r\n\r\n" + chunk),
            (
                "chunked under HTTP/1.0 beside the length of its chunks",
                old + b"Transfer-Encoding: chunked\r\nContent-Length: 106\r\n\r\n" + chunk,
            ),
            ("a parenthesis in a header name", ok + b"X(a): b\r\n" + length),
            ("a quote in a header name", ok + b'X"a: b\r\n' + length),
            ("a slash in a header name", ok + b"X/y: b\r\n" + length),
            ("an at sign in a header name", ok + b"X@y: b\r\n" + length),
            ("a tab in a header name", ok + b"X\ty: b\r\n" + length),
            ("a high byte in a header name", ok + b"X\x80: b\r\n" + length),
            (
                "a soft hyphen ending the name of a length",
                ok + b"Content-Length\xad: 2\r\n\r\n" + EXECUTE,
            ),
            (
                "a parenthesis ending the name of a coding beside a length",
                ok + b"Transfer-Encoding(: chunked\r\n" + length,
            ),
            (
                "a bare CR in a chunk extension",
                CHUNKED + b"5f;a\rb\r\n" + EXECUTE + b"\r\n0\r\n\r\n",
            ),
            (
                "a bare LF in a chunk extension",
                CHUNKED + b"5f;a\nb\r\n" + EXECUTE + b"\r\n0\r\n\r\n",
            ),
            ("nothing after the last chunk", last),
            ("a trailer cut before its blank line", last + b"X-T: 1\r\n"),
            ("a trailer with no colon", last + b"garbage\r\n\r\n"),
            ("a NUL in a trailer", last + b"X-T: \x00\r\n\r\n"),
        ):
            with self.subTest(answer=name):
                client = self.raw(writing(answer, http_answer(200, RECORDED)))
                with self.assertRaises(EnforceError) as raised:
                    client.call("t", ARGUMENTS, self.tool)
                self.assertIs(type(raised.exception), NoAnswer, raised.exception)
                self.assertEqual((raised.exception.answer.ran, self.ran), (False, []))
                self.assertEqual(len(self.receiver.requests), 1)

    def test_the_framings_a_receiver_may_write_are_still_read(self) -> None:
        ok = b"HTTP/1.1 200 OK\r\n"
        chunk = b"5f\r\n" + EXECUTE + b"\r\n0\r\n\r\n"
        for name, answer in (
            ("a length", ok + b"Content-Length: 95\r\n\r\n" + EXECUTE),
            ("chunked", ok + b"Transfer-Encoding: chunked\r\n\r\n" + chunk),
            ("chunked in another case", ok + b"Transfer-Encoding: Chunked\r\n\r\n" + chunk),
            (
                "a length padded with spaces and tabs",
                ok + b"Content-Length: \t 95\t \r\n\r\n" + EXECUTE,
            ),
            (
                "chunked padded with spaces and tabs",
                ok + b"Transfer-Encoding:\t chunked \t\r\n\r\n" + chunk,
            ),
            ("a tab in a header value", ok + b"X-A: a\tb\r\nContent-Length: 95\r\n\r\n" + EXECUTE),
            (
                "a chunk size before a space and a tab",
                CHUNKED + b"5f \t\r\n" + EXECUTE + b"\r\n0\r\n\r\n",
            ),
            ("chunked with a trailer", CHUNKED + b"5f\r\n" + EXECUTE + b"\r\n0\r\nX-T: 1\r\n\r\n"),
            ("a chunk extension", CHUNKED + b"5f;a=b\r\n" + EXECUTE + b"\r\n0\r\n\r\n"),
            ("a length under HTTP/1.0", b"HTTP/1.0 200 OK\r\nContent-Length: 95\r\n\r\n" + EXECUTE),
            (
                "every byte a header name may hold",
                ok + b"!#$%&'*+-.^_`|~09AZaz: b\r\nContent-Length: 95\r\n\r\n" + EXECUTE,
            ),
        ):
            with self.subTest(answer=name):
                client = self.raw(writing(answer, http_answer(200, RECORDED)))
                self.assertEqual(client.call("t", ARGUMENTS, self.tool).ending, "ENDING_RECORDED")
                self.assertEqual(self.ran, [ARGUMENTS])

    def test_a_long_head_and_a_long_chunk_line_within_their_bounds_are_read(self) -> None:
        for name, answer in (
            ("one long header", http_answer(200, EXECUTE, "X-Pad: " + "p" * 60000)),
            (
                "two headers within the head's budget",
                http_answer(200, EXECUTE, "X-Pad-0: " + "p" * 30000, "X-Pad-1: " + "p" * 30000),
            ),
            (
                "a chunk-size line within its limit",
                CHUNKED + b"5f;pad=" + b"p" * 200 + b"\r\n" + EXECUTE + b"\r\n0\r\n\r\n",
            ),
            ("chunk extensions that 40-byte chunks of data outweigh", forty_byte_chunks(line=90)),
            (
                "a trailer named for another header",
                chunked(EXECUTE).replace(b"\r\n\r\n", b"\r\nTrailer: X-Checksum\r\n\r\n", 1),
            ),
            (
                "a trailer within 4 KiB",
                CHUNKED + b"5f\r\n" + EXECUTE + b"\r\n0\r\nX-Pad: " + b"p" * 4000 + b"\r\n\r\n",
            ),
        ):
            with self.subTest(answer=name):
                client = self.raw(writing(answer, http_answer(200, RECORDED)))
                self.assertEqual(client.call("t", ARGUMENTS, self.tool).ending, "ENDING_RECORDED")

    def test_a_bound_on_the_head_or_on_a_chunk_ends_the_read_at_once(self) -> None:
        """Each answer is whole and well-formed but for the one bound it passes."""
        self.assertEqual(len(EXECUTE), 0x5F)
        pads = [b"X-Pad-%d: " % number + b"p" * 60000 + b"\r\n" for number in range(8)]
        length = b"Content-Length: 95\r\n\r\n"
        for name, answer in (
            (
                "two headers that together pass the head's budget",
                b"HTTP/1.1 200 OK\r\n" + b"".join(pads[:2]) + length + EXECUTE,
            ),
            (
                "eight headers that together pass the head's budget",
                b"HTTP/1.1 200 OK\r\n" + b"".join(pads) + length + EXECUTE,
            ),
            (
                "a chunk-size line past its limit",
                CHUNKED + b"5f;pad=" + b"p" * 300 + b"\r\n" + EXECUTE + b"\r\n0\r\n\r\n",
            ),
            (
                "a chunk followed by two bytes that are not its end",
                CHUNKED + b"5f\r\n" + EXECUTE + b"XX0\r\n\r\n",
            ),
            (
                "two trailers that together pass the head's budget",
                CHUNKED + b"5f\r\n" + EXECUTE + b"\r\n0\r\n" + b"".join(pads[:2]) + b"\r\n",
            ),
        ):
            with self.subTest(answer=name):

                def serve(
                    connection: socket.socket,
                    number: int,
                    _request: bytes,
                    answer: bytes = answer,
                ) -> None:
                    # Nothing but a bound ends the read: the answer is whole and nobody hangs up.
                    connection.sendall(http_answer(200, RECORDED) if number else answer)
                    self.receiver.released.wait(60)

                client = self.raw(serve, timeout=60.0)
                started = time.monotonic()
                with self.assertRaises(NoAnswer) as raised:
                    client.call("t", ARGUMENTS, self.tool)
                self.assertLess(time.monotonic() - started, 20.0, "the deadline ended the read")
                self.assertEqual((raised.exception.answer.ran, self.ran), (False, []))
                self.assertEqual(len(self.receiver.requests), 1)
