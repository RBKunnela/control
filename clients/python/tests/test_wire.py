"""The reader's refusals and the writer: each form refused, at the top and at depth."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta, timezone
from unittest import mock

from guardana_control.enforce import _wire
from guardana_control.enforce._wire import WireError
from tests.wire_bodies import BODIES, admit


class Refused(unittest.TestCase):
    """Each form the reader refuses, and that its message names what it met."""

    def test_every_refusal(self) -> None:
        for what, body, names in BODIES:
            with self.subTest(what=what), self.assertRaisesRegex(WireError, names):
                admit(body)
        self.assertGreater(len(BODIES), 140)

    def test_the_other_answers_are_read_as_strictly(self) -> None:
        for message, body, names in (
            (
                _wire.COMPLETE_RESPONSE,
                b'{"ending":"ENDING_RECORDED","grant":"all"}',
                "grant: no member of CompleteResponse",
            ),
            (
                _wire.COMPLETE_RESPONSE,
                b'{"ending":"ENDING_UNRECORDED","ending":"ENDING_RECORDED"}',
                "'ending' is repeated",
            ),
            (
                _wire.COMPLETE_RESPONSE,
                b'{"ending":"ENDING_LATER"}',
                "ending: 'ENDING_LATER' is no name of Ending",
            ),
            (_wire.COMPLETE_RESPONSE, b'{"ending":1.0}', "ending: neither a name"),
            (_wire.COMPLETE_RESPONSE, b'{"ending":null}', "ending: null"),
            (
                _wire.COMPLETE_RESPONSE,
                b'{"code":"ERROR_CODE_HANDLE_SPENT"}',
                "code: no member of CompleteResponse",
            ),
            (
                _wire.ABORT_RESPONSE,
                b'{"ending":"ENDING_RECORDED","grant":"all"}',
                "grant: no member of AbortResponse",
            ),
            (_wire.ABORT_RESPONSE, b'{"ending":true}', "ending: neither a name"),
            (
                _wire.ERROR,
                b'{"code":"ERROR_CODE_LATER"}',
                "code: 'ERROR_CODE_LATER' is no name of ErrorCode",
            ),
            (
                _wire.ERROR,
                b'{"code":"ERROR_CODE_UNAVAILABLE","retry":true}',
                "retry: no member of Error",
            ),
            (_wire.ERROR, b'{"message":null}', "message: null"),
            (_wire.ERROR, b'{"outcome":"OUTCOME_EXECUTE"}', "outcome: no member of Error"),
            (_wire.ERROR, b"<html></html>", "not JSON"),
            (_wire.ERROR, b"", "not JSON"),
        ):
            with self.subTest(body=body), self.assertRaisesRegex(WireError, names):
                _wire.read(message, body)

    def test_a_message_quotes_a_bounded_part_of_what_the_answer_wrote(self) -> None:
        long = "g" * 100000
        cut = "g" * 120 + "... (cut from 100000 characters)"
        for what, body, message in (
            ("an undeclared member", '{"' + long + '":1}', f"{cut}: no member of AdmitResponse"),
            (
                "an undeclared member at depth",
                '{"execution":{"' + long + '":1}}',
                f"execution.{cut}: no member of Execution",
            ),
            (
                "a repeated member",
                '{"' + long + '":1,"' + long + '":2}',
                f"member '{cut}' is repeated",
            ),
            (
                "an enum name",
                '{"outcome":"' + long + '"}',
                f"outcome: '{cut}' is no name of Outcome",
            ),
            (
                "a map key over null",
                '{"decision":{"obligations":[{"params":{"' + long + '":null}}]}}',
                f"decision.obligations[0].params.{cut}: null",
            ),
            (
                "a map key over a number",
                '{"decision":{"obligations":[{"params":{"' + long + '":5}}]}}',
                f"decision.obligations[0].params.{cut}: not a string",
            ),
            (
                "an enum integer",
                '{"outcome":' + "9" * 4000 + "}",
                "outcome: " + "9" * 120 + "... (cut from 4000 characters) is outside int32",
            ),
        ):
            with self.subTest(what=what):
                with self.assertRaises(WireError) as raised:
                    admit(body.encode())
                self.assertEqual(str(raised.exception), message)

    def test_a_message_quotes_whole_what_is_no_longer_than_the_bound(self) -> None:
        for length, quoted in (
            (120, "g" * 120),
            (121, "g" * 120 + "... (cut from 121 characters)"),
        ):
            with self.subTest(length=length):
                with self.assertRaises(WireError) as raised:
                    admit(('{"' + "g" * length + '":1}').encode())
                self.assertEqual(str(raised.exception), f"{quoted}: no member of AdmitResponse")

    def test_a_member_of_a_kind_the_reader_has_no_rule_for_is_refused(self) -> None:
        table = {
            "M": {
                "known": ("string", "one", ""),
                "odd": ("double", "one", ""),
                "bag": ("string", "set", ""),
            }
        }
        with mock.patch.object(_wire, "MESSAGES", table):
            self.assertEqual(_wire.read("M", b'{"known":"x"}'), {"known": "x"})
            with self.assertRaisesRegex(WireError, "odd: no rule for a one of double"):
                _wire.read("M", b'{"odd":1.5}')
            with self.assertRaisesRegex(WireError, "bag: no rule for a set of string"):
                _wire.read("M", b'{"bag":["x"]}')


class Written(unittest.TestCase):
    """A request is its message's JSON names, with every default value left out."""

    def test_an_admit_request(self) -> None:
        self.assertEqual(
            _wire.write(_wire.ADMIT_REQUEST, {"tool": "refund", "arguments": b'{"a":1}'}),
            b'{"tool":"refund","arguments":"eyJhIjoxfQ=="}',
        )
        self.assertEqual(
            _wire.write(_wire.ADMIT_REQUEST, {"tool": "t", "arguments": b""}), b'{"tool":"t"}'
        )
        self.assertEqual(
            _wire.write(_wire.ADMIT_REQUEST, {"tool": "", "arguments": b"A"}),
            b'{"arguments":"QQ=="}',
        )
        self.assertEqual(
            _wire.write(
                _wire.ADMIT_REQUEST, {"tool": "za\u017c\u00f3\u0142\u0107", "arguments": b"AB"}
            ),
            '{"tool":"za\u017c\u00f3\u0142\u0107","arguments":"QUI="}'.encode(),
        )

    def test_a_complete_request(self) -> None:
        self.assertEqual(
            _wire.write(
                _wire.COMPLETE_REQUEST,
                {
                    "handle": "h-1",
                    "sentArguments": b"\xfb\xff\xbf",
                    "status": "COMPLETION_STATUS_FAILURE",
                    "startedAt": datetime(2026, 10, 11, 12, 0, 1, tzinfo=UTC),
                    "endedAt": datetime(
                        2026, 10, 11, 14, 0, 3, 250000, tzinfo=timezone(timedelta(hours=2))
                    ),
                    "resultHash": "sha256:77aa",
                    "sideEffectConfirmation": "",
                },
            ),
            b'{"handle":"h-1","sentArguments":"+/+/","status":"COMPLETION_STATUS_FAILURE",'
            b'"startedAt":"2026-10-11T12:00:01Z","endedAt":"2026-10-11T12:00:03.250Z",'
            b'"resultHash":"sha256:77aa"}',
        )

    def test_a_time_is_written_with_no_three_or_six_fractional_digits(self) -> None:
        for at, written in (
            (datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC), "2026-01-02T03:04:05Z"),
            (datetime(2026, 1, 2, 3, 4, 5, 120000, tzinfo=UTC), "2026-01-02T03:04:05.120Z"),
            (datetime(2026, 1, 2, 3, 4, 5, 1, tzinfo=UTC), "2026-01-02T03:04:05.000001Z"),
            (datetime(2026, 1, 2, 3, 4, 5, 123450, tzinfo=UTC), "2026-01-02T03:04:05.123450Z"),
            (datetime(987, 1, 2, 3, 4, 5, tzinfo=UTC), "0987-01-02T03:04:05Z"),
            (
                datetime(2026, 1, 1, 0, 30, tzinfo=timezone(timedelta(hours=1))),
                "2025-12-31T23:30:00Z",
            ),
        ):
            with self.subTest(at=at):
                body = _wire.write(_wire.COMPLETE_REQUEST, {"startedAt": at})
                self.assertEqual(body, ('{"startedAt":"' + written + '"}').encode())

    def test_an_abort_request_and_the_unspecified_cause_left_out(self) -> None:
        self.assertEqual(
            _wire.write(_wire.ABORT_REQUEST, {"handle": "h-1", "cause": "ABORT_CAUSE_NOT_SENT"}),
            b'{"handle":"h-1","cause":"ABORT_CAUSE_NOT_SENT"}',
        )
        self.assertEqual(
            _wire.write(_wire.ABORT_REQUEST, {"handle": "h-1", "cause": "ABORT_CAUSE_UNSPECIFIED"}),
            b'{"handle":"h-1"}',
        )

    def test_a_value_of_the_wrong_type_is_refused(self) -> None:
        for message, values in (
            (_wire.ADMIT_REQUEST, {"tool": 7}),
            (_wire.ADMIT_REQUEST, {"arguments": "text"}),
            (_wire.ADMIT_REQUEST, {"arguments": bytearray(b"a")}),
            (_wire.ABORT_REQUEST, {"cause": "ABORT_CAUSE_LATER"}),
            (_wire.ABORT_REQUEST, {"cause": 3}),
            (_wire.COMPLETE_REQUEST, {"startedAt": datetime(2026, 1, 2, 3, 4, 5)}),
            (_wire.COMPLETE_REQUEST, {"startedAt": "2026-01-02T03:04:05Z"}),
        ):
            with self.subTest(values=values), self.assertRaises(TypeError):
                _wire.write(message, values)
        with self.assertRaises(KeyError):
            _wire.write(_wire.ABORT_REQUEST, {"grant": "all"})
