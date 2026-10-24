"""The reader: each form read, at the top and at depth."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from guardana_control.enforce import _wire
from tests.wire_bodies import admit, decision, execution, pending


class Read(unittest.TestCase):
    """Each form the reader takes, and what it makes of it."""

    def test_an_answer_with_every_kind_of_member(self) -> None:
        body = (
            b'{"outcome":"OUTCOME_EXECUTE",'
            b'"decision":{"decisionId":"d-1","verdict":"VERDICT_ALLOW_WITH_OBLIGATIONS",'
            b'"policyRuleIds":["a","b"],"reasonCodes":[],"decisionLatencyUs":"1234",'
            b'"decidedAt":"2026-10-11T12:00:00.987654321Z",'
            b'"obligations":[{"type":"emit_alert","params":{"channel":"ops","to":""},"advisory":true}]},'
            b'"execution":{"handle":"h-1","expiresAt":"2026-10-11T12:05:00Z",'
            b'"authorizedArguments":"eyJhIjoxfQ==","obligations":[]},'
            b'"pending":{"approvalId":"ap-1","retryAfter":"1.500s"}}'
        )
        self.assertEqual(
            admit(body),
            {
                "outcome": "OUTCOME_EXECUTE",
                "decision": {
                    "decisionId": "d-1",
                    "verdict": "VERDICT_ALLOW_WITH_OBLIGATIONS",
                    "policyRuleIds": ("a", "b"),
                    "reasonCodes": (),
                    "decisionLatencyUs": 1234,
                    "decidedAt": datetime(2026, 10, 11, 12, 0, 0, 987654, tzinfo=UTC),
                    "obligations": (
                        {
                            "type": "emit_alert",
                            "params": {"channel": "ops", "to": ""},
                            "advisory": True,
                        },
                    ),
                },
                "execution": {
                    "handle": "h-1",
                    "expiresAt": datetime(2026, 10, 11, 12, 5, tzinfo=UTC),
                    "authorizedArguments": b'{"a":1}',
                    "obligations": (),
                },
                "pending": {
                    "approvalId": "ap-1",
                    "retryAfter": timedelta(seconds=1, milliseconds=500),
                },
            },
        )

    def test_an_empty_object_and_the_whitespace_json_allows(self) -> None:
        self.assertEqual(admit(b"{}"), {})
        self.assertEqual(
            admit(b' \t\r\n{ "outcome" :\t"OUTCOME_BLOCK"\r\n}\n '), {"outcome": "OUTCOME_BLOCK"}
        )
        self.assertEqual(
            _wire.read(_wire.COMPLETE_RESPONSE, b'{"ending":"ENDING_RECORDED"}\n'),
            {"ending": "ENDING_RECORDED"},
        )

    def test_an_enum_is_a_declared_name_or_an_integer_in_int32(self) -> None:
        for written, read in (
            ('"OUTCOME_EXECUTE"', "OUTCOME_EXECUTE"),
            ('"OUTCOME_UNSPECIFIED"', "OUTCOME_UNSPECIFIED"),
            ("0", "OUTCOME_UNSPECIFIED"),
            ("1", "OUTCOME_EXECUTE"),
            ("3", "OUTCOME_PENDING"),
            ("-0", "OUTCOME_UNSPECIFIED"),
            ("4", 4),
            ("-1", -1),
            ("2147483647", 2147483647),
            ("-2147483648", -2147483648),
        ):
            with self.subTest(written=written):
                got = admit(('{"outcome":' + written + "}").encode())
                self.assertEqual(got, {"outcome": read})
                self.assertIs(type(got["outcome"]), type(read))
        self.assertEqual(admit(decision('"verdict":99')), {"decision": {"verdict": 99}})
        self.assertEqual(admit(decision('"verdict":2')), {"decision": {"verdict": "VERDICT_DENY"}})

    def test_an_int64_is_a_decimal_string(self) -> None:
        for written, read in (
            ("0", 0),
            ("-0", 0),
            ("1234", 1234),
            ("-7", -7),
            ("9223372036854775807", 9223372036854775807),
            ("-9223372036854775808", -9223372036854775808),
        ):
            with self.subTest(written=written):
                got = admit(decision('"decisionLatencyUs":"' + written + '"'))
                self.assertEqual(got, {"decision": {"decisionLatencyUs": read}})

    def test_bytes_are_padded_standard_base64(self) -> None:
        for written, read in (
            ("", b""),
            ("QQ==", b"A"),
            ("QUI=", b"AB"),
            ("QUJD", b"ABC"),
            ("eyJxIjoifn5+Pz8/In0=", b'{"q":"~~~???"}'),
            ("+/+/", b"\xfb\xff\xbf"),
        ):
            with self.subTest(written=written):
                got = admit(execution('"authorizedArguments":"' + written + '"'))
                self.assertEqual(got["execution"], {"handle": "h-1", "authorizedArguments": read})

    def test_a_timestamp_is_rfc_3339_with_z_and_up_to_nine_fractional_digits(self) -> None:
        for written, read in (
            ("2026-10-11T12:05:00Z", datetime(2026, 10, 11, 12, 5, tzinfo=UTC)),
            ("2026-10-11T12:05:00.5Z", datetime(2026, 10, 11, 12, 5, 0, 500000, tzinfo=UTC)),
            ("2026-10-11T12:05:00.123Z", datetime(2026, 10, 11, 12, 5, 0, 123000, tzinfo=UTC)),
            ("2026-10-11T12:05:00.123456Z", datetime(2026, 10, 11, 12, 5, 0, 123456, tzinfo=UTC)),
            (
                "2026-10-11T12:05:00.123456789Z",
                datetime(2026, 10, 11, 12, 5, 0, 123456, tzinfo=UTC),
            ),
            ("2024-02-29T23:59:59Z", datetime(2024, 2, 29, 23, 59, 59, tzinfo=UTC)),
            ("0001-01-01T00:00:00Z", datetime(1, 1, 1, tzinfo=UTC)),
            (
                "9999-12-31T23:59:59.999999999Z",
                datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC),
            ),
        ):
            with self.subTest(written=written):
                got = admit(execution('"expiresAt":"' + written + '"'))
                self.assertEqual(got["execution"], {"handle": "h-1", "expiresAt": read})

    def test_a_duration_is_decimal_seconds_with_s(self) -> None:
        for written, read in (
            ("0s", timedelta(0)),
            ("30s", timedelta(seconds=30)),
            ("1.5s", timedelta(seconds=1, milliseconds=500)),
            ("1.500s", timedelta(seconds=1, milliseconds=500)),
            ("0.000001s", timedelta(microseconds=1)),
            ("0.000000001s", timedelta(0)),
            ("1.999999999s", timedelta(seconds=1, microseconds=999999)),
            ("-1.5s", timedelta(seconds=-1, milliseconds=-500)),
            ("315576000000s", timedelta(seconds=315576000000)),
            ("-315576000000s", timedelta(seconds=-315576000000)),
        ):
            with self.subTest(written=written):
                got = admit(pending('"retryAfter":"' + written + '"'))
                self.assertEqual(got["pending"], {"retryAfter": read})

    def test_a_string_keeps_a_whole_surrogate_pair(self) -> None:
        got = admit(
            execution('"expiresAt":"2026-10-11T12:05:00Z"').replace(b"h-1", b"h-\\ud83d\\ude00")
        )
        self.assertEqual(
            got["execution"],
            {
                "handle": "h-\U0001f600",
                "expiresAt": datetime(2026, 10, 11, 12, 5, tzinfo=UTC),
            },
        )
        self.assertEqual(
            admit('{"execution":{"handle":"za\u017c\u00f3\u0142\u0107"}}'.encode()),
            {"execution": {"handle": "za\u017c\u00f3\u0142\u0107"}},
        )

    def test_an_answer_at_the_bound_is_read(self) -> None:
        body = b'{"outcome":"OUTCOME_BLOCK"}'
        self.assertEqual(_wire.MAX_ANSWER_BYTES, 262144)
        self.assertEqual(admit(body + b" " * (262144 - len(body))), {"outcome": "OUTCOME_BLOCK"})

    def test_parse_returns_the_answer_as_it_was_written(self) -> None:
        got = _wire.parse(b'{"outcome":1,"decision":{"verdict":2,"decisionLatencyUs":"7"}}')
        self.assertEqual(got, {"outcome": 1, "decision": {"verdict": 2, "decisionLatencyUs": "7"}})

    def test_an_error_body_is_read_by_its_own_members(self) -> None:
        got = _wire.read(
            _wire.ERROR,
            b'{"code":"ERROR_CODE_HANDLE_SPENT","message":"spent","ending":"ENDING_ABANDONED"}',
        )
        self.assertEqual(
            got,
            {"code": "ERROR_CODE_HANDLE_SPENT", "message": "spent", "ending": "ENDING_ABANDONED"},
        )
        self.assertEqual(_wire.read(_wire.ERROR, b'{"code":7}'), {"code": "ERROR_CODE_UNAVAILABLE"})
        self.assertEqual(_wire.read(_wire.ERROR, b'{"code":8}'), {"code": 8})
