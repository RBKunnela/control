"""The reader and the writer: each form read, each form refused, at the top and at depth."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta, timezone
from unittest import mock

from guardana_control.enforce import _wire
from guardana_control.enforce._wire import WireError

ARGS = "eyJhIjoxfQ=="  # {"a":1}


def execution(member: str) -> bytes:
    return ('{"outcome":"OUTCOME_EXECUTE","execution":{"handle":"h-1",' + member + "}}").encode()


def decision(member: str) -> bytes:
    return ('{"decision":{' + member + "}}").encode()


def pending(member: str) -> bytes:
    return ('{"outcome":"OUTCOME_PENDING","pending":{' + member + "}}").encode()


def admit(body: bytes) -> dict[str, object]:
    return _wire.read(_wire.ADMIT_RESPONSE, body)


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


# Each refusal: what it is, the body, and what the message must name.
BODIES: tuple[tuple[str, bytes, str], ...] = (
    ("one byte past the bound", b'{"outcome":"OUTCOME_BLOCK"}' + b" " * 262118, "262144 bytes"),
    ("a byte order mark", b'\xef\xbb\xbf{"outcome":"OUTCOME_BLOCK"}', "byte order mark"),
    ("bytes that are not UTF-8", b'{"execution":{"handle":"\xff"}}', "not UTF-8"),
    ("an encoded surrogate", b'{"execution":{"handle":"\xed\xa0\x80"}}', "not UTF-8"),
    ("UTF-16 without a mark", '{"outcome":"OUTCOME_BLOCK"}'.encode("utf-16-le"), "not JSON"),
    ("UTF-16 with a mark", '{"outcome":"OUTCOME_BLOCK"}'.encode("utf-16"), "not UTF-8"),
    ("UTF-32", '{"outcome":"OUTCOME_BLOCK"}'.encode("utf-32-le"), "not JSON"),
    ("an empty body", b"", "not JSON"),
    ("null", b"null", "not a JSON object"),
    ("an array", b'[{"outcome":"OUTCOME_BLOCK"}]', "not a JSON object"),
    ("a string", b'"OUTCOME_BLOCK"', "not a JSON object"),
    ("a number", b"1", "not a JSON object"),
    ("NaN for the body", b"NaN", "NaN"),
    ("two answers", b'{"outcome":"OUTCOME_BLOCK"}{"outcome":"OUTCOME_EXECUTE"}', "not JSON"),
    ("trailing text", b'{"outcome":"OUTCOME_BLOCK"} ok', "not JSON"),
    ("a trailing comma", b'{"outcome":"OUTCOME_BLOCK",}', "not JSON"),
    ("single quotes", b"{'outcome':'OUTCOME_BLOCK'}", "not JSON"),
    ("a comment", b'/* */{"outcome":"OUTCOME_BLOCK"}', "not JSON"),
    ("a truncated answer", b'{"outcome":"OUTCOME_BLOCK"', "not JSON"),
    ("arrays nested past the decoder", b"[" * 200000, "nested too deeply|not JSON"),
    (
        "a member nested past the decoder",
        b'{"decision":' + b"[" * 200000,
        "nested too deeply|not JSON",
    ),
    ("objects nested past the decoder", b'{"a":' * 52000, "nested too deeply|not JSON"),
    (
        "closed arrays nested past the decoder",
        b"[" * 100000 + b"]" * 100000,
        "nested too deeply|not a JSON object",
    ),
    (
        "a closed member nested past the decoder",
        b'{"decision":' + b"[" * 100000 + b"]" * 100000 + b"}",
        "nested too deeply|decision: not an object",
    ),
    ("an integer past the decoder", b'{"outcome":' + b"9" * 5000 + b"}", "not JSON"),
    (
        "a member repeated",
        b'{"outcome":"OUTCOME_BLOCK","outcome":"OUTCOME_EXECUTE"}',
        "'outcome' is repeated",
    ),
    (
        "a member repeated alike",
        b'{"outcome":"OUTCOME_BLOCK","outcome":"OUTCOME_BLOCK"}',
        "'outcome' is repeated",
    ),
    ("a member repeated at depth", execution('"handle":"h-2"'), "'handle' is repeated"),
    (
        "a map key repeated",
        decision('"obligations":[{"params":{"ms":"1","ms":"2"}}]'),
        "'ms' is repeated",
    ),
    (
        "an undeclared member",
        b'{"outcome":"OUTCOME_BLOCK","grant":"all"}',
        "grant: no member of AdmitResponse",
    ),
    ("an undeclared member that is null", b'{"grant":null}', "grant: no member of AdmitResponse"),
    (
        "an undeclared member at depth",
        execution('"grant":"all"'),
        "execution.grant: no member of Execution",
    ),
    (
        "an undeclared member in a list",
        decision('"obligations":[{"type":"x"},{"grant":1}]'),
        r"decision.obligations\[1\].grant: no member of Obligation",
    ),
    (
        "another message's member",
        b'{"code":"ERROR_CODE_UNAVAILABLE"}',
        "code: no member of AdmitResponse",
    ),
    (
        "the proto name of a member",
        execution('"authorized_arguments":"' + ARGS + '"'),
        "execution.authorized_arguments: no member",
    ),
    ("a member name in another case", b'{"Outcome":"OUTCOME_BLOCK"}', "Outcome: no member"),
    ("null for a member", b'{"outcome":null}', "outcome: null"),
    ("null for a message", b'{"pending":null}', "pending: null"),
    ("null at depth", execution('"expiresAt":null'), "execution.expiresAt: null"),
    ("null for a list", execution('"obligations":null'), "execution.obligations: null"),
    ("null in a list", decision('"reasonCodes":["a",null]'), r"decision.reasonCodes\[1\]: null"),
    ("null in a map", decision('"obligations":[{"params":{"ms":null}}]'), "params.ms: null"),
    ("NaN for a member", b'{"outcome":NaN}', "NaN"),
    ("Infinity at depth", decision('"verdict":Infinity'), "Infinity"),
    ("-Infinity at depth", decision('"verdict":-Infinity'), "-Infinity"),
    (
        "an enum name not declared",
        b'{"outcome":"OUTCOME_LATER"}',
        "outcome: 'OUTCOME_LATER' is no name of Outcome",
    ),
    (
        "an enum name not declared, at depth",
        decision('"verdict":"VERDICT_LATER"'),
        "decision.verdict: 'VERDICT_LATER' is no name of Verdict",
    ),
    (
        "an enum name in another case",
        b'{"outcome":"outcome_execute"}',
        "'outcome_execute' is no name",
    ),
    ("an enum name without its prefix", b'{"outcome":"EXECUTE"}', "'EXECUTE' is no name"),
    ("an enum integer in a string", b'{"outcome":"1"}', "'1' is no name"),
    ("an empty enum name", b'{"outcome":""}', "'' is no name"),
    ("an enum as true", b'{"outcome":true}', "outcome: neither a name of Outcome nor an integer"),
    ("an enum as a float", b'{"outcome":1.0}', "outcome: neither a name"),
    ("an enum as an exponent", b'{"outcome":1e0}', "outcome: neither a name"),
    ("an enum as a fraction", b'{"outcome":1.5}', "outcome: neither a name"),
    ("an enum in a list", b'{"outcome":["OUTCOME_EXECUTE"]}', "outcome: neither a name"),
    ("an enum past int32", b'{"outcome":2147483648}', "outcome: 2147483648 is outside int32"),
    ("an enum below int32", b'{"outcome":-2147483649}', "outcome: -2147483649 is outside int32"),
    (
        "an enum past int32, at depth",
        decision('"verdict":2147483648'),
        "decision.verdict: 2147483648 is outside int32",
    ),
    (
        "an int64 as a number",
        decision('"decisionLatencyUs":1234'),
        "decisionLatencyUs: not an int64 in a decimal string",
    ),
    ("an int64 as a float", decision('"decisionLatencyUs":1234.0'), "decisionLatencyUs"),
    ("an int64 as true", decision('"decisionLatencyUs":true'), "decisionLatencyUs"),
    ("an int64 with an exponent", decision('"decisionLatencyUs":"1e3"'), "decisionLatencyUs"),
    ("an int64 with a fraction", decision('"decisionLatencyUs":"1234.0"'), "decisionLatencyUs"),
    ("an int64 with a leading zero", decision('"decisionLatencyUs":"01"'), "decisionLatencyUs"),
    ("an int64 with a plus sign", decision('"decisionLatencyUs":"+1"'), "decisionLatencyUs"),
    ("an empty int64", decision('"decisionLatencyUs":""'), "decisionLatencyUs"),
    ("an int64 with a space", decision('"decisionLatencyUs":" 1"'), "decisionLatencyUs"),
    ("an int64 with a newline", decision('"decisionLatencyUs":"1\\n"'), "decisionLatencyUs"),
    ("a hexadecimal int64", decision('"decisionLatencyUs":"0x4d2"'), "decisionLatencyUs"),
    ("an int64 with a separator", decision('"decisionLatencyUs":"1_234"'), "decisionLatencyUs"),
    (
        "an int64 in other digits",
        decision('"decisionLatencyUs":"\u0661\u0662\u0663"'),
        "decisionLatencyUs",
    ),
    (
        "an int64 past its range",
        decision('"decisionLatencyUs":"9223372036854775808"'),
        "decisionLatencyUs: outside int64",
    ),
    (
        "an int64 below its range",
        decision('"decisionLatencyUs":"-9223372036854775809"'),
        "decisionLatencyUs: outside int64",
    ),
    (
        "an int64 of twenty digits",
        decision('"decisionLatencyUs":"10000000000000000000"'),
        "decisionLatencyUs: not an int64 in a decimal string",
    ),
    (
        "an int64 of more digits than the interpreter converts",
        decision('"decisionLatencyUs":"' + "9" * 5000 + '"'),
        "decisionLatencyUs: not an int64 in a decimal string",
    ),
    (
        "a negative int64 of more digits than the interpreter converts",
        decision('"decisionLatencyUs":"-' + "9" * 5000 + '"'),
        "decisionLatencyUs: not an int64 in a decimal string",
    ),
    (
        "base64 without padding",
        execution('"authorizedArguments":"eyJxIjoifn5+Pz8/In0"'),
        "authorizedArguments: not padded standard base64",
    ),
    (
        "the URL alphabet",
        execution('"authorizedArguments":"eyJxIjoifn5-Pz8_In0="'),
        "authorizedArguments",
    ),
    (
        "both alphabets",
        execution('"authorizedArguments":"eyJxIjoifn5+Pz8_In0="'),
        "authorizedArguments",
    ),
    (
        "a newline inside base64",
        execution('"authorizedArguments":"eyJh\\nIjoxfQ=="'),
        "authorizedArguments",
    ),
    (
        "a newline after base64",
        execution('"authorizedArguments":"eyJhIjoxfQ==\\n"'),
        "authorizedArguments",
    ),
    (
        "a carriage return inside base64",
        execution('"authorizedArguments":"eyJh\\rIjoxfQ=="'),
        "authorizedArguments",
    ),
    (
        "a space inside base64",
        execution('"authorizedArguments":"eyJh IjoxfQ=="'),
        "authorizedArguments",
    ),
    (
        "a character outside the alphabet",
        execution('"authorizedArguments":"eyJh!joxfQ=="'),
        "authorizedArguments",
    ),
    ("excess padding", execution('"authorizedArguments":"eyJhIjoxfQ===="'), "authorizedArguments"),
    (
        "padding inside",
        execution('"authorizedArguments":"eyJhIjoxfQ==eyJhIjoxfQ=="'),
        "authorizedArguments",
    ),
    (
        "a length base64 cannot have",
        execution('"authorizedArguments":"eyJhIjoxfQe"'),
        "authorizedArguments",
    ),
    ("padding alone", execution('"authorizedArguments":"===="'), "authorizedArguments"),
    ("bytes as an object", execution('"authorizedArguments":{"a":1}'), "authorizedArguments"),
    (
        "ten fractional digits",
        execution('"expiresAt":"2026-10-11T12:05:00.1234567890Z"'),
        "expiresAt: not an RFC 3339 time",
    ),
    ("a point with no fraction", execution('"expiresAt":"2026-10-11T12:05:00.Z"'), "expiresAt"),
    ("a comma for the point", execution('"expiresAt":"2026-10-11T12:05:00,5Z"'), "expiresAt"),
    ("a lower-case t", execution('"expiresAt":"2026-10-11t12:05:00Z"'), "expiresAt"),
    ("a lower-case z", execution('"expiresAt":"2026-10-11T12:05:00z"'), "expiresAt"),
    ("a space for the T", execution('"expiresAt":"2026-10-11 12:05:00Z"'), "expiresAt"),
    ("a numeric offset", execution('"expiresAt":"2026-10-11T14:05:00+02:00"'), "expiresAt"),
    ("a zero offset", execution('"expiresAt":"2026-10-11T12:05:00+00:00"'), "expiresAt"),
    ("an offset without a colon", execution('"expiresAt":"2026-10-11T14:05:00+0200"'), "expiresAt"),
    ("no zone", execution('"expiresAt":"2026-10-11T12:05:00"'), "expiresAt"),
    ("a date alone", execution('"expiresAt":"2026-10-11"'), "expiresAt"),
    ("no seconds", execution('"expiresAt":"2026-10-11T12:05Z"'), "expiresAt"),
    ("a one-digit hour", execution('"expiresAt":"2026-10-11T9:05:00Z"'), "expiresAt"),
    ("a five-digit year", execution('"expiresAt":"10000-01-01T00:00:00Z"'), "expiresAt"),
    ("the year zero", execution('"expiresAt":"0000-12-31T23:59:59Z"'), "expiresAt: no such time"),
    (
        "a day the month lacks",
        execution('"expiresAt":"2026-02-30T12:05:00Z"'),
        "expiresAt: no such time",
    ),
    (
        "the 29th of February in a common year",
        execution('"expiresAt":"2026-02-29T12:05:00Z"'),
        "expiresAt: no such time",
    ),
    ("a leap second", execution('"expiresAt":"2026-12-31T23:59:60Z"'), "expiresAt: no such time"),
    ("the hour 24", execution('"expiresAt":"2026-10-11T24:00:00Z"'), "expiresAt: no such time"),
    ("an empty time", execution('"expiresAt":""'), "expiresAt"),
    ("a space before a time", execution('"expiresAt":" 2026-10-11T12:05:00Z"'), "expiresAt"),
    ("a newline after a time", execution('"expiresAt":"2026-10-11T12:05:00Z\\n"'), "expiresAt"),
    (
        "a time in other digits",
        execution('"expiresAt":"\u0662\u0660\u0662\u0666-10-11T12:05:00Z"'),
        "expiresAt",
    ),
    ("a time as a number", execution('"expiresAt":1791720300'), "expiresAt"),
    ("a time as an object", execution('"expiresAt":{"seconds":"1791720300"}'), "expiresAt"),
    ("a time in the decision", decision('"decidedAt":"2026-10-11"'), "decision.decidedAt"),
    (
        "a duration without its unit",
        pending('"retryAfter":"30"'),
        "pending.retryAfter: not a Duration in decimal seconds",
    ),
    ("an upper-case unit", pending('"retryAfter":"30S"'), "retryAfter"),
    ("a duration as a number", pending('"retryAfter":30'), "retryAfter"),
    ("ten fractional digits of a second", pending('"retryAfter":"1.0000000001s"'), "retryAfter"),
    ("an exponent", pending('"retryAfter":"3e1s"'), "retryAfter"),
    ("a space before the unit", pending('"retryAfter":"30 s"'), "retryAfter"),
    ("a newline after the unit", pending('"retryAfter":"30s\\n"'), "retryAfter"),
    ("minutes", pending('"retryAfter":"1m30s"'), "retryAfter"),
    ("an empty duration", pending('"retryAfter":""'), "retryAfter"),
    ("a plus sign", pending('"retryAfter":"+30s"'), "retryAfter"),
    ("no whole seconds", pending('"retryAfter":".5s"'), "retryAfter"),
    ("a point with no fraction of a second", pending('"retryAfter":"30.s"'), "retryAfter"),
    ("a leading zero", pending('"retryAfter":"030s"'), "retryAfter"),
    (
        "a second past the range",
        pending('"retryAfter":"315576000001s"'),
        "retryAfter: outside a Duration's range",
    ),
    (
        "a fraction past the range",
        pending('"retryAfter":"315576000000.000000001s"'),
        "retryAfter: outside",
    ),
    (
        "a fraction below the range",
        pending('"retryAfter":"-315576000000.5s"'),
        "retryAfter: outside",
    ),
    (
        "seconds of thirteen digits",
        pending('"retryAfter":"1000000000000s"'),
        "retryAfter: not a Duration in decimal seconds",
    ),
    (
        "seconds of more digits than the interpreter converts",
        pending('"retryAfter":"' + "9" * 5000 + 's"'),
        "retryAfter: not a Duration in decimal seconds",
    ),
    (
        "a fraction after more digits than the interpreter converts",
        pending('"retryAfter":"-' + "9" * 5000 + '.5s"'),
        "retryAfter: not a Duration in decimal seconds",
    ),
    (
        "a lone high surrogate",
        b'{"execution":{"handle":"\\ud800"}}',
        "execution.handle: a lone surrogate",
    ),
    (
        "a lone low surrogate",
        b'{"execution":{"handle":"h-\\udc00"}}',
        "execution.handle: a lone surrogate",
    ),
    (
        "a surrogate before another escape",
        b'{"execution":{"handle":"\\ud800\\u0041"}}',
        "execution.handle: a lone surrogate",
    ),
    (
        "a lone surrogate in a list",
        decision('"reasonCodes":["\\udfff"]'),
        r"reasonCodes\[0\]: a lone surrogate",
    ),
    (
        "a lone surrogate in a map value",
        decision('"obligations":[{"params":{"k":"\\ud800"}}]'),
        "params.k: a lone surrogate",
    ),
    (
        "a lone surrogate in a map key",
        decision('"obligations":[{"params":{"\\ud800":"v"}}]'),
        "params: a lone surrogate",
    ),
    ("a control character in a string", b'{"execution":{"handle":"h\t1"}}', "not JSON"),
    ("an escape JSON lacks", b'{"execution":{"handle":"h\\x2d1"}}', "not JSON"),
    ("a string as a number", b'{"execution":{"handle":7}}', "execution.handle: not a string"),
    (
        "a bool in a string",
        decision('"obligations":[{"advisory":"true"}]'),
        "advisory: not true or false",
    ),
    (
        "a bool as a number",
        decision('"obligations":[{"advisory":1}]'),
        "advisory: not true or false",
    ),
    (
        "a list as a string",
        decision('"policyRuleIds":"refunds.small"'),
        "decision.policyRuleIds: not a list",
    ),
    (
        "a list as an object",
        decision('"obligations":{"type":"x"}'),
        "decision.obligations: not a list",
    ),
    ("a map as a list", decision('"obligations":[{"params":["ms"]}]'), "params: not an object"),
    (
        "a map value as a number",
        decision('"obligations":[{"params":{"ms":500}}]'),
        "params.ms: not a string",
    ),
    ("a message as an array", b'{"execution":[{"handle":"h-1"}]}', "execution: not an object"),
    ("a message as a string", b'{"execution":"h-1"}', "execution: not an object"),
    (
        "a message in a list as a string",
        decision('"obligations":["x"]'),
        r"obligations\[0\]: not an object",
    ),
    ("a number with a leading zero", b'{"outcome":01}', "not JSON"),
    ("a number with a plus sign", b'{"outcome":+1}', "not JSON"),
    ("a hexadecimal number", b'{"outcome":0x1}', "not JSON"),
)


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
