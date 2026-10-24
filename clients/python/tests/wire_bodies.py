"""Answer bodies for the reader's tests: built a member at a time, and each one it refuses."""

from __future__ import annotations

from guardana_control.enforce import _wire

ARGS = "eyJhIjoxfQ=="  # {"a":1}


def execution(member: str) -> bytes:
    return ('{"outcome":"OUTCOME_EXECUTE","execution":{"handle":"h-1",' + member + "}}").encode()


def decision(member: str) -> bytes:
    return ('{"decision":{' + member + "}}").encode()


def pending(member: str) -> bytes:
    return ('{"outcome":"OUTCOME_PENDING","pending":{' + member + "}}").encode()


def admit(body: bytes) -> dict[str, object]:
    return _wire.read(_wire.ADMIT_RESPONSE, body)


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
