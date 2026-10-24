"""The rules of a call that no case file holds: what a call returns and each exception carries."""

from __future__ import annotations

import traceback
from datetime import UTC, datetime, timedelta

from guardana_control.enforce import (
    Answer,
    CallBlocked,
    CallPending,
    CallRefused,
    Held,
    MalformedAnswer,
    NotRecorded,
    Result,
    Status,
)
from tests import harness
from tests.rules import ARGUMENTS, EXECUTE, Rules, admit, complete, result_of, returning, succeed


class Returning(Rules):
    """What a call returns, and what each exception carries."""

    def test_a_recorded_run_returns_what_the_call_learned(self) -> None:
        client = self.serve(admit(EXECUTE), complete())
        receipt = object()
        answer = client.call(
            "t", ARGUMENTS, self.entering(returning(Result(Status.FAILURE, receipt)))
        )
        self.assertEqual(
            answer,
            Answer(
                outcome="OUTCOME_EXECUTE",
                decision={"schemaVersion": "1.0", "decisionId": "d-1", "verdict": 1},
                held=None,
                ran=True,
                result=Result(Status.FAILURE, receipt, harness.BEFORE, harness.AFTER),
                ending="ENDING_RECORDED",
            ),
        )
        self.assertIs(result_of(answer).value, receipt)
        self.assertEqual(self.sent(), [self.admitted, self.completed("COMPLETION_STATUS_FAILURE")])

    def test_the_decision_cannot_be_changed_by_the_caller(self) -> None:
        client = self.serve(
            admit(EXECUTE.replace(b'"verdict":1', b'"verdict":1,"reasonCodes":["A"]')), complete()
        )
        answer = client.call("t", ARGUMENTS, succeed)
        decision = answer.decision or {}
        self.assertEqual(decision["reasonCodes"], ("A",))
        with self.assertRaises(TypeError):
            decision["verdict"] = 2  # type: ignore[index]

    def test_only_recorded_says_the_record_landed(self) -> None:
        for written, named in (
            (b'{"ending":"ENDING_UNRECORDED"}', "ENDING_UNRECORDED"),
            (b'{"ending":"ENDING_ABANDONED"}', "ENDING_ABANDONED"),
            (b'{"ending":"ENDING_RECORD_FAILED"}', "ENDING_RECORD_FAILED"),
            (b'{"ending":3}', "ENDING_UNRECORDED"),
            (b'{"ending":9}', "9"),
            (b'{"ending":"ENDING_UNSPECIFIED"}', ""),
            (b'{"ending":0}', ""),
            (b"{}", ""),
        ):
            with self.subTest(written=written):
                client = self.serve(admit(EXECUTE), complete(written))
                with self.assertRaises(NotRecorded) as raised:
                    client.call("t", ARGUMENTS, self.entering(succeed))
                answer = raised.exception.answer
                self.assertEqual(
                    (answer.ran, answer.ending, answer.outcome), (True, named, "OUTCOME_EXECUTE")
                )
                self.assertEqual(
                    answer.result, Result(Status.SUCCESS, None, harness.BEFORE, harness.AFTER)
                )
                self.assertEqual(
                    answer.decision, {"schemaVersion": "1.0", "decisionId": "d-1", "verdict": 1}
                )
                self.assertEqual(len(self.sent()), 2)

    def test_the_integer_of_recorded_is_recorded(self) -> None:
        client = self.serve(admit(EXECUTE), complete(b'{"ending":1}'))
        self.assertEqual(client.call("t", ARGUMENTS, succeed).ending, "ENDING_RECORDED")

    def test_a_blocked_call_carries_the_decision_and_did_not_run(self) -> None:
        for written in (
            b'{"outcome":"OUTCOME_BLOCK","decision":{"schemaVersion":"1.0","verdict":"VERDICT_DENY","reasonCodes":["RULE_DENY"]}}',
            b'{"decision":{"schemaVersion":"1.0","verdict":"VERDICT_DENY","reasonCodes":["RULE_DENY"]}}',
            b'{"outcome":7,"decision":{"schemaVersion":"1.0","verdict":"VERDICT_DENY","reasonCodes":["RULE_DENY"]},'
            b'"execution":{"handle":"h-1","authorizedArguments":"eyJhIjoxfQ=="}}',
        ):
            with self.subTest(written=written):
                client = self.serve(admit(written), complete())
                with self.assertRaises(CallBlocked) as raised:
                    client.call("t", ARGUMENTS, self.untouched)
                self.assertEqual(
                    raised.exception.answer,
                    Answer(
                        outcome="OUTCOME_BLOCK",
                        decision={
                            "schemaVersion": "1.0",
                            "verdict": "VERDICT_DENY",
                            "reasonCodes": ("RULE_DENY",),
                        },
                        held=None,
                        ran=False,
                        result=None,
                        ending="",
                    ),
                )
                self.assertEqual(self.sent(), [self.admitted])

    def test_a_pending_call_says_when_to_ask_again(self) -> None:
        client = self.serve(
            admit(
                b'{"outcome":"OUTCOME_PENDING","decision":{"schemaVersion":"1.0","verdict":3},"pending":{"approvalId":"ap-1",'
                b'"actionDigest":"sha256:9f2c","expiresAt":"2026-10-11T13:00:00.250Z","retryAfter":"1.500s"}}'
            )
        )
        with self.assertRaises(CallPending) as raised:
            client.call("t", ARGUMENTS, self.untouched)
        answer = raised.exception.answer
        self.assertEqual(
            answer.held,
            Held(
                approval_id="ap-1",
                action_digest="sha256:9f2c",
                expires_at=datetime(2026, 10, 11, 13, 0, 0, 250000, tzinfo=UTC),
                retry_after=timedelta(seconds=1, milliseconds=500),
            ),
        )
        self.assertEqual(
            (answer.outcome, answer.ran, answer.decision),
            ("OUTCOME_PENDING", False, {"schemaVersion": "1.0", "verdict": 3}),
        )
        self.assertEqual(self.sent(), [self.admitted])

    def test_a_held_call_keeps_its_times_to_the_microsecond(self) -> None:
        for written, kept in (
            ("0.000000001s", timedelta(0)),
            ("1.999999999s", timedelta(seconds=1, microseconds=999999)),
            ("-1.999999999s", timedelta(seconds=-1, microseconds=-999999)),
        ):
            with self.subTest(written=written):
                body = (
                    b'{"outcome":"OUTCOME_PENDING","pending":{"expiresAt":'
                    b'"2026-10-11T13:00:00.999999999Z","retryAfter":"' + written.encode() + b'"}}'
                )
                with self.assertRaises(CallPending) as raised:
                    self.serve(admit(body)).call("t", ARGUMENTS, self.untouched)
                expires = datetime(2026, 10, 11, 13, 0, 0, 999999, tzinfo=UTC)
                self.assertEqual(raised.exception.answer.held, Held("", "", expires, kept))

    def test_a_pending_answer_that_names_nothing_is_still_held(self) -> None:
        client = self.serve(admit(b'{"outcome":3}'))
        with self.assertRaises(CallPending) as raised:
            client.call("t", ARGUMENTS, self.untouched)
        self.assertEqual(raised.exception.answer.held, Held("", "", None, None))

    def test_a_refusal_carries_its_status_code_message_and_ending(self) -> None:
        client = self.serve(admit(b'{"code":"ERROR_CODE_UNAVAILABLE","message":"down"}', 503))
        with self.assertRaises(CallRefused) as raised:
            client.call("t", ARGUMENTS, self.untouched)
        refused = raised.exception
        self.assertEqual(
            (refused.status, refused.code, refused.message), (503, "ERROR_CODE_UNAVAILABLE", "down")
        )
        self.assertEqual(refused.answer, Answer("OUTCOME_BLOCK", None, None, False, None, ""))
        self.assertEqual(self.sent(), [self.admitted])

        client = self.serve(
            admit(EXECUTE),
            complete(b'{"code":5,"message":"spent","ending":"ENDING_ABANDONED"}', 409),
            complete(),
        )
        with self.assertRaises(CallRefused) as raised:
            client.call("t", ARGUMENTS, self.entering(succeed))
        refused = raised.exception
        self.assertEqual(
            (refused.status, refused.code, refused.message),
            (409, "ERROR_CODE_HANDLE_SPENT", "spent"),
        )
        self.assertEqual((refused.answer.ran, refused.answer.ending), (True, "ENDING_ABANDONED"))
        self.assertEqual(
            refused.answer.result, Result(Status.SUCCESS, None, harness.BEFORE, harness.AFTER)
        )
        self.assertEqual(len(self.sent()), 2)

    def test_a_long_refusal_keeps_its_message_and_quotes_a_bounded_part(self) -> None:
        written = b'{"code":"ERROR_CODE_UNAVAILABLE","message":"' + b"m" * 100000 + b'"}'
        client = self.serve(admit(written, 503))
        with self.assertRaises(CallRefused) as raised:
            client.call("t", ARGUMENTS, self.untouched)
        refused = raised.exception
        self.assertEqual(refused.message, "m" * 100000)
        quoted = "503 ERROR_CODE_UNAVAILABLE: '" + "m" * 120 + "... (cut from 100000 characters)'"
        self.assertEqual(str(refused), "the receiver refused the request: " + quoted)
        self.assertEqual(str(refused.__cause__), quoted)
        self.assertLess(len("".join(traceback.format_exception(refused))), 10000)

    def test_a_long_malformed_answer_is_quoted_in_a_bounded_part(self) -> None:
        cut = "g" * 120 + "... (cut from 100000 characters)"
        for status, said in (
            (200, f"{cut}: no member of AdmitResponse"),
            (500, f"status 500 with no readable error body: {cut}: no member of Error"),
        ):
            with self.subTest(status=status):
                client = self.serve(admit(b'{"' + b"g" * 100000 + b'":1}', status))
                with self.assertRaises(MalformedAnswer) as raised:
                    client.call("t", ARGUMENTS, self.untouched)
                self.assertEqual(
                    str(raised.exception), "the receiver's answer is malformed: " + said
                )
                self.assertLess(len("".join(traceback.format_exception(raised.exception))), 10000)

    def test_a_refusal_with_no_code_or_an_undeclared_one(self) -> None:
        for written, code in ((b"{}", ""), (b'{"code":0}', ""), (b'{"code":42}', "42")):
            with self.subTest(written=written):
                client = self.serve(admit(written, 500))
                with self.assertRaises(CallRefused) as raised:
                    client.call("t", ARGUMENTS, self.untouched)
                self.assertEqual((raised.exception.status, raised.exception.code), (500, code))

    def test_an_answer_the_client_cannot_act_on_sends_nothing(self) -> None:
        for what, written, names in (
            (
                "no handle",
                b'{"outcome":"OUTCOME_EXECUTE","decision":{"schemaVersion":"1.0","verdict":1},"execution":{"authorizedArguments":"eyJhIjoxfQ=="}}',
                "no handle",
            ),
            (
                "an empty handle",
                b'{"outcome":1,"decision":{"schemaVersion":"1.0","verdict":1},"execution":{"handle":""}}',
                "no handle",
            ),
            (
                "no execution",
                b'{"outcome":"OUTCOME_EXECUTE","decision":{"schemaVersion":"1.0","verdict":1}}',
                "no handle",
            ),
            (
                "an error body under 200",
                b'{"code":"ERROR_CODE_UNAVAILABLE"}',
                "code: no member of AdmitResponse",
            ),
            (
                "a member it does not know",
                EXECUTE[:-1] + b',"grant":"all"}',
                "grant: no member of AdmitResponse",
            ),
            (
                "an enum name it does not know",
                EXECUTE.replace(b'"verdict":1', b'"verdict":"VERDICT_LATER"'),
                "'VERDICT_LATER' is no name of Verdict",
            ),
        ):
            with self.subTest(what=what):
                client = self.serve(admit(written), complete())
                with self.assertRaisesRegex(MalformedAnswer, names) as raised:
                    client.call("t", ARGUMENTS, self.untouched)
                answer = raised.exception.answer
                self.assertEqual(
                    (answer.ran, answer.outcome, answer.ending), (False, "OUTCOME_BLOCK", "")
                )
                self.assertEqual(self.sent(), [self.admitted])

    def test_an_execute_with_no_handle_still_carries_its_decision(self) -> None:
        client = self.serve(
            admit(b'{"outcome":1,"decision":{"schemaVersion":"1.0","verdict":1},"execution":{}}')
        )
        with self.assertRaises(MalformedAnswer) as raised:
            client.call("t", ARGUMENTS, self.untouched)
        self.assertEqual(raised.exception.answer.decision, {"schemaVersion": "1.0", "verdict": 1})

    def test_a_malformed_answer_to_complete_says_the_tool_ran(self) -> None:
        client = self.serve(
            admit(EXECUTE), complete(b'{"ending":"ENDING_RECORDED","grant":"all"}'), complete()
        )
        with self.assertRaisesRegex(
            MalformedAnswer, "grant: no member of CompleteResponse"
        ) as raised:
            client.call("t", ARGUMENTS, self.entering(succeed))
        self.assertEqual((raised.exception.answer.ran, raised.exception.answer.ending), (True, ""))
        self.assertEqual(len(self.sent()), 2)
