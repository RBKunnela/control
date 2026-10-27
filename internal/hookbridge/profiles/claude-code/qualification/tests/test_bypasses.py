import unittest
from typing import Any

from tests import layouts
from tests.observations import Run


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.run_ = Run()
        self.addCleanup(self.run_.close)

    def result(self, case_id: str) -> tuple[str, Any]:
        r = self.run_.result(case_id)
        return r["verdict"], r["observed"].get("unknown")


class Disabled(Case):
    def test_no_event_beside_a_recording_control_passes(self) -> None:
        layouts.disabled(self.run_)
        self.assertEqual(self.result("disabled"), ("pass", None))

    def test_an_event_under_disable_fails(self) -> None:
        layouts.disabled(self.run_, events=True)
        self.assertEqual(self.result("disabled"), ("fail", None))

    def test_no_control_invocation_is_unknown(self) -> None:
        layouts.disabled(self.run_)
        self.run_.inv("disabled", "control").drop("runtime-1.exit")
        want = "the runtime was not run for disabled/control"
        self.assertEqual(self.result("disabled"), ("unknown", want))

    def test_a_control_that_recorded_nothing_is_unknown(self) -> None:
        layouts.disabled(self.run_, control=False)
        want = (
            "no PreToolUse event of the Write call the case asked for was recorded in "
            "disabled/control"
        )
        self.assertEqual(self.result("disabled"), ("unknown", want))


class Matcher(Case):
    def test_no_mcp_event_beside_a_recorded_call_passes(self) -> None:
        layouts.mcp(self.run_)
        self.assertEqual(self.result("mcp-matcher"), ("pass", None))

    def test_an_mcp_event_fails(self) -> None:
        layouts.mcp(self.run_, hooked=True)
        self.assertEqual(self.result("mcp-matcher"), ("fail", None))

    def test_no_recorded_call_beside_it_is_unknown(self) -> None:
        layouts.mcp(self.run_, control=False)
        want = (
            "no PreToolUse event of a call that is not an MCP one was recorded in "
            "mcp-matcher/run, so the recorder was not seen recording"
        )
        self.assertEqual(self.result("mcp-matcher"), ("unknown", want))

    def test_a_tool_that_did_not_run_is_unknown(self) -> None:
        layouts.mcp(self.run_, ran=False)
        want = "the MCP tool did not run, so the matcher was not exercised"
        self.assertEqual(self.result("mcp-matcher"), ("unknown", want))


class Rewrite(Case):
    def test_the_replacement_seen_as_a_mismatch_passes(self) -> None:
        layouts.rewrite(self.run_)
        self.assertEqual(self.result("rewrite"), ("pass", None))

    def test_the_proposed_content_written_fails(self) -> None:
        layouts.rewrite(self.run_, written="hello")
        self.assertEqual(self.result("rewrite"), ("fail", None))

    def test_no_mismatch_fails(self) -> None:
        layouts.rewrite(self.run_, mismatch=False)
        self.assertEqual(self.result("rewrite"), ("fail", None))

    def test_unread_health_is_unknown(self) -> None:
        layouts.rewrite(self.run_).drop("healthz.before.json")
        want = "the plane's count of halted runs was not read for rewrite/run"
        self.assertEqual(self.result("rewrite"), ("unknown", want))


class RewriteDenied(Case):
    def test_a_denied_rewrite_that_halted_nothing_passes(self) -> None:
        layouts.rewrite_denied(self.run_)
        self.assertEqual(self.result("rewrite-denied"), ("pass", None))

    def test_a_halted_run_fails(self) -> None:
        layouts.rewrite_denied(self.run_, halted=True)
        self.assertEqual(self.result("rewrite-denied"), ("fail", None))


class Subagent(Case):
    def test_a_sub_agents_write_decided_passes(self) -> None:
        layouts.subagent(self.run_)
        self.assertEqual(self.result("subagent"), ("pass", None))

    def test_a_write_not_under_the_agent_is_unknown(self) -> None:
        layouts.subagent(self.run_, under_agent=False)
        want = "no Write ran under the Agent call in subagent/run"
        self.assertEqual(self.result("subagent"), ("unknown", want))


class Controls(Case):
    def test_the_allow_all_bridge_caught_by_its_marker_passes(self) -> None:
        layouts.allow_all(self.run_)
        self.assertEqual(self.result("control-allow-all"), ("pass", None))

    def test_the_allow_all_bridge_with_no_marker_fails(self) -> None:
        layouts.allow_all(self.run_, marker=False)
        self.assertEqual(self.result("control-allow-all"), ("fail", None))

    def test_the_report_proposed_bridge_caught_passes(self) -> None:
        layouts.rewrite(self.run_)
        layouts.rewrite(self.run_, "control-report-proposed", mismatch=False)
        self.assertEqual(self.result("control-report-proposed"), ("pass", None))

    def test_the_report_proposed_bridge_showing_a_mismatch_fails(self) -> None:
        layouts.rewrite(self.run_)
        layouts.rewrite(self.run_, "control-report-proposed")
        self.assertEqual(self.result("control-report-proposed"), ("fail", None))

    def test_report_proposed_with_no_real_mismatch_to_compare_is_unknown(self) -> None:
        layouts.rewrite(self.run_, mismatch=False)
        layouts.rewrite(self.run_, "control-report-proposed", mismatch=False)
        want = "the real bridge showed no mismatch in rewrite to compare with"
        self.assertEqual(self.result("control-report-proposed"), ("unknown", want))
