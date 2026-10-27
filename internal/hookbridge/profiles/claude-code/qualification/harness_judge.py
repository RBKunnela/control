"""The result of every qualification case, from the judges in harness_verdicts.py,
harness_hold.py and harness_rewrite.py."""

import os

from harness_hold import judge_concurrent, judge_obligation, judge_pending
from harness_observed import Inv, Record, load_json
from harness_rewrite import FAILING, judge_rewrite, judge_rewrite_denied
from harness_verdicts import (
    FAIL,
    PASS,
    UNKNOWN,
    Effect,
    Verdict,
    control,
    judge_allow,
    judge_block,
    judge_disabled,
    judge_effect,
    judge_mcp,
    judge_subagent,
)


def judged(cases: str, events_root: str, work: str | None = None) -> list[Record]:
    """The result of every case, read from cases and events_root."""
    cache: dict[tuple[str, str], Inv] = {}

    def c(group: str, name: str) -> Inv:
        key = (group, name)
        if key not in cache:
            cache[key] = Inv(cases, events_root, group, name, work)
        return cache[key]

    seeds = load_json(os.path.join(cases, "seeds.json"))
    if not isinstance(seeds, dict):
        raise ValueError("no seeds.json in " + cases)
    results: list[tuple[str, list[Inv], Verdict]] = [
        ("allow", [c("allow", "run")], judge_allow(c)),
        ("block", [c("block", "run")], judge_block(c("block", "run"))),
    ]
    results += judge_pending(c, seeds)
    hold = [c("concurrent", "hold"), c("concurrent", "race")]
    results.append(("concurrent", hold, judge_concurrent(c, seeds)))
    results.append(("obligation", [c("obligation", "run")], judge_obligation(c, seeds)))
    down = Effect(
        "down.txt",
        False,
        "with the plane's socket pointing nowhere the bridge exits 2 and the Write is "
        "blocked: no down.txt",
        "pass",
        exit_status=2,
    )
    results.append(("plane-down", [c("plane-down", "run")], judge_effect(c, "plane-down", down)))
    for group, runs, how in FAILING_CASES:
        act, said = FAILING[group]
        e = Effect(group + ".txt", runs, how, act, said, printed=act == "garbage")
        results.append((group, [c(group, "run")], judge_effect(c, group, e)))
    disabled = [c("disabled", "run"), c("disabled", "control")]
    results.append(("disabled", disabled, judge_disabled(c)))
    rewrite = judge_rewrite(c("rewrite", "run"), seeds["replacement"])
    results.append(("rewrite", [c("rewrite", "run")], rewrite))
    results.append(("rewrite-denied", [c("rewrite-denied", "run")], judge_rewrite_denied(c)))
    results.append(("mcp-matcher", [c("mcp-matcher", "run")], judge_mcp(c)))
    results.append(("subagent", [c("subagent", "run")], judge_subagent(c)))
    results.append(
        (
            "control-allow-all",
            [c("control-allow-all", "run")],
            control(
                judge_block(c("control-allow-all", "run")),
                FAIL,
                "the block case through a bridge that lets every call run is judged failed, "
                "because the marker was made",
                lambda o: o.get("marker") is True,
            ),
        )
    )
    results.append(
        (
            "control-report-proposed",
            [c("control-report-proposed", "run")],
            report_proposed(c("control-report-proposed", "run"), seeds["replacement"], rewrite),
        )
    )
    out = []
    for case_id, invs, (expected, observed, v) in results:
        pre = [
            [e["tool"], e["meta"].get("exit"), e["meta"].get("stderr", "").strip()]
            for i in invs
            for e in i.events
            if e["kind"] == "PreToolUse" and e["meta"].get("act") == "pass"
        ]
        out.append(
            {
                "id": case_id,
                "invocations": sum(i.ran for i in invs),
                "expected": expected,
                "observed": dict(observed, pre_tool_use=pre),
                "verdict": v,
            }
        )
    return out


FAILING_CASES = (
    (
        "timeout-block",
        False,
        "a PreToolUse hook that outlives its 5 s timeout, under onFailure block, blocks the Write",
    ),
    ("timeout-open", True, "the same hook without onFailure lets the Write run"),
    (
        "crash-block",
        False,
        "a PreToolUse hook killed by a signal, under onFailure block, blocks the Write",
    ),
    ("crash-open", True, "the same hook without onFailure lets the Write run"),
    (
        "garbage",
        True,
        "a PreToolUse hook that prints unreadable output and exits 0 lets the Write run",
    ),
)


def report_proposed(inv: Inv, replacement: str, rewrite: Verdict) -> Verdict:
    ctl = control(
        judge_rewrite(inv, replacement),
        FAIL,
        "the rewrite case through a bridge that reports the authorized input as the one "
        "that ran is judged failed, because the replacement ran and no mismatch was "
        "recorded, where the real bridge's mismatch was seen",
        lambda o: (
            o.get("bridge_exits") == [0]
            and o.get("written") == replacement
            and o.get("mismatch") is False
        ),
    )
    if rewrite[2] != PASS:
        why = "the real bridge showed no mismatch in rewrite to compare with"
        return ctl[0], dict(ctl[1], unknown=why), UNKNOWN
    return ctl
