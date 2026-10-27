"""The verdict of each qualification case, read from what its invocations left behind.

A case whose tool call was not made, or whose observation is missing or
cannot be read, is unknown, never passed; so is a claim about what reached the
model when the stream holds no answer to the call, and a claim that something
was not recorded when nothing in the same run shows the recorder recording.
The judges of a held approval are in harness_hold.py, those of a rewritten
input in harness_rewrite.py; both build on the helpers here.
"""

import os
from collections.abc import Callable, Iterable
from typing import Any, NamedTuple

from harness_observed import PROGRAM, Inv, Record, scrub

PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"

# The status a hook exits with to block a call.
BLOCK = 2

Verdict = tuple[str, Record, str]
Cases = Callable[[str, str], Inv]


def exits(evs: Iterable[Record]) -> list[Any]:
    return [e["meta"].get("exit") for e in evs]


def missing(*invs: Inv) -> str | None:
    """Why these invocations cannot be judged, or None."""
    for inv in invs:
        reasons = (
            (inv.unselected, "not run: QUALIFY_ONLY left out " + inv.name),
            (inv.skipped, "skipped: the invocation cap was reached before " + inv.name),
            (not inv.ran, "the runtime was not run for " + inv.name),
            (not inv.observed_files, "the project's snapshot could not be read for " + inv.name),
            (not inv.observed_trail, "the trail could not be read for " + inv.name),
            (bool(inv.problem), str(inv.problem)),
        )
        why = next((text for hit, text in reasons if hit), None)
        if why:
            return why
    return None


def reason(said: str) -> str:
    """The runtime's reason after the hook command it names, which holds
    local paths and is left out."""
    if "]: " not in said:
        return ""
    return scrub(PROGRAM.sub("", said.rsplit("]: ", 1)[-1].splitlines()[0]))


def silent(admits: Iterable[Record]) -> bool:
    """Whether every admit the bridge let run was answered with nothing on
    standard output, which is the only reply that cannot widen a call."""
    return all(e["meta"].get("stdout") == "" for e in admits if e["meta"].get("exit") == 0)


def not_called(inv: Inv, tool: str, evs: list[Record]) -> str | None:
    if not inv.tool_uses(tool):
        return f"the model made no {tool} call in {inv.name}"
    if not evs:
        return (
            f"no PreToolUse event of the {tool} call the case asked for was recorded in {inv.name}"
        )
    return None


def verdict(expected: str, observed: Record, ok: bool, why: str | None = None) -> Verdict:
    if why:
        return expected, dict(observed, unknown=why), UNKNOWN
    return expected, observed, PASS if ok else FAIL


def holds(inv: Inv, base: str, want: object) -> bool:
    """Whether the project's snapshot holds base with the text want, a string."""
    return isinstance(want, str) and base in inv.files and inv.files[base] == want


def edit_applied(seed: str, admits: list[Record]) -> str | None:
    """The seed with the first admitted edit applied, or None."""
    if not admits:
        return None
    i = admits[0]["input"]
    old, new = i.get("old_string"), i.get("new_string")
    if not isinstance(old, str) or not isinstance(new, str) or old not in seed:
        return None
    return seed.replace(old, new, 1)


# cases


def judge_allow(c: Cases) -> Verdict:
    inv = c("allow", "run")
    admits = inv.hook("PreToolUse", "Write", "note.txt")
    expected = (
        "the Write is let run silently (exit 0); note.txt holds the content its admit proposed; "
        "the trail closes the call ACTION_COMPLETED; no EXECUTED_ARGS_MISMATCH"
    )
    why = missing(inv) or not_called(inv, "Write", admits)
    proposed = admits[0]["input"].get("content") if admits else None
    reqs = inv.on("Write", "note.txt")
    mismatch = any(
        "EXECUTED_ARGS_MISMATCH" in r["protocol"] + r["codes"] for r in inv.requests().values()
    )
    observed = {
        "admit_exits": exits(admits),
        "admit_stdout": [e["meta"].get("stdout") for e in admits],
        "file": inv.files.get("note.txt"),
        "proposed": proposed,
        "trail": [r["kinds"] for r in reqs],
        "mismatch": mismatch,
    }
    ok = (
        exits(admits) == [0]
        and silent(admits)
        and holds(inv, "note.txt", proposed)
        and any("ACTION_COMPLETED" in r["kinds"] for r in reqs)
        and not mismatch
    )
    return verdict(expected, observed, ok, why)


def judge_block(inv: Inv) -> Verdict:
    admits = inv.hook("PreToolUse", "Bash")
    expected = (
        "the Bash call is blocked: its PreToolUse exits 2, no file marker appears, "
        "the trail ends it ACTION_BLOCKED with RULE_DENY"
    )
    why = missing(inv) or not_called(inv, "Bash", admits)
    if not why and any(e["input"].get("command") != "touch marker" for e in admits):
        why = "the model asked for another command than touch marker in " + inv.name
    reqs = [r for r in inv.requests().values() if r.get("name") == "Bash"]
    observed = {
        "admit_exits": exits(admits),
        "marker": "marker" in inv.files,
        "trail": [(r["kinds"], r["codes"]) for r in reqs],
    }
    ok = (
        bool(admits)
        and all(x == BLOCK for x in exits(admits))
        and "marker" not in inv.files
        and bool(reqs)
        and all("ACTION_BLOCKED" in r["kinds"] and "RULE_DENY" in r["codes"] for r in reqs)
    )
    return verdict(expected, observed, ok, why)


class Effect(NamedTuple):
    """A Write case judged by judge_effect: the file it writes, whether the
    Write must run, what is expected, the act of its PreToolUse hook, the
    runtime's words for a refusal, the status every admit must exit with, and
    whether the hook must be recorded as having printed and exited 0."""

    base: str
    runs: bool
    expected: str
    act: str
    said: tuple[str, ...] = ()
    exit_status: int | None = None
    printed: bool = False


def judge_effect(c: Cases, group: str, e: Effect) -> Verdict:
    """A Write that runs, or not, as the case's PreToolUse hook makes it. Every
    PreToolUse hook of the Write must have been the case's act, so another
    hook's answer cannot stand in for it."""
    inv = c(group, "run")
    admits = inv.hook("PreToolUse", "Write", e.base)
    why = missing(inv) or not_called(inv, "Write", admits)
    acts = sorted({str(a["meta"].get("act")) for a in admits})
    if not why and acts != [e.act]:
        why = f"the Write's PreToolUse hooks were {acts}, not {e.act} alone"
    writes = [
        u
        for u in inv.calls()
        if u["name"] == "Write" and os.path.basename(str(u["input"].get("file_path"))) == e.base
    ]
    if not why and not all(inv.in_project(u["input"].get("file_path")) for u in writes):
        why = f"the model wrote {e.base} outside the project"
    if (
        not why
        and e.printed
        and not all(a["meta"].get("exit") == 0 and a["meta"].get("stdout") for a in admits)
    ):
        why = "the hook's exit and output were not recorded as written and 0"
    if not why and any(inv.result(u["id"]) is None for u in writes):
        why = f"the stream of {inv.name} holds no answer to the Write call"
    refused = bool(writes) and all(inv.refused(u["id"]) for u in writes)
    worded = bool(writes) and all(all(w in inv.said(u["id"]) for w in e.said) for u in writes)
    observed = {
        "pre_hook": [(a["meta"].get("act"), a["meta"].get("exit")) for a in admits],
        "file": inv.files.get(e.base),
        "runtime_returned": inv.returned(),
        "write_refused": refused,
        "refusal": [reason(inv.said(u["id"])) for u in writes if inv.refused(u["id"])],
    }
    ok = (
        inv.returned()
        and (e.base in inv.files) == e.runs
        and refused != e.runs
        and worded
        and (e.exit_status is None or set(exits(admits)) == {e.exit_status})
    )
    return verdict(e.expected, observed, ok, why)


def judge_disabled(c: Cases) -> Verdict:
    """No event under disableAllHooks says something only beside a control:
    the same recorder and settings, without it, recording the same Write."""
    inv, ctl = c("disabled", "run"), c("disabled", "control")
    recorded = ctl.hook("PreToolUse", "Write", "disabled-control.txt")
    why = (
        missing(inv, ctl)
        or (None if inv.tool_uses("Write") else "the model made no Write call in " + inv.name)
        or not_called(ctl, "Write", recorded)
    )
    observed = {
        "events_recorded": len(inv.events),
        "file": inv.files.get("disabled.txt"),
        "control_events": len(recorded),
    }
    ok = "disabled.txt" in inv.files and not inv.events
    return verdict(
        "with disableAllHooks the Write runs and no hook event is recorded (a stated bypass), "
        "where the same settings without it record the Write's PreToolUse",
        observed,
        ok,
        why,
    )


def judge_mcp(c: Cases) -> Verdict:
    """No event for the MCP tool says something only when the recorder is seen
    recording a call that is not one in the same invocation."""
    inv = c("mcp-matcher", "run")
    why = missing(inv) or (
        None if inv.tool_uses("mcp__") else "the model made no MCP tool call in " + inv.name
    )
    others = {u["id"] for u in inv.calls() if not str(u["name"]).startswith("mcp__") and u["id"]}
    recorded = [
        e["tool"]
        for e in inv.events
        if e["kind"] == "PreToolUse" and not e["tool"].startswith("mcp__") and e["call"] in others
    ]
    hooked = [e["tool"] for e in inv.events if e["tool"].startswith("mcp__")]
    ran = "mcp-ran.txt" in inv.files
    observed = {"mcp_events": hooked, "tool_ran": ran, "control_events": recorded}
    if not why and not recorded:
        why = (
            "no PreToolUse event of a call that is not an MCP one was recorded in "
            + inv.name
            + ", so the recorder was not seen recording"
        )
    if not why and not hooked and not ran:
        why = "the MCP tool did not run, so the matcher was not exercised"
    return verdict(
        "the matcher leaves the mcp__ tool out: no hook event for it, and the tool ran, "
        "where another call of the same invocation reached the hook",
        observed,
        ran and not hooked,
        why,
    )


def judge_subagent(c: Cases) -> Verdict:
    inv = c("subagent", "run")
    agents = {u["id"] for u in inv.calls() if u["name"] == "Agent" and not u["parent"]}
    writes = {u["id"] for u in inv.calls() if u["name"] == "Write" and u["parent"] in agents}
    admits = [
        e for e in inv.hook("PreToolUse", "Write", "sub.txt") if e["agent"] and e["call"] in writes
    ]
    why = (
        missing(inv)
        or (None if agents else "the model made no Agent call in " + inv.name)
        or (None if writes else "no Write ran under the Agent call in " + inv.name)
        or (
            None
            if admits
            else "no PreToolUse event of the sub-agent's Write of sub.txt was recorded"
        )
    )
    reqs = inv.on("Write", "sub.txt")
    observed = {
        "agent_calls": len(agents),
        "sub_agent_writes": len(writes),
        "admit_exits": exits(admits),
        "decided": [r.get("verdict") for r in reqs],
        "file": inv.files.get("sub.txt"),
    }
    ok = bool(admits) and any(r.get("verdict") for r in reqs)
    return verdict(
        "a Write a sub-agent makes under the Agent call reaches the hook with the sub-agent's id, "
        "and the plane decides it",
        observed,
        ok,
        why,
    )


def control(
    inner: Verdict, caught_when: str, expected: str, broke: Callable[[Record], bool]
) -> Verdict:
    """A negative control passes when the case under the broken bridge is
    judged caught_when for the reason the broken bridge gives: broke(observed)."""
    _, observed, v = inner
    if v == UNKNOWN:
        why = "the expectation under the broken bridge was not judged"
        return expected, dict(observed, unknown=why), UNKNOWN
    ok = v == caught_when and broke(observed)
    return expected, dict(observed, judged=v), PASS if ok else FAIL
