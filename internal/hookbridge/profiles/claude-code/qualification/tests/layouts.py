"""For each case, the observations of a run that passes it; each knob breaks
one thing the case is judged by."""

import json
from typing import Any

from tests.observations import SEEDS, Invocation, Run

PROPOSED = ["ACTION_PROPOSED", "POLICY_DECIDED"]
RAN = [*PROPOSED, "ACTION_STARTED", "ACTION_COMPLETED"]
HELD = "A1B2C3D4E5F6G7H8J9K0L1M2N3"
RACED = "B1B2C3D4E5F6G7H8J9K0L1M2N3"
BLOCKED_BY_HOOK = 'onFailure is "block"'


def write(inv: Invocation, base: str, content: str = "hello", **answer: Any) -> tuple[Any, str]:
    i = {"file_path": inv.path(base), "content": content}
    return i, inv.call("Write", i, **answer)


def edit(inv: Invocation, base: str, old: str, new: str) -> dict[str, Any]:
    return {"file_path": inv.path(base), "old_string": old, "new_string": new, "replace_all": False}


def allow(
    run: Run, written: str | None = "hello", content: str | None = "hello", stdout: str = ""
) -> Invocation:
    inv = run.inv("allow")
    i: dict[str, Any] = {"file_path": inv.path("note.txt")}
    if content is not None:
        i["content"] = content
    inv.hook("PreToolUse", "Write", i, inv.call("Write", i), stdout=stdout)
    inv.snapshot({} if written is None else {"note.txt": written})
    inv.request("r-allow", "Write", "note.txt", RAN)
    return inv


def block(run: Run, marker: bool = False, command: str = "touch marker") -> Invocation:
    inv = run.inv("block")
    i = {"command": command}
    cid = inv.call("Bash", i, answer="blocked by policy (RULE_DENY)", error=True)
    inv.hook("PreToolUse", "Bash", i, cid, exit=2, stderr="blocked by policy (RULE_DENY)\n")
    inv.snapshot({"marker": ""} if marker else {})
    inv.request("r-block", "Bash", "cmd", [*PROPOSED, "ACTION_BLOCKED"], reasonCodes=["RULE_DENY"])
    return inv


def allow_all(run: Run, marker: bool = True) -> Invocation:
    inv = run.inv("control-allow-all")
    i = {"command": "touch marker"}
    inv.hook("PreToolUse", "Bash", i, inv.call("Bash", i))
    inv.snapshot({"marker": ""} if marker else {})
    return inv


def pending(
    run: Run,
    old: str = "port = 3000",
    resumed: str | None = "port = 8080\n",
    used: str = "ALREADY_USED",
) -> None:
    held = run.inv("pending", "held")
    i = edit(held, "target.txt", old, "port = 8080")
    stderr = f"held for approval {HELD}; once it is approved, ask again after 1s"
    held.hook("PreToolUse", "Edit", i, held.call("Edit", i, error=True), exit=2, stderr=stderr)
    held.snapshot({"target.txt": SEEDS["target.txt"]})
    held.put("approvals.txt", f"approval {HELD}\n  state          x\n  resolution     pending\n")
    held.put("approved.json", json.dumps({"approval": HELD, "exit": 0}))
    held.request(
        "r-held", "Edit", "target.txt", PROPOSED, actionDigest="sha256:d1", approvalId=HELD
    )

    again = run.inv("pending", "resumed")
    again.hook("PreToolUse", "Edit", i, again.call("Edit", i))
    again.snapshot({} if resumed is None else {"target.txt": resumed})
    again.trail += held.trail
    again.request("r-resumed", "Edit", "target.txt", RAN, actionDigest="sha256:d1")

    third = run.inv("pending", "used")
    stderr = f"blocked by policy (APPROVAL_{used})\n"
    third.hook("PreToolUse", "Edit", i, third.call("Edit", i, error=True), exit=2, stderr=stderr)
    third.snapshot({"target.txt": SEEDS["target.txt"]})
    third.trail += again.trail
    third.request("r-used", "Edit", "target.txt", [*PROPOSED, "ACTION_BLOCKED"])


def concurrent(run: Run, other: str = "mode = final", old: str = "mode = draft") -> None:
    hold = run.inv("concurrent", "hold")
    i = edit(hold, "second.txt", old, "mode = final")
    stderr = f"held for approval {RACED}; once it is approved, ask again after 1s"
    hold.hook("PreToolUse", "Edit", i, hold.call("Edit", i, error=True), exit=2, stderr=stderr)
    hold.snapshot({"second.txt": SEEDS["second.txt"]})
    hold.put("approved.json", json.dumps({"approval": RACED, "exit": 0}))
    hold.request(
        "r-hold", "Edit", "second.txt", PROPOSED, actionDigest="sha256:d2", approvalId=RACED
    )

    race = run.inv("concurrent", "race")
    race.put("runtime-2.exit", "0\n")
    race.put("stream-2.jsonl", "")
    j = edit(race, "second.txt", old, other)
    race.hook("PreToolUse", "Edit", i, race.call("Edit", i))
    stderr = "blocked by policy (APPROVAL_ALREADY_USED)\n"
    race.hook("PreToolUse", "Edit", j, race.call("Edit", j, error=True), exit=2, stderr=stderr)
    race.snapshot({"second.txt": "mode = final\n"} if old in SEEDS["second.txt"] else {})
    race.trail += hold.trail
    race.request("r-a", "Edit", "second.txt", RAN, actionDigest="sha256:d2")
    race.request(
        "r-b", "Edit", "second.txt", [*PROPOSED, "ACTION_BLOCKED"], actionDigest="sha256:d2"
    )


def obligation(run: Run, answer: str = "blocked: the obligation cannot be met") -> Invocation:
    inv = run.inv("obligation")
    i = {"file_path": inv.path("secret.txt")}
    cid = inv.call("Read", i, answer=answer, error=True)
    inv.hook("PreToolUse", "Read", i, cid, exit=2, stderr="blocked by policy (OBLIGATION)\n")
    inv.request(
        "r-ob",
        "Read",
        "secret.txt",
        [*PROPOSED, "ACTION_FAILED"],
        result=("RESULT_STATUS_BLOCKED", "TOOL_PROTOCOL_STATUS_OBLIGATION_UNMET"),
    )
    return inv


# The fake hook's act of each failing case, whether its Write runs, and what
# the runtime answers a blocked one with.
EFFECTS = {
    "plane-down": ("pass", False, "PreToolUse:Write [hook]: cannot reach the plane"),
    "timeout-block": ("sleep", False, f"hook timed out; blocking because {BLOCKED_BY_HOOK}"),
    "crash-block": ("crash", False, f"failed; blocking because {BLOCKED_BY_HOOK}"),
    "timeout-open": ("sleep", True, ""),
    "crash-open": ("crash", True, ""),
    "garbage": ("garbage", True, ""),
}


def effect(run: Run, group: str, runs: bool | None = None, act: str | None = None) -> Invocation:
    """The case's Write, run or refused as EFFECTS says unless runs is given."""
    hook_act, should_run, refusal = EFFECTS[group]
    runs = should_run if runs is None else runs
    inv = run.inv(group)
    base = "down.txt" if group == "plane-down" else group + ".txt"
    i, cid = write(inv, base, "ran", answer=refusal or "ok", error=not runs)
    meta: dict[str, Any] = {"act": act or hook_act}
    if hook_act == "pass":
        meta["exit"] = 2
    if hook_act == "garbage":
        meta["stdout"] = "�{not an answer\n"
    inv.hook("PreToolUse", "Write", i, cid, **meta)
    inv.snapshot({base: "ran"} if runs else {})
    return inv


def disabled(run: Run, control: bool = True, events: bool = False) -> None:
    inv = run.inv("disabled")
    i, cid = write(inv, "disabled.txt", "ran")
    if events:
        inv.hook("PreToolUse", "Write", i, cid)
    inv.snapshot({"disabled.txt": "ran"})
    ctl = run.inv("disabled", "control")
    i, cid = write(ctl, "disabled-control.txt", "ran")
    if control:
        ctl.hook("PreToolUse", "Write", i, cid)
    ctl.snapshot({"disabled-control.txt": "ran"})


def mcp(run: Run, control: bool = True, hooked: bool = False, ran: bool = True) -> None:
    inv = run.inv("mcp-matcher")
    stamp = inv.call("mcp__q__stamp", {}, answer="stamped")
    if hooked:
        inv.hook("PreToolUse", "mcp__q__stamp", {}, stamp)
    i, cid = write(inv, "mcp-control.txt", "ran")
    if control:
        inv.hook("PreToolUse", "Write", i, cid)
    inv.snapshot({"mcp-ran.txt": "stamped\n"} if ran else {})


def rewrite(
    run: Run, group: str = "rewrite", written: str = SEEDS["replacement"], mismatch: bool = True
) -> Invocation:
    inv = run.inv(group)
    i, cid = write(inv, "note.txt")
    inv.hook("PreToolUse", "Write", i, cid)
    inv.hook("PreToolUse", "Write", i, cid, act="rewrite")
    inv.hook("PostToolUse", "Write", dict(i, content=written), cid)
    inv.snapshot({"note.txt": written})
    protocol = "EXECUTED_ARGS_MISMATCH" if mismatch else ""
    inv.request("r-rw", "Write", "note.txt", RAN, result=("RESULT_STATUS_OK", protocol))
    inv.health(0, 1 if mismatch else 0)
    return inv


def rewrite_denied(run: Run, halted: bool = False) -> Invocation:
    inv = run.inv("rewrite-denied")
    i, cid = write(inv, "draft.txt", error=True)
    stderr = "the policy allows it only with a changed input\n"
    inv.hook("PreToolUse", "Write", i, cid, exit=2, stderr=stderr)
    result = ("RESULT_STATUS_BLOCKED", "EXECUTED_ARGS_MISMATCH")
    inv.request("r-rd", "Write", "draft.txt", [*PROPOSED, "ACTION_FAILED"], result=result)
    inv.health(0, 1 if halted else 0)
    return inv


def subagent(run: Run, under_agent: bool = True) -> Invocation:
    inv = run.inv("subagent")
    agent = inv.call("Agent", {"description": "write sub.txt"})
    i = {"file_path": inv.path("sub.txt"), "content": "sub"}
    cid = inv.call("Write", i, parent=agent if under_agent else None)
    inv.hook("PreToolUse", "Write", i, cid, agent="agent-1")
    inv.request("r-sub", "Write", "sub.txt", PROPOSED, verdict="VERDICT_ALLOW")
    return inv


def full(run: Run) -> None:
    """A run that passes every case."""
    allow(run)
    block(run)
    pending(run)
    concurrent(run)
    obligation(run)
    for group in EFFECTS:
        effect(run, group)
    disabled(run)
    rewrite(run)
    rewrite_denied(run)
    mcp(run)
    subagent(run)
    allow_all(run)
    rewrite(run, "control-report-proposed", mismatch=False)
