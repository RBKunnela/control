"""The verdict of each qualification case, read from what its invocations left behind.

A case whose tool call was not made, or whose observation is missing, is
unknown, never passed.
"""

import json
import os
import re
import sys

from harness_observed import PROGRAM, Inv, load_json, scrub

PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"


def exits(evs):
    return [e["meta"].get("exit") for e in evs]


def missing(*invs):
    """Why these invocations cannot be judged, or None."""
    for inv in invs:
        if inv.unselected:
            return "not run: QUALIFY_ONLY left out " + inv.name
        if inv.skipped:
            return "skipped: the invocation cap was reached before " + inv.name
        if not inv.ran:
            return "the runtime was not run for " + inv.name
        if not inv.observed_files:
            return "the project's snapshot could not be read for " + inv.name
        if not inv.observed_trail:
            return "the trail could not be read for " + inv.name
    return None


def reason(said):
    """The runtime's reason after the hook command it names, which holds
    local paths and is left out."""
    return scrub(PROGRAM.sub("", said.rsplit("]: ", 1)[-1].splitlines()[0])) if "]: " in said else ""


def silent(admits):
    """Whether every admit the bridge let run was answered with nothing on
    standard output, which is the only reply that cannot widen a call."""
    return all(e["meta"].get("stdout") == "" for e in admits if e["meta"].get("exit") == 0)


def not_called(inv, tool, evs):
    if not inv.tool_uses(tool):
        return "the model made no %s call in %s" % (tool, inv.name)
    if not evs:
        return "no PreToolUse event of the %s call the case asked for was recorded in %s" % (tool, inv.name)
    return None


def verdict(expected, observed, ok, why=None):
    if why:
        observed = dict(observed, unknown=why)
        return expected, observed, UNKNOWN
    return expected, observed, PASS if ok else FAIL


# cases


def judge_allow(c):
    inv = c("allow", "run")
    admits = inv.hook("PreToolUse", "Write", "note.txt")
    expected = ("the Write is let run silently (exit 0); note.txt holds the content its admit proposed; "
                "the trail closes the call ACTION_COMPLETED; no EXECUTED_ARGS_MISMATCH")
    why = missing(inv) or not_called(inv, "Write", admits)
    proposed = admits[0]["input"].get("content") if admits else None
    reqs = inv.on("Write", "note.txt")
    mismatch = any("EXECUTED_ARGS_MISMATCH" in r["protocol"] + r["codes"] for r in inv.requests().values())
    observed = {"admit_exits": exits(admits), "admit_stdout": [e["meta"].get("stdout") for e in admits],
                "file": inv.files.get("note.txt"), "proposed": proposed,
                "trail": [r["kinds"] for r in reqs], "mismatch": mismatch}
    ok = (exits(admits) == [0] and silent(admits) and inv.files.get("note.txt") == proposed
          and any("ACTION_COMPLETED" in r["kinds"] for r in reqs) and not mismatch)
    return verdict(expected, observed, ok, why)


def judge_block(inv):
    admits = inv.hook("PreToolUse", "Bash")
    expected = ("the Bash call is blocked: its PreToolUse exits 2, no file marker appears, "
                "the trail ends it ACTION_BLOCKED with RULE_DENY")
    why = missing(inv) or not_called(inv, "Bash", admits)
    if not why and any(e["input"].get("command") != "touch marker" for e in admits):
        why = "the model asked for another command than touch marker in " + inv.name
    reqs = [r for r in inv.requests().values() if r.get("name") == "Bash"]
    observed = {"admit_exits": exits(admits), "marker": "marker" in inv.files,
                "trail": [(r["kinds"], r["codes"]) for r in reqs]}
    ok = (bool(admits) and all(x == 2 for x in exits(admits)) and "marker" not in inv.files
          and bool(reqs) and all("ACTION_BLOCKED" in r["kinds"] and "RULE_DENY" in r["codes"] for r in reqs))
    return verdict(expected, observed, ok, why)


def edit_applied(seed, admits):
    """The seed with the first admitted edit applied, or None."""
    if not admits:
        return None
    i = admits[0]["input"]
    old, new = i.get("old_string"), i.get("new_string")
    if not isinstance(old, str) or not isinstance(new, str) or old not in seed:
        return None
    return seed.replace(old, new, 1)


def judge_pending(c, seeds):
    held_inv, resumed, used = c("pending", "held"), c("pending", "resumed"), c("pending", "used")
    seed = seeds["target.txt"]
    out = []

    admits = held_inv.hook("PreToolUse", "Edit", "target.txt")
    approval = held_approval(admits)
    why = missing(held_inv) or not_called(held_inv, "Edit", admits)
    state = approval_state(held_inv, approval)
    observed = {"admit_exits": exits(admits), "approval": approval, "approval_state": state,
                "file_unchanged": held_inv.files.get("target.txt") == seed}
    ok = exits(admits) == [2] and bool(approval) and state == "pending" and held_inv.files.get("target.txt") == seed
    out.append(("pending-held", [held_inv],
                verdict("the Edit is denied naming an approval, which approvals list shows pending; "
                        "target.txt is unchanged", observed, ok, why)))

    digest = held_inv.digest_of(approval) if approval else None
    admits = resumed.hook("PreToolUse", "Edit", "target.txt")
    why = (missing(resumed) or not_called(resumed, "Edit", admits)
           or (None if digest else "no held approval to resume")
           or (None if held_inv.approved.get("exit") == 0 else "the harness could not approve the hold"))
    again = held_approval(admits)
    if not why and again and again != approval:
        why = "the retry was another call: it was held anew as " + again
    observed = {"admit_exits": exits(admits), "file": resumed.files.get("target.txt"),
                "started_on_digest": resumed.started(digest) if digest else None,
                "completed_on_digest": resumed.completed(digest) if digest else None}
    ok = (exits(admits) == [0] and silent(admits) and resumed.files.get("target.txt") == edit_applied(seed, admits)
          and resumed.started(digest) == 1 and resumed.completed(digest) == 1)
    out.append(("pending-resumed", [resumed],
                verdict("once approved, the identical retry runs once: its PreToolUse exits 0, the edit is "
                        "applied, and one ACTION_STARTED and one ACTION_COMPLETED follow a decision on the "
                        "approval's digest", observed, ok, why)))

    admits = used.hook("PreToolUse", "Edit", "target.txt")
    why = missing(used) or not_called(used, "Edit", admits) or (None if digest else "no held approval was used")
    reasons = [e["meta"].get("stderr", "") for e in admits]
    observed = {"admit_exits": exits(admits), "reasons": reasons,
                "file_unchanged": used.files.get("target.txt") == seed,
                "started_on_digest": used.started(digest) if digest else None}
    ok = (bool(admits) and all(x == 2 for x in exits(admits)) and all("APPROVAL_ALREADY_USED" in r for r in reasons)
          and used.files.get("target.txt") == seed and used.started(digest) == 1)
    out.append(("pending-used", [used],
                verdict("a third identical call is refused as used (APPROVAL_ALREADY_USED); target.txt, "
                        "seeded again, is unchanged; still one ACTION_STARTED on the digest", observed, ok, why)))
    return out


def held_approval(admits):
    for e in admits:
        m = re.search(r"held for approval (\S+);", e["meta"].get("stderr", ""))
        if m:
            return m.group(1)
    return None


def approval_state(inv, approval):
    path = os.path.join(inv.dir, "approvals.txt")
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return None
    m = re.search(r"^approval %s\n(?:  .*\n)*?  resolution +(\S+)" % re.escape(approval or "-"), text, re.M)
    return m.group(1) if m else None


def judge_concurrent(c, seeds):
    hold, race = c("concurrent", "hold"), c("concurrent", "race")
    admits = hold.hook("PreToolUse", "Edit", "second.txt")
    approval = held_approval(admits)
    digest = hold.digest_of(approval) if approval else None
    races = race.hook("PreToolUse", "Edit", "second.txt")
    why = (missing(hold, race) or not_called(hold, "Edit", admits)
           or (None if digest and hold.approved.get("exit") == 0 else "no approved hold to race for")
           or (None if race.ran == 2 and len(races) == 2 else
               "the two retries made %d recorded Edit calls, not one each" % len(races)))
    started = race.started(digest) if digest else None
    observed = {"approval": approval, "race_exits": exits(races), "started_on_digest": started,
                "file": race.files.get("second.txt")}
    ok = started == 1 and sorted(exits(races)) == [0, 2] and race.files.get("second.txt") == edit_applied(
        seeds["second.txt"], races)
    return verdict("of two identical approved retries in parallel exactly one runs: one ACTION_STARTED on "
                   "the approval's digest, one PreToolUse exits 0 and the other 2", observed, ok, why)


def judge_obligation(c, seeds):
    inv = c("obligation", "run")
    admits = inv.hook("PreToolUse", "Read", "secret.txt")
    why = missing(inv) or not_called(inv, "Read", admits)
    reqs = inv.on("Read", "secret.txt")
    seen = any(seeds["secret"] in r for r in inv.tool_results())
    observed = {"admit_exits": exits(admits), "content_reached_model": seen,
                "trail": [(r["kinds"], r["statuses"], r["protocol"]) for r in reqs]}
    ok = (bool(admits) and all(x == 2 for x in exits(admits)) and not seen and bool(reqs)
          and all("ACTION_FAILED" in r["kinds"] and "RESULT_STATUS_BLOCKED" in r["statuses"]
                  and any("OBLIGATION" in p for p in r["protocol"]) for r in reqs))
    return verdict("the Read, allowed only with an obligation, is denied: its PreToolUse exits 2, the content "
                   "never reaches the model, and the trail closes it ACTION_FAILED, BLOCKED, with an "
                   "OBLIGATION code (aborted, never run)", observed, ok, why)


def judge_effect(c, group, base, runs, expected, act, said=(), exit_status=None, printed=False):
    """A Write that runs, or not, as the case's PreToolUse hook makes it. Every
    PreToolUse hook of the Write must have been act's, so another hook's answer
    cannot stand in for it; a refusal must be in the runtime's words said; with
    exit_status, every admit must also have exited with it; printed, the hook
    must be recorded as having written to standard output and exited 0."""
    inv = c(group, "run")
    admits = inv.hook("PreToolUse", "Write", base)
    why = missing(inv) or not_called(inv, "Write", admits)
    acts = sorted({str(e["meta"].get("act")) for e in admits})
    if not why and acts != [act]:
        why = "the Write's PreToolUse hooks were %s, not %s alone" % (acts, act)
    writes = [u for u in inv.calls() if u["name"] == "Write" and os.path.basename(str(u["input"].get("file_path"))) == base]
    if not why and not all(inv.in_project(u["input"].get("file_path")) for u in writes):
        why = "the model wrote %s outside the project" % base
    if not why and printed and not all(e["meta"].get("exit") == 0 and e["meta"].get("stdout") for e in admits):
        why = "the hook's exit and output were not recorded as written and 0"
    refused = bool(writes) and all(inv.refused(u["id"]) for u in writes)
    worded = bool(writes) and all(all(w in inv.said(u["id"]) for w in said) for u in writes)
    observed = {"pre_hook": [(e["meta"].get("act"), e["meta"].get("exit")) for e in admits],
                "file": inv.files.get(base), "runtime_returned": inv.returned(), "write_refused": refused,
                "refusal": [reason(inv.said(u["id"])) for u in writes if inv.refused(u["id"])]}
    ok = (inv.returned() and (base in inv.files) == runs and refused != runs and worded
          and (exit_status is None or set(exits(admits)) == {exit_status}))
    return verdict(expected, observed, ok, why)


def judge_disabled(c):
    inv = c("disabled", "run")
    why = missing(inv) or (None if inv.tool_uses("Write") else "the model made no Write call in " + inv.name)
    observed = {"events_recorded": len(inv.events), "file": inv.files.get("disabled.txt")}
    ok = "disabled.txt" in inv.files and not inv.events
    return verdict("with disableAllHooks the Write runs and no hook event is recorded (a stated bypass)",
                   observed, ok, why)


def judge_rewrite(inv, replacement):
    admits = inv.hook("PreToolUse", "Write", "note.txt")
    bridge = [e for e in admits if e["meta"].get("act") == "pass"]
    posts = inv.hook("PostToolUse", "Write", "note.txt")
    why = missing(inv) or not_called(inv, "Write", bridge)
    written = inv.files.get("note.txt")
    mismatch = any("EXECUTED_ARGS_MISMATCH" in r["protocol"] for r in inv.on("Write", "note.txt"))
    carried = [e["input"].get("content") for e in posts]
    observed = {"bridge_exits": exits(bridge), "written": written,
                "proposed": bridge[0]["input"].get("content") if bridge else None,
                "completion_input": carried, "mismatch": mismatch, "run_halted": inv.halted()}
    proposed = observed["proposed"]
    if not why and (exits(bridge) != [0] or written == proposed):
        return verdict(EXPECT_REWRITE, observed, False)
    if not why and written != replacement:
        why = "the runtime wrote neither the proposed content nor the replacement"
    if not why and not carried:
        why = "no completion of the Write was recorded"
    ok = mismatch and inv.halted() and all(x == written for x in carried)
    return verdict(EXPECT_REWRITE, observed, ok, why)


# FAILING is, for each case whose PreToolUse hook fails, the act of its fake
# hook and the words the runtime refuses the call in when it blocks it.
BLOCKED = 'onFailure is "block"'
FAILING = {
    "timeout-block": ("sleep", ("timed out", BLOCKED)),
    "timeout-open": ("sleep", ()),
    "crash-block": ("crash", ("failed", BLOCKED)),
    "crash-open": ("crash", ()),
    "garbage": ("garbage", ()),
}

EXPECT_REWRITE = ("another hook's updatedInput is what runs; the completion carries it, and the plane records "
                  "EXECUTED_ARGS_MISMATCH and halts the run")


def judge_rewrite_denied(c):
    inv = c("rewrite-denied", "run")
    admits = inv.hook("PreToolUse", "Write", "draft.txt")
    why = missing(inv) or not_called(inv, "Write", admits)
    reqs = inv.on("Write", "draft.txt")
    reasons = [e["meta"].get("stderr", "") for e in admits]
    observed = {"admit_exits": exits(admits), "reasons": reasons, "file": inv.files.get("draft.txt"),
                "trail": [(r["kinds"], r["statuses"], r["protocol"]) for r in reqs], "run_halted": inv.halted()}
    ok = (bool(admits) and all(x == 2 for x in exits(admits)) and "draft.txt" not in inv.files
          and all("changed input" in r for r in reasons) and bool(reqs) and not inv.halted()
          and all("RESULT_STATUS_BLOCKED" in r["statuses"] and "EXECUTED_ARGS_MISMATCH" in r["protocol"]
                  for r in reqs))
    return verdict("a Write the policy allows only with its content removed is denied: its PreToolUse exits 2 "
                   "naming the changed input, no draft.txt appears, the trail closes it BLOCKED with "
                   "EXECUTED_ARGS_MISMATCH (aborted, never run), and the run is not halted", observed, ok, why)


def judge_mcp(c):
    inv = c("mcp-matcher", "run")
    why = missing(inv) or (None if inv.tool_uses("mcp__") else "the model made no MCP tool call in " + inv.name)
    hooked = [e["tool"] for e in inv.events if e["tool"].startswith("mcp__")]
    ran = "mcp-ran.txt" in inv.files
    observed = {"mcp_events": hooked, "tool_ran": ran}
    if not why and not hooked and not ran:
        why = "the MCP tool did not run, so the matcher was not exercised"
    return verdict("the matcher leaves the mcp__ tool out: no hook event for it, and the tool ran",
                   observed, ran and not hooked, why)


def judge_subagent(c):
    inv = c("subagent", "run")
    agents = {u["id"] for u in inv.calls() if u["name"] == "Agent" and not u["parent"]}
    writes = {u["id"] for u in inv.calls() if u["name"] == "Write" and u["parent"] in agents}
    admits = [e for e in inv.hook("PreToolUse", "Write", "sub.txt") if e["agent"] and e["call"] in writes]
    why = (missing(inv) or (None if agents else "the model made no Agent call in " + inv.name)
           or (None if writes else "no Write ran under the Agent call in " + inv.name)
           or (None if admits else "no PreToolUse event of the sub-agent's Write of sub.txt was recorded"))
    reqs = inv.on("Write", "sub.txt")
    observed = {"agent_calls": len(agents), "sub_agent_writes": len(writes), "admit_exits": exits(admits),
                "decided": [r.get("verdict") for r in reqs], "file": inv.files.get("sub.txt")}
    ok = bool(admits) and any(r.get("verdict") for r in reqs)
    return verdict("a Write a sub-agent makes under the Agent call reaches the hook with the sub-agent's id, and "
                   "the plane decides it", observed, ok, why)


def control(inner, caught_when, expected, broke):
    """A negative control passes when the case under the broken bridge is
    judged caught_when for the reason the broken bridge gives: broke(observed)."""
    _, observed, v = inner
    if v == UNKNOWN:
        return expected, dict(observed, unknown="the expectation under the broken bridge was not judged"), UNKNOWN
    return expected, dict(observed, judged=v), PASS if v == caught_when and broke(observed) else FAIL


def judge(args):
    cache = {}

    def c(group, name):
        key = (group, name)
        if key not in cache:
            cache[key] = Inv(args.cases, args.events, group, name)
        return cache[key]

    seeds = load_json(os.path.join(args.cases, "seeds.json"))
    if not isinstance(seeds, dict):
        sys.exit("harness: no seeds.json in " + args.cases)
    results = [("allow", [c("allow", "run")], judge_allow(c)),
               ("block", [c("block", "run")], judge_block(c("block", "run")))]
    results += judge_pending(c, seeds)
    results.append(("concurrent", [c("concurrent", "hold"), c("concurrent", "race")],
                    judge_concurrent(c, seeds)))
    results.append(("obligation", [c("obligation", "run")], judge_obligation(c, seeds)))
    results.append(("plane-down", [c("plane-down", "run")],
                    judge_effect(c, "plane-down", "down.txt", False,
                                 "with the plane's socket pointing nowhere the bridge exits 2 and the Write is "
                                 "blocked: no down.txt", "pass", exit_status=2)))
    for group, runs, how in (("timeout-block", False, "a PreToolUse hook that outlives its 5 s timeout, under "
                              "onFailure block, blocks the Write"),
                             ("timeout-open", True, "the same hook without onFailure lets the Write run"),
                             ("crash-block", False, "a PreToolUse hook killed by a signal, under onFailure block, "
                              "blocks the Write"),
                             ("crash-open", True, "the same hook without onFailure lets the Write run"),
                             ("garbage", True, "a PreToolUse hook that prints unreadable output and exits 0 "
                              "lets the Write run")):
        act, said = FAILING[group]
        results.append((group, [c(group, "run")], judge_effect(c, group, group + ".txt", runs, how, act, said,
                                                              printed=act == "garbage")))
    results.append(("disabled", [c("disabled", "run")], judge_disabled(c)))
    rewrite = judge_rewrite(c("rewrite", "run"), seeds["replacement"])
    results.append(("rewrite", [c("rewrite", "run")], rewrite))
    results.append(("rewrite-denied", [c("rewrite-denied", "run")], judge_rewrite_denied(c)))
    results.append(("mcp-matcher", [c("mcp-matcher", "run")], judge_mcp(c)))
    results.append(("subagent", [c("subagent", "run")], judge_subagent(c)))
    results.append(("control-allow-all", [c("control-allow-all", "run")],
                    control(judge_block(c("control-allow-all", "run")), FAIL,
                            "the block case through a bridge that lets every call run is judged failed, "
                            "because the marker was made", lambda o: o.get("marker") is True)))
    inner = judge_rewrite(c("control-report-proposed", "run"), seeds["replacement"])
    ctl = control(inner, FAIL, "the rewrite case through a bridge that reports the authorized input as the one "
                               "that ran is judged failed, because the replacement ran and no mismatch was "
                               "recorded, where the real bridge's mismatch was seen",
                  lambda o: o.get("bridge_exits") == [0] and o.get("written") == seeds["replacement"]
                  and o.get("mismatch") is False)
    if rewrite[2] != PASS:
        ctl = (ctl[0], dict(ctl[1], unknown="the real bridge showed no mismatch in rewrite to compare with"), UNKNOWN)
    results.append(("control-report-proposed", [c("control-report-proposed", "run")], ctl))

    for case_id, invs, (expected, observed, v) in results:
        observed = dict(observed, pre_tool_use=[
            [e["tool"], e["meta"].get("exit"), e["meta"].get("stderr", "").strip()]
            for i in invs for e in i.events if e["kind"] == "PreToolUse" and e["meta"].get("act") == "pass"])
        print(json.dumps({"id": case_id, "invocations": sum(i.ran for i in invs),
                          "expected": expected, "observed": observed, "verdict": v}))
