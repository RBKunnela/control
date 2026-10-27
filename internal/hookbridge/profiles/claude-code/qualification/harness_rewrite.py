"""The judges of the cases where another hook rewrites a call's input, and the
fake hooks of the cases whose PreToolUse hook fails."""

from harness_observed import Inv
from harness_verdicts import BLOCK, FAIL, Cases, Verdict, exits, missing, not_called, verdict

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

EXPECT_REWRITE = (
    "another hook's updatedInput is what runs; the completion carries it, and the plane records "
    "EXECUTED_ARGS_MISMATCH and halts the run"
)


def healthy(inv: Inv) -> str | None:
    """Why the plane's count of halted runs before and after inv is not known,
    or None."""
    if inv.observed_health:
        return None
    return "the plane's count of halted runs was not read for " + inv.name


def judge_rewrite(inv: Inv, replacement: str) -> Verdict:
    admits = inv.hook("PreToolUse", "Write", "note.txt")
    bridge = [e for e in admits if e["meta"].get("act") == "pass"]
    posts = inv.hook("PostToolUse", "Write", "note.txt")
    why = missing(inv) or not_called(inv, "Write", bridge) or healthy(inv)
    written = inv.files.get("note.txt")
    mismatch = any("EXECUTED_ARGS_MISMATCH" in r["protocol"] for r in inv.on("Write", "note.txt"))
    carried = [e["input"].get("content") for e in posts]
    proposed = bridge[0]["input"].get("content") if bridge else None
    observed = {
        "bridge_exits": exits(bridge),
        "written": written,
        "proposed": proposed,
        "completion_input": carried,
        "mismatch": mismatch,
        "run_halted": inv.halted(),
    }
    if not why and (exits(bridge) != [0] or written == proposed):
        return EXPECT_REWRITE, observed, FAIL
    if not why and written != replacement:
        why = "the runtime wrote neither the proposed content nor the replacement"
    if not why and not carried:
        why = "no completion of the Write was recorded"
    ok = mismatch and inv.halted() and all(x == written for x in carried)
    return verdict(EXPECT_REWRITE, observed, ok, why)


def judge_rewrite_denied(c: Cases) -> Verdict:
    inv = c("rewrite-denied", "run")
    admits = inv.hook("PreToolUse", "Write", "draft.txt")
    why = missing(inv) or not_called(inv, "Write", admits) or healthy(inv)
    reqs = inv.on("Write", "draft.txt")
    reasons = [e["meta"].get("stderr", "") for e in admits]
    observed = {
        "admit_exits": exits(admits),
        "reasons": reasons,
        "file": inv.files.get("draft.txt"),
        "trail": [(r["kinds"], r["statuses"], r["protocol"]) for r in reqs],
        "run_halted": inv.halted(),
    }
    ok = (
        bool(admits)
        and all(x == BLOCK for x in exits(admits))
        and "draft.txt" not in inv.files
        and all("changed input" in r for r in reasons)
        and bool(reqs)
        and not inv.halted()
        and all(
            "RESULT_STATUS_BLOCKED" in r["statuses"] and "EXECUTED_ARGS_MISMATCH" in r["protocol"]
            for r in reqs
        )
    )
    return verdict(
        "a Write the policy allows only with its content removed is denied: its PreToolUse exits 2 "
        "naming the changed input, no draft.txt appears, the trail closes it BLOCKED with "
        "EXECUTED_ARGS_MISMATCH (aborted, never run), and the run is not halted",
        observed,
        ok,
        why,
    )
