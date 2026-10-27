"""The judges of the cases that hold a call for approval, resume it once and
race two retries for it, and of the obligation the plane cannot meet."""

import os
import re
from typing import Any

from harness_observed import Inv, Record
from harness_verdicts import (
    BLOCK,
    Cases,
    Verdict,
    edit_applied,
    exits,
    holds,
    missing,
    not_called,
    silent,
    verdict,
)


def held_approval(admits: list[Record]) -> str | None:
    for e in admits:
        m = re.search(r"held for approval (\S+);", e["meta"].get("stderr", ""))
        if m:
            return m.group(1)
    return None


def approval_state(inv: Inv, approval: str | None) -> str | None:
    path = os.path.join(inv.dir, "approvals.txt")
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return None
    name = re.escape(approval or "-")
    m = re.search(rf"^approval {name}\n(?:  .*\n)*?  resolution +(\S+)", text, re.M)
    return m.group(1) if m else None


def judge_pending(c: Cases, seeds: Record) -> list[tuple[str, list[Inv], Verdict]]:
    held_inv, resumed, used = c("pending", "held"), c("pending", "resumed"), c("pending", "used")
    seed = seeds["target.txt"]
    out = []

    admits = held_inv.hook("PreToolUse", "Edit", "target.txt")
    approval = held_approval(admits)
    why = missing(held_inv) or not_called(held_inv, "Edit", admits)
    state = approval_state(held_inv, approval)
    observed: Record = {
        "admit_exits": exits(admits),
        "approval": approval,
        "approval_state": state,
        "file_unchanged": held_inv.files.get("target.txt") == seed,
    }
    ok = (
        exits(admits) == [BLOCK]
        and bool(approval)
        and state == "pending"
        and holds(held_inv, "target.txt", seed)
    )
    expected = (
        "the Edit is denied naming an approval, which approvals list shows pending; "
        "target.txt is unchanged"
    )
    out.append(("pending-held", [held_inv], verdict(expected, observed, ok, why)))

    digest = held_inv.digest_of(approval) if approval else None
    admits = resumed.hook("PreToolUse", "Edit", "target.txt")
    why = (
        missing(resumed)
        or not_called(resumed, "Edit", admits)
        or (None if digest else "no held approval to resume")
        or (
            None if held_inv.approved.get("exit") == 0 else "the harness could not approve the hold"
        )
    )
    again = held_approval(admits)
    if not why and again and again != approval:
        why = "the retry was another call: it was held anew as " + again
    observed = {
        "admit_exits": exits(admits),
        "file": resumed.files.get("target.txt"),
        "started_on_digest": resumed.started(digest) if digest else None,
        "completed_on_digest": resumed.completed(digest) if digest else None,
    }
    ok = (
        exits(admits) == [0]
        and silent(admits)
        and holds(resumed, "target.txt", edit_applied(seed, admits))
        and resumed.started(digest) == 1
        and resumed.completed(digest) == 1
    )
    expected = (
        "once approved, the identical retry runs once: its PreToolUse exits 0, the edit is "
        "applied, and one ACTION_STARTED and one ACTION_COMPLETED follow a decision on the "
        "approval's digest"
    )
    out.append(("pending-resumed", [resumed], verdict(expected, observed, ok, why)))

    admits = used.hook("PreToolUse", "Edit", "target.txt")
    why = (
        missing(used)
        or not_called(used, "Edit", admits)
        or (None if digest else "no held approval was used")
    )
    reasons = [e["meta"].get("stderr", "") for e in admits]
    observed = {
        "admit_exits": exits(admits),
        "reasons": reasons,
        "file_unchanged": used.files.get("target.txt") == seed,
        "started_on_digest": used.started(digest) if digest else None,
    }
    ok = (
        bool(admits)
        and all(x == BLOCK for x in exits(admits))
        and all("APPROVAL_ALREADY_USED" in r for r in reasons)
        and holds(used, "target.txt", seed)
        and used.started(digest) == 1
    )
    expected = (
        "a third identical call is refused as used (APPROVAL_ALREADY_USED); target.txt, "
        "seeded again, is unchanged; still one ACTION_STARTED on the digest"
    )
    out.append(("pending-used", [used], verdict(expected, observed, ok, why)))
    return out


def judge_concurrent(c: Cases, seeds: Record) -> Verdict:
    hold, race = c("concurrent", "hold"), c("concurrent", "race")
    admits = hold.hook("PreToolUse", "Edit", "second.txt")
    approval = held_approval(admits)
    digest = hold.digest_of(approval) if approval else None
    races = race.hook("PreToolUse", "Edit", "second.txt")
    why = (
        missing(hold, race)
        or not_called(hold, "Edit", admits)
        or (None if digest and hold.approved.get("exit") == 0 else "no approved hold to race for")
        or (
            None
            if race.ran == 2 and len(races) == 2  # noqa: PLR2004
            else f"the two retries made {len(races)} recorded Edit calls, not one each"
        )
    )
    if not why and any(e["input"] != admits[0]["input"] for e in races):
        why = "a retry's input differs from the held call's, so it is another call"
    started = race.started(digest) if digest else None
    observed = {
        "approval": approval,
        "race_exits": exits(races),
        "started_on_digest": started,
        "file": race.files.get("second.txt"),
    }
    ok = (
        started == 1
        and sorted(exits(races)) == [0, BLOCK]
        and holds(race, "second.txt", edit_applied(seeds["second.txt"], races))
    )
    return verdict(
        "of two identical approved retries in parallel exactly one runs: one ACTION_STARTED on "
        "the approval's digest, one PreToolUse exits 0 and the other 2",
        observed,
        ok,
        why,
    )


def admitted(inv: Inv, admits: list[Record]) -> list[Record]:
    """The stream's tool calls that the recorded admits name."""
    ids = {e["call"] for e in admits if e["call"]}
    return [u for u in inv.calls() if u["id"] in ids]


def unanswered(inv: Inv, tool: str, calls: list[Record]) -> str | None:
    """Why the stream does not show the runtime's answer to each of calls, or
    None. With no answer recorded, as when the runtime stopped after the hook,
    what reached the model is not known."""
    if not calls:
        return f"no {tool} call in the stream of {inv.name} is one its PreToolUse events name"
    if any(inv.result(u["id"]) is None for u in calls):
        return f"the stream of {inv.name} holds no answer to the {tool} call"
    return None


def judge_obligation(c: Cases, seeds: Record) -> Verdict:
    inv = c("obligation", "run")
    admits = inv.hook("PreToolUse", "Read", "secret.txt")
    reads = admitted(inv, admits)
    why = missing(inv) or not_called(inv, "Read", admits) or unanswered(inv, "Read", reads)
    reqs = inv.on("Read", "secret.txt")
    refused = bool(reads) and all(inv.refused(u["id"]) for u in reads)
    seen = any(seeds["secret"] in r for r in inv.tool_results())
    observed: dict[str, Any] = {
        "admit_exits": exits(admits),
        "read_refused": refused,
        "content_reached_model": seen,
        "trail": [(r["kinds"], r["statuses"], r["protocol"]) for r in reqs],
    }
    ok = (
        bool(admits)
        and all(x == BLOCK for x in exits(admits))
        and refused
        and not seen
        and bool(reqs)
        and all(
            "ACTION_FAILED" in r["kinds"]
            and "RESULT_STATUS_BLOCKED" in r["statuses"]
            and any("OBLIGATION" in p for p in r["protocol"])
            for r in reqs
        )
    )
    return verdict(
        "the Read, allowed only with an obligation, is denied: its PreToolUse exits 2, the runtime "
        "answers the Read with an error, the content never reaches the model, and the trail closes "
        "it ACTION_FAILED, BLOCKED, with an OBLIGATION code (aborted, never run)",
        observed,
        ok,
        why,
    )
