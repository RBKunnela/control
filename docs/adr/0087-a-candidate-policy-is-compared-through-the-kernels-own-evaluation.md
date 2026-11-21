# ADR-0087: A candidate policy is compared through the kernel's own evaluation, and what a case cannot show stays unknown

Status: proposed
Date: 2026-11-20

Builds on [ADR-0012](0012-policy-kernel-semantics.md),
[ADR-0036](0036-policy-explain-reads-the-kernels-own-evaluation.md) and
[ADR-0035](0035-a-versioned-evidence-export-and-a-bounded-query.md), and
delivers backlog B27 as
[ADR-0050](0050-adoption-workflows-preserve-authority-and-evidence.md) frames it.

## Context

An operator about to ship a new policy wants to know which calls it decides
differently from the one in force. `policy test` and `policy explain` decide a
case under one document. A second evaluator for comparison would drift from the
kernel's three-valued logic. Evidence holds a hash of each call's arguments,
never the arguments; it holds no run's flow and no answer the decision point
would give to a new question. A replay that filled those gaps with defaults
would report a guess as a result.

## Decision

**The command.** `guardana-control policy compare --current <document>
--candidate <document> [--cases <dir>] [--evidence <export>] [--labels <file>]
--report <file>`, `experimental`. Both documents are signed in memory with the
fixed key `policy test` uses, as `policy explain` signs them, and loaded at
each case's `loaded_at`. Every case is decided twice through
`Kernel.Explain`, the evaluation the plane's `Decide` runs. Nothing else
decides.

**The cases.** A case file is a `policy test` case with `expect` optional:
its format is checked; it is not compared with any decision; its `document` must have the current document's canonical digest,
or the run is refused naming the file. A request of an evidence export is a
case when it holds one `ACTION_PROPOSED` and one `POLICY_DECIDED`: the
proposal's envelope with arguments `{}` and their hash recomputed, no flow,
no external answer, and the decision's two times. The recorded decision is a
cross-check, never the before.

**Unknown is a result.** A case is unknown, with one reason and no verdict on
either side, when it cannot say what the candidate changes: an incomplete
request, in an export that is not whole or in one that is; a proposal or
decision of a major this build does not read; more than one decision; a
decision on another policy (the historic policy is missing); a decision not
recorded fresh; a side the kernel could not evaluate, on which no rule ran, or that the
kernel denied on its own whatever the rules decide (a refused delegation,
two tenants);
a side whose policy is stale at the case's time, for every source; a rule
left undetermined on either side by a field, the flow or the decision point's
answer the case lacks; and, for evidence, an obligation the record does not
show the plane applying, or today's kernel on the current policy deciding
otherwise than the record. An unknown
case is never counted unchanged.

**The change.** The four actions are ordered: run, run under obligations,
hold, block, and the binding (non-advisory) obligations order with them.
Further along, or as far binding more, while still binding everything the
before side bound, is stricter; a block binds everything. The reverse is
looser. Anything that moves both ways, changes an obligation's parameters, or
changes only the verdict, the codes or advisory obligations is other, which
names no direction and is read row by row.

**The report.** `policy-comparison/v1alpha1`, written once to a name that does
not exist, marked simulated, naming both policies' ids, versions and digests,
each input's provenance, each case's sides, and counts each over its own
denominator. Labels (`policy-case-labels/v1alpha1`) count cases by label and
change. The policy document names no author, so a labeller's independence is
declared, not verified, and the report says so.

**Exit status.** 0 when every case was evaluated on both sides and none is
unknown, 1 with any unknown, 2 for a refused input or a report not written.

## Security / compatibility impact

No wire contract, reason code, digest, kernel or `pkg/` surface changes. The
command sends no call, reads or consumes no approval, writes no policy, floor
or statement and reaches no plane: its key exists only in its own process.
Two new formats are versioned and `experimental`.

## Alternatives considered

- Extending `policy test`: it passes or fails a case against an expectation;
  a comparison has no expectation and its unknowns are not failures.
- The recorded decision as the before: it may come from another build, a
  setting or an answer the evidence does not hold; agreement is checked
  instead.
- Defaults for missing arguments, flow or answers: each would turn an absent
  fact into a verdict.
- Shadow evaluation of live traffic on a plane: it needs a plane change and
  its own record; this compares offline.

## Consequences

An operator sees, before signing, which cases a candidate decides more or
less strictly, and how many it cannot judge and why. An export with no flow
data compares little for a policy that reads flow, and says so. Every number
is simulated; none is evidence that a call ran or was blocked.

## Validation

- `internal/policycompare`: every ordered pair of actions has its change;
  a case unknown on either side is never unchanged; counts over their own
  denominators; each evidence reason has its input; the labels reader refuses
  an unknown member, a duplicate, null, a kind not first, and a label naming
  no case of the run.
- `cmd/guardana-control`: the corpus in `testdata/policy/compare/` end to end
  with literal counts; a case of another document, an existing report, and
  each bound refused; nothing written but the report; exit 0 and 1.
