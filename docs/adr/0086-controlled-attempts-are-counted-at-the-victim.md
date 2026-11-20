# ADR-0086: Controlled attempts are counted at the victim, by an executor of their own

Status: accepted
Date: 2026-11-20

Amends [ADR-0085](0085-the-1-0-bar-is-met-by-own-evidence-and-what-needs-outside-people-stays-not-met.md)
part 1, which named `scenario run` as the runner of the adversarial matrix.
Builds on [ADR-0022](0022-scenarios-are-data.md) and
[ADR-0023](0023-a-local-page-answers-through-the-directory.md).

## Context

B37 asks for a fixed set of attempts against the demo's victims, counted
where the effect would land, with the cost to legitimate work beside it.
ADR-0085 named `scenario run` as the runner. `scenario run` holds a plane to
its own account: it stops at the first step that differs, and it refuses a
plane whose mode is not the scenario's. Both are right for a test of the
plane, and both make an absence the harness's: an attack step after a
difference is never sent, and the positive control, the same attack on a
plane that lets it through, could not run at all. A count read from the
plane's verdicts would also measure the plane by its own word.

The demo's victims already journal every call they receive, one line each,
in a file under a directory the plane passes them at start. The plane's stop
closes each victim's input and waits for it to exit, and returns an error
when one does not.

## Decision

**An executor of its own.** `guardana-gateway attempts run --manifest <file>
--report <file>` reads an `attempt-manifest/v1alpha1`, strict JSON as a
scenario is, which names the scenarios to run, labels every step of each
exactly once as `attack` (with the effects it aims at), `legitimate` or
`operator`, names the plane configurations (mode, decision point, role), the
repetitions, the effects and the thresholds, and says how the attempts were
chosen and that no model drives them. For every repetition, plane
configuration and attempt, one at a time, it lays out a fresh dev plane and a
fresh journal directory, sends every call step in order whatever earlier
answers were, runs operator steps through `guardana-control` as `scenario
run` does, stops the plane, and only then reads the journals. A step whose
input names an output the run does not have is not sent, and says so. The
answer each call got is compared with the scenario's answer and reported as
the plane's agreement, apart; no count reads it.

**Counted at the victim.** An effect is observed when a journal line of its
server and call meets every condition on its arguments. An absence on a
measured plane is verified only when the journal is a regular, owner-only
file with one name whose every line parses and whose last line is whole;
every line of that call is the exact line of a legitimate or operator step
of the same run; the same effect was observed on every positive plane in
every repetition of the report; and no line a legitimate or operator step
accounts for, anywhere in the report, meets the effect; and every attack step
aiming at it was sent and answered after every operator action before it ran.
An attack step that was not sent leaves the effect absent and not sent,
counted apart. Anything else is unknown.
A legitimate step is completed only with a result and its exact journal
line, held or blocked by its answer, and unknown otherwise.

**The positive control is OBSERVE.** OBSERVE runs the calls the other modes
block or hold, so the same attempts on an OBSERVE plane show each effect the
victim can be made to receive. Pause and stops have no such control, and no
broken copy of the plane's code is run; every report says both.

**What the run measured, never what a flag states.** The report's header
records the binary's commit and modified flag from its build information, the
sha256 of the manifest, of every file it names and of a corpus digest over
them, the sha256 of this binary, of `guardana-control` and of each victim,
the platform and the start time. Each attempt line records the policy digest
the plane's `/healthz` reported. The summary line records the binaries' sha256
after the run. A changed binary, more than one policy digest or an interrupt
makes the run incomplete; a file without its summary line is incomplete.

**Exits.** 0 when the run is complete, every threshold is met on every
measured plane and nothing is unknown or absent and not sent; 1 when it is
complete otherwise; 2 for a usage error, a refused manifest, or a run that
could not complete.

## Security / compatibility impact

Nothing enters the authorization path. The executor is a client of planes it
starts itself, in its own process, with the dev wiring: keys made in the
process, a bundle signed at start, a collector in the process, approvals,
trust and operators owned by dev, no run tokens. The one change to dev is a
mode the executor sets over the demo's file. Both formats are versioned and
`experimental`; a change is a new kind.

## Alternatives considered

- **`scenario run` as ADR-0085 wrote it.** An absence would be the harness
  stopping, and the positive control would be refused for its mode.
- **Counting from the trail.** The plane's own account, which B37 rules out.
- **A script under `examples/`.** No versioned format and nothing another
  operator could rerun as it ran here.
- **The blocking rule removed as a positive control.** With no rule the
  kernel denies, so the control would observe nothing.

## Consequences

A report of the demo states its counts over their denominators, the controls
that held and the scope that was not measured. A plane start per attempt-run
makes a run slow: the demo's manifest at one repetition starts fourteen
planes. A model-driven set stays a lab job outside CI, with the same
manifest and report.

## Validation

- `internal/attempts`: one refusal per rule of the manifest, each bound at its
  edge and one past it, the kind judged before every other member, the path
  rule, the labels against the scenario; conditions on nested members and
  non-strings; the journal's refusals (missing, a link, a second name, a mode
  others may read, a torn or unparsable line); the controls (a positive
  plane that missed once, one of two positive planes that missed, a
  legitimate line that meets the effect); an attack not sent, one sent
  without an answer, one after an operator's action that did not run; and the
  counts against literal numbers; fuzz targets for both parsers.
- `cmd/guardana-gateway`: on live planes, a refund verified absent on ENFORCE
  and observed on OBSERVE, an attempt whose first answer differs still sending
  its refund, which the OBSERVE victim journals, a report path that exists
  refused, and the demo's manifest as it ships meeting its thresholds and
  printing the counts its guide shows.
