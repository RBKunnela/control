# ADR-0085: The 1.0 bar is met by the project's own evidence, and what needs outside people stays not met

Status: accepted
Date: 2026-11-13

Amends [ADR-0064](0064-milestone-two-starts-with-an-independent-sensor.md),
under which 1.0 waits for the outside review and B11 for an adopter's choice.
Builds on [ADR-0009](0009-open-core-boundary.md) and
[ADR-0066](0066-each-decision-about-authority-is-a-port.md).

## Context

The release bar in [ROADMAP.md](../../ROADMAP.md#release-bar-for-10) and the
backlog's tasks name people from outside the project: an independent
reviewer of the threat model (B34), three new users trying the connect guide
and the setup (B06, B23), and three approvers new to the project explaining
what they approve (B38). B11 qualifies a framework integration only once an
adopter selects one. The project may reach its 1.0 candidate with none of
these people. Waiting for them could hold 1.0 back for good; dropping the
requirements without a word, or counting a model that reads a page as a new
user, would report a bar as met that nobody met. ADR-0064 rejected shipping
1.0 with no outside review as a weak signal for a security tool. It stays
weak; under this record 1.0 ships with the outside review stated as not met,
and the closest evidence the project can produce beside it.

## Decision

The bar changes here, before any evidence meant to replace a requirement is
collected, and every original requirement stays written in its task with its
disposition. A task the bar names carries one or two of exactly two
dispositions in its acceptance text:

- **`not met`**: the requirement needs people from outside the project and
  stays unmet at 1.0. The release notes and [status.md](../status.md) say so.
  Three requirements of the bar have it: an outside review of the threat
  model, trials with new users, and new approvers' understanding of what they
  approve. B11's framework chosen by an adopter has it too, as the adoption
  by outside teams that ADR-0064 keeps as a target after 1.0. A
  model that reads a page or plays a user is a simulation; its result is
  labelled simulated and states "human participants: 0", and never counts
  toward these.
- **`own evidence`**: the project meets the requirement with evidence it
  produces itself. Two integrations qualified against independently maintained
  upstream releases, where B11's framework is the maintainer's choice with the
  reasons published; a disclosure rehearsal on a synthetic defect, with its
  timings; and B29 to B33 as written.

The own evidence comes from a self-run assurance programme. Before each part
runs, a manifest is fixed that names the commit and the artefact digests, the
cases and how they were chosen, the repetitions, the policy, procedure and
tool-definition digests, the permissions, the model and its settings or "no
model", the expected effects, the thresholds and the stopping rules. Failed
and cancelled runs are kept. Effects are checked at the victim, never read
from the plane's verdict, with positive and negative controls. For each named
security check, a deliberately broken copy of the code it guards is run, and
the check has to catch it. Every result carries the
backlog's scope block. The parts:

1. an adversarial matrix run by `scenario run` against the demo's victim (B37);
   Amended by [ADR-0086](0086-controlled-attempts-are-counted-at-the-victim.md): it runs on `attempts run`, not `scenario run`.
2. scripted agents, then agents driven by a model, as a lab job outside CI
   (B37);
3. scripted operator and approver personas, for the functional half of B38;
4. fault injection and crash points (B14, B32);
5. isolation under real accounts, and the offline archives (B13, B32);
6. a soak and tail latency on a dedicated machine (B33);
7. a rebuild from the public pages alone by an automated reader, with every
   intervention logged (B43);
8. passes over the threat model by other reviewers of the project's choosing,
   and the disclosure rehearsal (B34).

A result belongs to one commit. A fix that touches what a result measured
voids it. Each release candidate reruns the frozen programme.

## Security / compatibility impact

None on the wire or the plane. The change is to what 1.0 claims: no page may
say an outside person reviewed, trialled or understood something that no
outside person did. A model in the programme acts as an agent under test or
as a reader; it never takes part in authorization (invariant 1), and
nothing the programme learns is withheld from the open build (ADR-0009).

## Alternatives considered

- Keep the bar and wait for outside people: 1.0 may never ship, and nothing
  in the project's control brings it closer.
- Drop the human requirements without a word: the release would report as met
  requirements nobody met.
- Count a simulated reader as a trial: the same false report, with a number
  attached.

## Consequences

1.0 ships with three requirements named as not met, on the status page and
in its notes. The programme costs a manifest per part and a full rerun per
release candidate. If outside people do take part later, their result is
published under its own scope and the task's disposition changes in that
change.

## Validation

A disposition is written in a task's row as `` 1.0 bar: `own evidence` `` or
`` 1.0 bar: `not met` ``. `TestReleaseBarTasksCarryADisposition` in
`internal/docscheck` reads [docs/backlog.md](../backlog.md) and the release
bar section of ROADMAP.md. It fails on a disposition with any other word, on
one outside a task row, and on a task of the backlog's release bar table that
carries none. It also fails when the tasks ROADMAP's release bar names differ
from the tasks that carry a disposition; a range such as "B29 to B34" names
each task in it. It cannot tell a true disposition from a written one, nor a
simulated result from one labelled as human; review does.
