# ADR-0012: How the built-in policy kernel decides

Status: accepted
Date: 2026-09-11

Amends [ADR-0003](0003-policy-model-and-external-pdp.md).

Amended by [ADR-0038](0038-a-signed-freshness-statement-and-a-serial-floor.md),
which decides that a bundle is confirmed current by a signed freshness
statement, never by being read again, and that the serial floor outlives the
process; [status.md](../status.md) says how much of it a plane does today.

Amended in 0.6.0-alpha: a clock reading before 1970, the zero time among them,
or after the last instant of 9999, is a cause in the request, decided
`INDETERMINATE` with `POLICY_STALE` on every effect class, so fail-open reads
never apply to it. A reading earlier than the snapshot's not-before, the
latest `issuedAt` the plane verified from a freshness statement or its floor,
is provably wrong and is the same cause; the stale bundle below is then never
reached. A delegation hop's `issued_at` is the producer's unsigned claim and
is not compared with the clock.

Amended by [ADR-0055](0055-a-call-is-handed-out-only-while-its-policy-stands.md): the kernel judges a decision's
bundle again when the call is handed out, and a read the fail-closed table
opened stays open there only while its bundle is the same one.

## Context

ADR-0003 chose structured predicates and deny-overrides, and left the exact
fail-closed mapping open. ADR-0011 settled what the wire says. What is
left is how the kernel turns a validated envelope and a policy bundle into one of
five verdicts, and what it enforces for each, precisely enough that a second
implementation, or a reviewer, reaches the same decision from the same inputs.

## Decision

**A policy is a signed JSON document, `agent-policy/v1alpha1`.** Each rule has an
id, an effect (`ALLOW`, `DENY`, `REQUIRE_APPROVAL` or `ALLOW_WITH_OBLIGATIONS`)
and constraints on the principal, the agent, the action, the resource, the
destination, the data, the run's flow and the delegation. A constraint lists
values; a value matches by exact equality, and a list means any of them. Every
constraint of a rule has to hold. There are no regular expressions, prefixes or
scripts, and keys match exactly, case included. The document carries its bundle
id, version, a serial and the author's staleness budget, and no creation time.
The bytes that are signed are the restricted canonical form of the author's own
bytes. The kernel reads JSON only: typed YAML decoding reads `on` as true and
`10.5` as `10` without a word, and a policy is the wrong place to learn that.

**A constraint is true, false or unknown.** It is unknown when the field it reads
is absent, or when the flow of the run cannot be established. A data sensitivity
constraint reads the envelope's own labels: it is unknown when the envelope
carries no label and does not assert secrets. A rule is false if any constraint
is false, else unknown if any is unknown. An unknown `ALLOW` rule does not match.
An unknown rule of any other effect makes the decision `INDETERMINATE`, because
otherwise a request that leaves out the field a restrictive rule reads would slip
past it onto a broader allow.

**Deny-overrides, as a table.** A matched `DENY`, or a denial the kernel makes on
its own, wins. Then `INDETERMINATE`, whatever caused it; then `REQUIRE_APPROVAL`,
`ALLOW_WITH_OBLIGATIONS`, `ALLOW`. Nothing matched is `DENY`,
`NO_MATCHING_RULE`. Obligations come from every matched `ALLOW_WITH_OBLIGATIONS`
and `REQUIRE_APPROVAL` rule, in document order, two being the same when their
type, parameters and advisory flag are, and each kept once, so a broader rule
never sheds them.

**The kernel's own checks run whatever the policy says, and before it.** A
delegation hop whose expiry is at or before the receiver's clock, a party that
appears twice in a chain, and a hop that claims more than its parent are each
`DENY`. A principal and a resource that name different tenants are `DENY`; a
material call that names a tenant on one side only is `INDETERMINATE`. They run
before the bundle is consulted, so a missing bundle relaxes the policy and never
the kernel's own checks.

**What each verdict enforces.** `DENY` blocks. `REQUIRE_APPROVAL` waits for an
approval. `ALLOW_WITH_OBLIGATIONS` runs with its obligations applied. `ALLOW`
runs. For `INDETERMINATE`, a cause in the request, a refusal, an argument that
cannot be digested, a hash that does not match, an unknown rule or a one-sided
tenant, blocks the call whatever its effect. A cause in the policy's
availability, no bundle or one past its staleness budget, blocks every call but a
read. A read runs exactly when the operator has turned fail-open reads on and
either there is no bundle at all or the policy, with what it could not decide
left out, allows it: an `ALLOW` matched and nothing more restrictive did. A read
that no rule allowed is blocked, because there is no implicit allow. When a read
runs this way, the decision carries `FAIL_OPEN_READ_CONFIGURED` as its last reason
code, which is how the setting stays visible in the evidence, and the verdict
stays `INDETERMINATE` (ADR-0011). A denial for an obligation the enforcement
point cannot apply is never relieved by the setting. This narrows ADR-0003,
which let the setting apply to any read the kernel could not decide.

**The order is fixed, and stops only where nothing more can be known.** A refused
request, an argument that cannot be digested and a hash that does not match end
the decision: nothing is evaluated against input the kernel refused. Then the
kernel's own checks; then the bundle, whose staleness is recorded while
evaluation continues, so a stale bundle's `DENY` is still a `DENY`. Every cause
found is listed in the decision, in order, once each. A matched rule contributes
its reason, in document order; any undeterminable rule contributes
`RULE_UNDETERMINED` once; `NO_MATCHING_RULE` appears when no rule matched and
none was undeterminable. Reason codes come from the kind of failure, never from
error text.

**A bundle is trusted only after every check.** The signature names a key the
operator pinned; the signed document must be its own canonical form and must
agree with every field outside it; a field this build does not know, on the
bundle or its reference, is refused; and a creation time outside the document is
refused because none is signed. A lower serial for the same bundle, or the same
serial with different content, is refused. A bundle is fresh while the time since
it was last confirmed current is within the smaller of the author's budget and
the operator's; a bundle confirmed later than the receiver's clock reads is
stale. What that protection covers is stated rather than implied: it holds per
bundle id and per process, since a restart accepts any serial, and "confirmed
current" means delivered again, since a signature proves who wrote a bundle, not
that it is still the latest. It does not cover a bundle of another id: any
bundle ever signed under a pinned key whose id this process has not seen
replaces the running policy at any serial, and the serial rule sees a new id.
That is a substitution, not a rollback, and a holder pinned to the bundle id it
serves, refusing every other, is `planned` beside a signed expiry and a serial
that survives a restart.

**The kernel builds `ENFORCE` only.** The other modes are `planned` in the
gateway ([ADR-0013](0013-mcp-interception-approvals-and-modes.md)), and a
kernel refuses to start in one of them rather than behave as another.

**Nothing that decides reads a reason code's documented verdict.** The packages on
the decision path do not import the registry; they carry the identifiers they
emit, and tests hold each one to the registry.

## Security / compatibility impact

Every rule above fails closed, and the ones that cost availability say so: an
adapter that leaves out a field a restrictive rule reads gets blocks until it
sends the field, and a one-sided tenant blocks a material call. Both are visible
in the decision, with the rule or the check behind them, rather than a silent
allow. The one cost of failing open is stated too: with fail-open reads on and
no bundle, a read that names a tenant on one side only runs, because the tenant
check covers material calls only.

## Alternatives considered

- **Treat a restrictive rule over an absent field as matched.** Stricter for a
  `DENY`, and it turns a denial on an optional field into a denial of every call
  that lacks it, and an approval rule into an approval nobody asked for.
- **Fail-open for any undecided read.** It lets a read that one rule sends for
  approval run with no approval whenever another rule cannot be evaluated, and a
  read no rule allows run at all.
- **Stop at a missing bundle.** Simpler, and it lets fail-open reads skip the
  tenant and delegation checks, which need no policy.
- **YAML as the policy source.** Familiar, and its typed decoding accepts values
  a policy must refuse. A YAML front end in the command line, walking the parse
  tree and refusing what the canonical parser refuses, is possible later.
- **JSON Schema inside the kernel.** It carries regular expressions and a second
  schema to keep in step. The strict parse does the job; a schema for editors is
  `planned`.

## Consequences

Adapters have to send the fields the policies they run under read. The decision
names the rule or the check behind every block, which is what makes that cost
debuggable. Evidence sinks, content capture and the other modes are `planned`
with the gateway ([ADR-0013](0013-mcp-interception-approvals-and-modes.md),
[ADR-0014](0014-evidence-spool-and-sinks.md)).

## Validation

Planned with the kernel: fixtures for all five verdicts and one `INDETERMINATE`
per cause; a test of the fail-closed table crossing every cause with a read and
a material call, fail-open on and off; a property over ten thousand requests
that the same request and bundle give an identical decision, against a
separately loaded bundle; a table of every refusal against every effect class;
the benchmark at 10, 100 and 1000 rules.
