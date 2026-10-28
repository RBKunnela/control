# ADR-0066: Each decision about authority is a port with a default, and none fails open

Status: accepted
Date: 2026-10-28

Amends [ADR-0009](0009-open-core-boundary.md),
[ADR-0016](0016-approval-providers-and-the-lost-hold.md),
[ADR-0018](0018-keys-and-bundles-on-disk.md) and
[ADR-0046](0046-a-finding-stops-one-run-through-a-signed-route.md). Builds on
[ADR-0007](0007-repository-layout-and-dependency-rule.md),
[ADR-0017](0017-an-external-decision-point-can-veto.md),
[ADR-0026](0026-first-value-and-external-extension-paths.md) and
[ADR-0039](0039-many-channels-into-one-core.md).

## Context

Control is a framework: each part offers a proposed option and can be
extended or replaced. Today most decisions about authority are fixed in
code. The plane wires concrete types. End-user identity is a middleware
typed to one SDK. Every signature is Ed25519 from a key file, with one
pinned key per role. One store holds both the approver's answer and the
plane's proof that an approval was spent. A finding may stop a run on its
own claim. The policy language is one format. ADR-0007 and ADR-0039 forbid
loading code into a plane, and ADR-0026 keeps Go seams out of `pkg/` until
two consumers use them. The external decision point (ADR-0017) already has
the shape that fits both rules.

## Decision

**Every decision about identity, authentication, authorization, approval,
policy language and source, evidence storage and export, observation,
detection, reaction, signature algorithm, and keys and trust is made behind
a port.** Control ships a default for each, and an operator selects
another one explicitly.

**A port has all of these, or it is not a port:**

1. An interface declared under `internal/` by the package that consumes
   it. Implementations import the consumer, never the reverse.
2. An answer whose zero value means unknown or unavailable, with named
   states: no `bool` for three answers, no bare `error` for a decision. The
   answer carries facts; the core decides and spells every reason code.
3. A tested default, selected by a closed `kind` in the configuration. An
   unknown kind is refused at load, and no default grants more than having
   nothing configured.
4. At most one `remote` kind with a versioned, language-neutral protocol.
   A remote answer that carries authority is a signed object the core
   verifies: the service delivers it and never decides it.
5. Fail closed: no answer, a late one or a refused one is the unavailable
   state, and a material call is blocked (invariant 5). Any risk setting is
   named per port.
6. Bounds on time, concurrency and size, counted in `/metrics`, with the
   kind and state in `doctor` and `/healthz`.
7. Conformance cases under `testdata/ports/<port>/`, each rule with a
   negative control, passed by every kind.
8. Capabilities checked once at start, never read per call as authority.

**Extension is in-tree or remote, never loaded.** A new kind is compiled in
through a change to this repository, or reached remotely. An interface
moves to `pkg/` only by its own record after two consumers.

**Remote authorization only vetoes**, as ADR-0017 says: it takes authority
away and never grants it.

**The policy language is a port.** It parses a signed document and
evaluates it into the kernel's structured inputs: per rule, a three-valued
match with the rule id, effect, catalogue obligations and missing inputs,
which `policy explain` reads. The default is `agent-policy/v1alpha1`. The
document names its language in its own `apiVersion`, so it is never read
under a language it was not signed for. Every document travels in
`PolicyBundle.canonical` as JSON equal to its own canonical form, under the
existing payload type, so one policy keeps one digest and every decision
records it as its policy version. Evaluation is pure, deterministic and in
the guarded trees; a language needing a dependency outside the allowlist
needs its own record. The kernel keeps the fixed order, the fail-closed
table, how effects combine, the delegation and tenant checks, the veto, the
modes, the approval binding and the reason codes.

**The signature algorithm is a port, bound to the key by the roster.** Each
key carries exactly one algorithm. A verifier selects the key by id and the
algorithm by the key, never by what the message says. Each algorithm brings
its own key checks and test vectors. Envelopes outside v1 (freshness
statement, route, lift, checkpoints) take any algorithm the roster names.
The frozen v1 `PolicyBundle` defines `signature` as Ed25519 over DSSE and
`signature_alg` as the fixed `ed25519-dsse`. Another algorithm with no wire
bytes changed would leave that field naming an algorithm the signature is
not in, which changes a frozen field's meaning. So Ed25519 keys change
nothing, and the first other algorithm for policy bundles needs its own
record and compatibility plan. The signature is outside the bundle digest,
so digest_v1 and the approval binding never move.

**Keys are held by a signer port.** It signs bytes and states its public key
and id; the core builds the DSSE encoding and verifies every signature
against the roster before use. Default: the key file. Alternatives: a
hardware or cloud key service, a signing API that answers.

**Trust comes from a signed roster**, under a pinned root, with an expiry
and a serial floor, naming keys by role: policy, freshness, route, lift,
checkpoint, operator. An API that answers may deliver it. Without a newer
one, the plane keeps the last verified roster until it expires, then fails
closed.

**Operators are authenticated against the roster by default**, with an API
that answers as the alternative, and authorized by the roles it states.

**Approval authority is split from the plane's ledger.** Only the plane
marks an approval spent, in its own directory under its own lock. An
authenticated approver is recorded in `approver_id` as
`authn:<issuer>:<subject>`, with no wire change; only the core writes that
prefix, and a value carrying it from anywhere else is refused.

**A finding's trust comes from its detector's signed descriptor**, which
names the highest source class the detector may claim; a route names the
detectors it accepts. Detector identity goes in the finding record, not in
the v1 `Finding`.

**Checkpoint signing is off the decision path.** While its signer is
unavailable, calls are served and integrity is reported unknown;
`evidence.require_checkpoint` blocks material calls instead.

**What never becomes a port.** No language model grants or restores
authority (invariant 1); its output is never a port's answer. Keyword or
pattern matching alone never grants or denies (invariant 2). The kernel's
order and fail-closed table, the handling of `INDETERMINATE` (invariant 4),
digest_v1, the arguments hash, the approval binding, the consume-once
ledger (invariant 6), the reason-code registry, the mode table and the
evidence chain's validation stay in the core.

## Security / compatibility impact

No v1 wire bytes change. Binding the algorithm to the key stops a message
choosing how it is verified. A consumer outside this repository may still
read an `authn:` value as a plain name. Moving the spent mark removes
ADR-0016's limit under which an approvals directory writer could forge a
spent approval. Each remote kind adds a protocol to version and a service
to depend on, and fails closed. Each algorithm adds a standard library
package to the dependency rule's allowlist, a protected contract.

## Alternatives considered

- Public `pkg/` interfaces now: fastest for Go integrators, but freezes a
  surface before two consumers and shares the plane's process.
- Remote-only providers: one trust rule, but a network hop per call and no
  offline default.
- An algorithm chosen by `signature_alg`: the message picks its own check.
- A foreign language under its own payload type: moves a frozen contract.

## Consequences

A decision is replaced without a fork, in any language, through a remote
kind. Each port costs an interface, a default, a protocol and a suite, and
the plane gains one selector per port. Most of these ports are not built
yet: [status.md](../status.md) says which exist, and each arrives in its own
change with its conformance cases.

## Validation

- Each port's zero answer, and fakes that are unavailable, late and
  malformed, block a material call with the core's own code.
- `scripts/ports.txt` lists each port's interface, default, conformance
  directory and `doctor` key; a gate fails on a port missing one, or with
  no negative control, and on an unlisted interface documented as a port.
- The dependency rule refuses, under `adapters/`, importing the reason-code
  registry or building a v1 `Decision`.
- Every kind builds under `doctor`, an unknown kind is refused, and no
  default grants more than having nothing configured.
- An approvals directory writer cannot make the plane read an approval as
  spent, and an `authn:` value from a file is refused.
- A finding claiming a class above its descriptor's cannot stop a run.
- A signature made under an algorithm other than its key's is refused;
  each algorithm passes its vectors, weak keys included.
- Each policy language passes the language conformance cases, and its
  decisions name the bundle digest.
- An expired roster with no replacement blocks material calls.
- Review treats a `bool` in a port's answer as a defect unless the record
  names its two states.
