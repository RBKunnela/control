# ADR-0071: Operators are named by a signed roster, and authorized by its grants

Status: accepted
Date: 2026-10-30

Amends [ADR-0066](0066-each-decision-about-authority-is-a-port.md) property 1
for a port whose answer is sealed. Builds on ADR-0066, which makes trust,
operator authentication and operator authorization ports, on
[ADR-0038](0038-a-signed-freshness-statement-and-a-serial-floor.md) and
[ADR-0046](0046-a-finding-stops-one-run-through-a-signed-route.md) for the
serial floor, and on
[ADR-0017](0017-an-external-decision-point-can-veto.md) for the veto.

Amended by [ADR-0073](0073-an-approval-counts-only-as-the-plane-judges-it.md): a signed start
refuses the configuration file, the trust root key file and any key the
environment set, and not the approvals directory, which the plane owns.

## Context

Today an approver is whoever can write the approvals directory, and the
approver id is a claim. ADR-0066 says operators are authenticated against a
signed roster by default and authorized by the roles it states, and that a
remote authorization only vetoes. Three ports need a first kind each, a
format for the roster, and a rule for what an operator signs.

## Decision

**The trust roster port** (`internal/trust.Roster`, kind `file`, the
default). One file holds a DSSE envelope of payload type
`application/vnd.agent-trust-roster+json`, signed once by the pinned root key.
Its body is the canonical JSON object of kind `trust-roster/v1alpha1`:
`rosterId`, `serial`, `issuedAt`, `expiresAt` and `keys`, each required, no
other. Each key carries `keyId` (its own id), `alg` (`ed25519` in this
version), `role` (`operator` in this version), `subject`, `publicKey` and one
to 32 `grants` of `tenant`, `project` and `level` (`read`, `operate`,
`admin`). A tenant or a project is never empty and never a pattern. No key is
named twice; none is the root, nor a key the plane pins for policy,
freshness, routes or lifts; the root is none of those either. The lifetime is
at most 7 days; `operators roster sign` signs for 24 hours unless told
otherwise. Each signing needs a higher serial than the last: a second roster
at one serial is a fork every plane refuses, and the command refuses to
replace a roster at `--out` that verifies under this root and names the same
roster id, at the serial it signs or above; any other file there holding a
roster envelope is replaced. The port is
configured with the one roster id it takes. A roster of another id, dated
after the clock, expired, below the serial held, or at it with another
digest, is not taken, at start as while running. Each taken roster raises a
floor of the new `authority` kind in `internal/policystate`, so a restart
never takes a lower one. The floor directory keeps format `1.0` with a marker
of its own, `authority.meta`: a build that predates the kind finds no marker
it reads and a name it does not write, so it refuses the directory. The plane
keeps the last roster it verified until its own expiry, then answers
unavailable. Any other role or algorithm is refused until a change adds its
consumer.

**The operator authenticator port** (`internal/operators.Authenticator`,
kind `roster`, the default). An act has one payload type: approving or
rejecting a hold is `application/vnd.agent-approval-answer+json`. A statement
is one signature over a canonical JSON object of at most 16 KiB that names
`alg` and `keyId`. The key is selected by the signature's key id from the
roster, which has to answer the key under that same id, for role
`operator`, and the signature is verified under the algorithm that key
carries; then the body's `alg` and `keyId` must be that
key's. The answer is unavailable, refused or authenticated, never a `bool`,
and an authenticated one names the issuer `roster/<rosterId>`, the subject
and the key id. Only this package builds an authenticated answer.

**The operator authorizer port** (`internal/operators.Authorizer`, kind
`roster`, the default). It asks the roster again for the signing key, so a
key removed, given to another subject, or lowered after it signed permits
nothing, and permits an act over exactly one tenant's one project when a
grant there is at the act's level or above (`approve` needs `operate`). An
empty tenant or project is denied, never read as a wildcard. A veto may
follow it: it is asked only about what the roster permitted, its answer can
only be no objection or an objection, and no answer in time, late or for
want of a slot, is unavailable unless `operators.authorizer.on_unavailable`
is `roster_only`. An answer in time that this build cannot read, and a
caller that gave up, are unavailable under either setting.

**Bounds.** Each call to another port runs under a timeout, 2 s unless set
and at most 30 s, and at most 16 at once unless set, 256 at most; a call over
either is unavailable, counted per cause.

**Sealed answers.** ADR-0066 property 1 has the consumer declare a port's
interface. A port whose answer is sealed, so that only a verified signature
mints a positive one, is declared instead by the package that mints the
answer, and its kinds live beside it: `internal/trust` declares `Roster` and
holds the `file` kind, `internal/operators` declares the authenticator and
the authorizer and holds their `roster` kinds. A later kind of either,
`api` or `authzen`, joins its package.

**Conformance.** `testdata/ports/trust-roster`, `operator-authenticator` and
`operator-authorizer` hold one case file each, every rule with a negative
control, and each kind's test runs them. `scripts/ports.txt` lists the three
ports; its doctor column names the keys the approval authority's change adds
to `doctor`, which does not report them yet.

This change adds no reason code, no configuration key and no wire field. The
plane does not read a roster yet: the approval authority's change wires
these ports, builds the `authn:` approver id from an authenticated answer,
and amends the approval records.

## Security / compatibility impact

No v1 wire bytes, digest or approval binding change. The roster and the
answer get payload types of their own, so no signature made for another
signed file verifies as either. Selecting the algorithm by the key keeps a
statement from choosing how it is checked. The roster's expiry bounds how
long a revoked operator keeps authority while a newer roster is withheld,
and the plane's account can withhold it for the file kind.

When the approval authority's change adds `approvals.authority: signed`, its
start refuses a configuration, a trust root or an approvals directory the
plane's own account can write, and not the authority floor: the plane raises
that floor itself, so its account writes it. That account can therefore roll
the roster back only to an older or equal serial of the same roster id,
within that roster's lifetime of at most 7 days, and that is the whole limit.

## Alternatives considered

- One pinned key per operator in the configuration: no expiry, no grants,
  and a restart to revoke.
- An authorizer that reads the grants carried in the authentication: a key
  revoked between the two would still be permitted.
- Grants with a project wildcard: a mistyped empty project would grant
  every project.
- An expiry with no ceiling: a withheld roster would keep a revoked operator
  for as long as the signer chose.

## Consequences

An operator is added, revoked or regranted by signing a new roster, with no
restart. The root key becomes the authority over every operator, and its
signer must re-sign, at a higher serial, at least once a week. A second kind
of each port needs its own cases to pass.

- A grant's tenant and project are compared exactly, never by pattern, case
  or path; no later reader may widen them so.
- The caller passes every key it pins, policy, freshness, route and lift, in
  `Others`; the approval authority's change refuses an empty `Others` under
  `signed`.
- `Open` runs its first lookup under the caller's context, which can wait on
  the floor's lock, so the approval authority's change bounds that context.
- The approval authority's change takes the roster id only from the
  configuration its start check protects, never from the floor directory,
  the roster file or the first roster seen; otherwise the plane's account
  could choose the roster id, and the limit above would not hold.

## Validation

- `internal/trust`: an envelope of every other payload type never verifies
  as a roster and a roster never as another file; a root equal to the
  policy, freshness, route or lift key is refused; a lower, forked, expired or
  future roster is refused; a roster of another id is refused after a
  restart, though the floor directory lists it; the last roster is kept
  until its expiry, then unavailable; the floor lowered by hand does not lower
  the roster held.
- `operators roster sign` refuses to replace a roster at `--out` that
  verifies under this root and names the same id, at the serial it signs or
  above, and replaces a roster envelope of another id or another root.
- `internal/operators`: a statement naming another algorithm or key, signed
  by another key, or of another payload type, is refused; two operators act
  only where their grants reach; an empty project is denied; a revoked key
  permits nothing; a veto only denies; an unavailable, late or zero answer
  from the roster or the veto blocks, and under `roster_only` a zero answer
  in time, a cancelled caller, or a caller whose deadline passes while the
  veto is asked, still blocks.
- The three conformance files, each rule with a negative control.
