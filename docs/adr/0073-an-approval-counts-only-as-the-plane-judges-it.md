# ADR-0073: An approval counts only as the plane judges it, from an authority it names

Status: accepted
Date: 2026-11-05

Amends [ADR-0066](0066-each-decision-about-authority-is-a-port.md) property
3, [ADR-0071](0071-operators-are-named-by-a-signed-roster.md) on what a
signed start refuses, and [ADR-0016](0016-approval-providers-and-the-lost-hold.md)
on the provider key. Builds on ADR-0071's roster, authenticator and
authorizer.

Amended by [ADR-0075](0075-a-signed-plane-takes-a-pause-only-from-an-operators-signature.md),
[ADR-0076](0076-a-signed-plane-takes-a-run-only-from-an-operators-signature.md)
and [ADR-0077](0077-a-signed-plane-takes-a-stop-list-only-from-operators-signatures.md): under signed the plane also refuses to start when its own
account may write the pause file, the run records, the route file or the stops
directory, each record holding its part.

## Context

A held call ran on whatever the approvals store answered: one place both
held the call and said who approved it, and the approver id was a claim
anyone who could write the directory could make. ADR-0066 made approval a
port and ADR-0071 gave operators signed keys and grants, but no plane read
either. The approval needs a port of its own, a format an operator signs,
and a configuration that cannot keep the old meaning by default.

## Decision

**The approval authority port** (`internal/gateway.ApprovalAuthority`) hands
back everything answered about one held approval, as a batch: complete,
truncated or unavailable, the zero value unavailable. A truncated batch is
read as unavailable. The store keeps the held records and the projections an
approver lists; it no longer carries the answer.

**The plane judges every answer itself**, in this order: it authenticates the
answer, compares every member with its own record of the hold (tenant,
project, request id, approval id, action digest, bundle digest, and a
decision time between the request and now), authorizes the operator for the
hold's own tenant and project at the grant that approves, folds the answers,
and builds the approver id with `authn:<issuer>:<subject>`. Any valid
rejection wins. A rejection counts only from an operator the authorizer
permits to approve, and is never left out for its decision time: one dated
outside the window is taken at the window's edge. An approval dated outside
it is no answer. An answer the roster or the authorizer could not judge,
and a batch that is not complete, is never read as no rejection: the hold
stands and the call is `INDETERMINATE`, and a reconciliation closes it
`APPROVAL_STATE_UNKNOWN`.

**Two kinds.** `signed` takes only an answer signed under the operator answer
payload type, whose body is `approval-answer/v1alpha1`: canonical JSON with
`kind`, `alg`, `keyId`, `tenant`, `project`, `requestId`, `approvalId`,
`actionDigest`, `bundleDigest`, `decision` (`approve` or `reject`),
`decidedAt` and `reason`, each required. It reads answers from
`approvals.inbox_dir`, a directory operators write, named
`<approval id>.<label>.answer`. A foreign name and a body for another
approval are left out alone and counted; a file named for the approval that
cannot be read as an answer makes the batch unavailable, since it may be the
rejection. It ignores every claim. The inbox holds at most 4096 names, so
the plane removes the answers of approvals it no longer holds once a
lifetime has passed; that needs the plane to own the directory, since under
the sticky bit only a file's owner and the directory's owner may unlink a
file. The same owner, the plane's account included where it owns the
directory, can therefore unlink any answer, a rejection among them; the
sticky bit stops only the other operators. `directory` takes the claim filed under the
hold's approval id, its approver id held to the claim rule.

**`approvals.authority: memory | directory | signed` replaces
`approvals.provider` and has no default.** A configuration without it, or
with the old key, is refused naming both. `directory` is what `provider:
file` was. This amends ADR-0066 property 3 for this port: its kind is chosen
by every operator, because the two defaults on offer grant authority in
different ways and a silent upgrade would change who may approve.
`scripts/ports.txt` names its default kind `required`.

**Under directory and signed, `approvals.hold_journal_dir` is required**, so
the ledger of spent approvals outlives the process.

**The signed proof is kept in the plane's ledger only.** A spend records the
authenticated approver id and the digest of the answer it rests on. No other
directory holds it, and no file an approver writes can name an `authn:`
approver. The ledger's lookup answers only what became of an approval, so the
proof is evidence written and never read back; a reconciliation closes a
lost hold whose approval the ledger marks spent or given up from that mark
alone, `APPROVAL_NOT_RESUMED`, never from what the inbox says now.

**There is no risk setting.** No veto is wired to the authorizer, and an
authenticator or authorizer that cannot answer always fails closed.

**Under signed the start refuses** a configuration file or a trust root key
file the plane's own account could change, as
`gatewayconfig.CheckNotPlaneWritable` judges it, and any key the environment
set. It hands the roster every key the plane pins (the policy key, the
freshness key, the route key and the route's lift key) as keys no roster may
name, takes the roster id from the configuration file alone, and holds the
roster's first read to a timeout. This corrects ADR-0071, which listed the
approvals directory: the plane owns that directory by design, so the list is
the configuration file, the trust root key file and the environment.

Amended in 0.17: the list also holds `trust.roster`, judged the same way. An
account that could write the roster file could put an older unexpired roster
back, and a revoked operator with it. A test holds every file key of the
configuration either to this list or to a named reason the plane may write
it or does not read it under signed.

## Security / compatibility impact

Every configuration breaks once. A directory or memory plane keeps the
approver as an unauthenticated claim, and doctor and `/healthz` say so. The
start checks do not see root, file capabilities or bind mounts and
namespaces; an access control list on a path is refused rather than read;
NFS and SMB answer for access as their server does; `SSL_CERT_FILE` and
`SSL_CERT_DIR` still feed the decision point's roots, which can only veto.
The plane's account still raises the roster's floor, so it can withhold a
newer roster within the roster's lifetime, as ADR-0071 says. Amended in
0.17: the roster file is out of that account's reach, so it can no longer put
an older roster in place; raising the floor it writes still withholds a newer
one until the held roster expires.

## Alternatives considered

- Two keys, one for the store and one for the authority: an operator could
  set one and believe the other.
- An in-memory ledger under the directory kind: a restart would let an
  approval be spent twice.
- Any authenticated rejection wins: an operator with no grant on the project
  could stop every call there.
- A side record of the signed answer in the approvals directory: a second
  copy an approver can write beside the one the plane trusts.

## Consequences

The approvals directory stays, as a listing of held calls, and each record
says which authority holds it. Approving under signed is the approvals
command's, which signs with `--key` from the plane's record of the hold; the
console holds no operator key, so it shows a signed hold and that command and
answers nothing. Under signed the plane writes the directory's files `0640`
for an operators' group to read; the command warns when it signs as the
directory's owner, since the separation holds only from an operator's own
account. `Find` still lists the held records,
so a retry is paired with its hold and a record of a spent hold refuses the
next identical call.

## Validation

`testdata/ports/approval-authority/cases.json`, run under both kinds by
`internal/gateway`; the answer format and its fuzz target in
`internal/approvals`, and the inbox in `internal/approvals/inbox`, which the
console does not link; the configuration refusals in `internal/gatewayconfig`;
the start checks and the pinned key registry in `cmd/guardana-gateway`.
