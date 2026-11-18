---
title: Set up signed operators
summary: Lay out the accounts and directories of a signed plane, sign and renew its operator roster, revoke a key, and approve or pause as a named operator.
type: how-to
covers: [cmd/guardana-control/operators.go, cmd/guardana-control/approvals_sign.go, cmd/guardana-control/pause_signed.go, cmd/guardana-gateway/authority.go, cmd/guardana-gateway/doctor_authority.go, internal/trust/**, internal/operators/**, internal/approvals/inbox/**, internal/gatewayconfig/notwritable.go]
---

# Set up signed operators

Use this when a plane should take an approval, a pause, a run or a stop only
from a person it can name by a key, not from whoever can write a directory.
Under `approvals.authority: signed` a roster signed by a root key you pin names
each operator. Why each piece is signed, and what a signature never proves, is
on [signed operations](../concepts/signed-operations.md). The roster and the
approval authority are `experimental`
([trust-roster](../status.md#trust-roster),
[approval-authority](../status.md#approval-authority)). Nothing here is a
security boundary yet.

## Prerequisites

- A plane set up as [run the gateway](run-the-gateway.md) shows, steps 1 to 7.
- Three kinds of account: an admin who holds the root key and owns the
  configuration (root, in the layout below), one account per operator, and
  the plane's own account, which runs `guardana-gateway run` and is not root.
- An operators' group holding each operator's account.

## Which account owns what

`run` and `doctor` refuse a signed plane whose own account owns, or may
write, the configuration, `trust.root_public_key`, `trust.roster`,
`pause.file`, `reaction.route`, `reaction.stops` or the runs directory's
`records/`, or any directory on their paths; one where any of those entries
is missing or carries an access control list (on Linux and macOS); and one
whose environment sets any of its keys. Root's files of mode `0644` in
root's directories of mode `0755` pass.

| Path | Owner and mode |
| --- | --- |
| the configuration, `trust.root_public_key`, `trust.roster` | root, files `0644`, directories `0755` |
| `approvals.dir` | the plane's, the operators' group, mode `2750`; the plane writes its records `0640` |
| `approvals.inbox_dir` | the plane's, the operators' group, mode `1770`, so an operator removes only their own answers |
| `approvals.hold_journal_dir`, `trust.floor_dir`, `pause.floor_dir` | the plane's |
| the pause file's directory | the operator's, the plane's group, mode `2750`; the operator writes the signed pause file `0640` |
| `runs.dir` | as [a signed runs directory](../reference/runs.md#a-signed-runs-directory) says |
| the route and the stop list | the route `0644`, as `route sign` writes it, in a directory the plane's account cannot write; `reaction.stops` the stop writers', in a group of the plane's account alone, mode `2750`, where they write the list `0640` ([reaction under signed](../reference/reaction-signed.md)) |

The `2` in `2750` is the setgid bit: on Linux it gives a new file the
directory's group rather than its writer's, as BSD and macOS do without it.

## Steps

### 1. Make the keys

As the admin, and as each operator in their own account:

```
guardana-control policy keygen --out root    # the admin
guardana-control policy keygen --out op      # each operator
```

Each prints `key_id` and `public_key`. A command refuses a private key file
another account owns, or one the group or others have any permission on, so
each key stays in its holder's account. The root and operator keys must
differ from the policy, freshness and route keys: the plane refuses a root
that is one of them, and a roster naming one of them or the root.
Copy `root/signing.pub` to `/etc/guardana/root.pub`.

### 2. Sign the roster

Write the source with one entry per operator key, `level` being `read`,
`operate` or `admin`; `operate` approves, pauses and signs runs and stops,
`admin` also a route:

```json
{"kind": "trust-roster/v1alpha1", "rosterId": "acme-operators", "serial": 1, "keys": [
  {"keyId": "ed25519-<16 hex digits>", "alg": "ed25519", "role": "operator", "subject": "alice",
   "publicKey": "<44 characters of base64>",
   "grants": [{"tenant": "acme", "project": "orders", "level": "operate"}]}]}
```

```
guardana-control operators roster sign --key root/signing.key --out roster.signed --valid-for 72h roster.json
install -m 0644 roster.signed /etc/guardana/roster.json
```

It prints the roster's id, serial, digest, key count, `issued_at`,
`expires_at`, the root's key id and the file. A roster lasts 24 hours unless
`--valid-for` says otherwise, at most `168h`. As the plane's account, give the
roster its floor:

```
guardana-control operators floor init --roster-id acme-operators /var/lib/guardana/roster-floor
```

### 3. Configure the plane

```yaml
plane_id: orders-eu-1           # this plane's own id, one per plane
approvals:
  authority: signed
  dir: /var/lib/guardana/approvals
  hold_journal_dir: /var/lib/guardana/holds
  inbox_dir: /var/lib/guardana/inbox
trust:
  root_public_key: /etc/guardana/root.pub
  roster: /etc/guardana/roster.json
  roster_id: acme-operators
  floor_dir: /var/lib/guardana/roster-floor
operators:
  authenticator:
    kind: roster
  authorizer:
    kind: roster
```

A signed plane serves one tenant: a `listener.principal.tenant_id` other than
`tenant_id` is refused. Run `doctor`, then `run`, as the plane's account.

### 4. Approve a held request

From an operator's own account, list the holds and answer one:

```
guardana-control approvals list /var/lib/guardana/approvals
guardana-control approvals approve --key op/signing.key --inbox /var/lib/guardana/inbox -- /var/lib/guardana/approvals <approval_id>
```

`approvals reject` takes the same flags, and any valid rejection wins. The
answer counts only from a roster operator granted `operate` for the call's
tenant and project; `--approver-id` is refused for a signed hold, and the
command warns when run as the plane's account. The agent's identical retry
then runs ([approvals](../concepts/approvals-and-the-held-call.md)).

### 5. Pause a tool

As the operator, who owns `/srv/pause`, and `floor init` as the plane:

```
guardana-control pause init --key op/signing.key --plane-id orders-eu-1 --tenant acme --project orders \
  /srv/pause/pause.json
guardana-control pause floor init --tenant acme --project orders /var/lib/guardana/pause-floor
guardana-control pause add --action tool --provider orders --name refund \
  --key op/signing.key --roster /etc/guardana/roster.json --root-key /etc/guardana/root.pub /srv/pause/pause.json
```

```yaml
pause:
  file: /srv/pause/pause.json
  floor_dir: /var/lib/guardana/pause-floor
```

### 6. Renew and revoke

Sign the roster again before `expires_at`, each time with a higher `serial`,
and install it over the old one. The plane reads the roster file again each
time it judges a signature and takes a higher serial. Once the roster it
holds has expired and no newer one is in place, no operator's signature
counts.

To revoke a key, leave its entry out and sign at the next serial. A plane
that never reads the new roster, because it is not installed or is withheld,
trusts the old one until it expires: a short `--valid-for` bounds how long a
revoked key's signature still counts.

## Verify

`doctor` prints an `ok` line for `trust` naming the plane, its tenant, the
roster's id and serial, how many keys it names and the floor's serial. A
held request answered in step 4 runs on the agent's retry.

The two-account job of continuous integration runs the cases
[scripts/expected-runs.txt](../../scripts/expected-runs.txt) names: file
ownership, a signed run, `react` under a signed route, and the health and
export sockets. None of them approves a held request from an operator's own
account.

## Roll back

For a plane with no `runs.dir` and no route: set `approvals.authority:
directory`, remove `plane_id`, `approvals.inbox_dir`, `pause.floor_dir` and the
`trust` and `operators` keys, which every other authority refuses, give the
plane a pause file made without `--key`, and restart. Under `directory`, write access to `approvals.dir` is the approval
authority again.
