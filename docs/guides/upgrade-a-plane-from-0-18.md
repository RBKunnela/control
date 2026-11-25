---
title: Upgrade a plane from 0.18
summary: What a plane meets in 0.19, the route's deadline and retry rules first, and the steps a signed plane adds for its records, inbox and stop list.
type: how-to
covers: [internal/reaction/maystop.go, internal/reaction/permits.go, internal/reaction/stopwrite/carry.go, cmd/guardana-control/route.go, cmd/guardana-control/stops_init.go, cmd/guardana-control/runs_read.go, cmd/guardana-control/procedure_cases.go, cmd/guardana-control/notify.go, internal/notify/deliver.go, internal/segmentlog/dir.go, cmd/guardana-gateway/collect_listen.go, cmd/guardana-gateway/runs.go, cmd/guardana-gateway/doctor_runs.go, internal/approvals/inbox/inbox.go, internal/gatewayconfig/yaml.go, adapters/enforce/decode.go, internal/files/judged.go, internal/files/exchange_*.go]
---

# Upgrade a plane from 0.18

## When to use this

A plane ran 0.18 and is to run 0.19. No format changed its version ([format
versions](../reference/versions.md#what-019-changed)), but 0.19 refuses some
routes, documents and settings 0.18 took. Every plane follows the first part,
in its order; a plane under `approvals.authority: signed` also follows the
second before it starts. For a plane on 0.17, follow [upgrade a plane from
0.17](upgrade-a-plane-from-0-17.md) with the 0.19 binaries first.

## Prerequisites

- The plane is stopped.
- Copies of its configuration, route and stop list directory are kept aside
  for a roll back.
- The paths below are examples; `route.json` is the document the route was
  signed from.

## Every plane

### 1. Ask doctor

```
guardana-gateway doctor --config gateway.yaml
```

Run the 0.19 binary on the stopped plane's configuration. `doctor` stops at
the first check it fails, where `run` would refuse to start; fix each and run
it again. Under any authority it now refuses:

- a configuration block written twice, such as two `policy:` mappings, and a
  key holding a `.`, such as `policy.fail_open_read: true`: write each block
  once, and a path as nested blocks;
- a route naming `DEADLINE_EXCEEDED`, `DENIED_ACTION_RETRIED_ARGUMENTS` or
  `DENIED_ACTION_RETRIED_RESOURCE`, at either version: step 2.

Under `signed` it also fails, and may fail first, on what the second part
fixes.

### 2. Take the deadline and retry rules out of the route

Skip this step when the route names none of them. These three rules compare
two events' times, so their findings are `SUSPECTED` at most and stop nothing
([ADR-0088](../adr/0088-a-verdict-that-compares-two-events-times-is-at-most-suspected.md)).
A signed plane takes the [signed route step](#1-the-route-and-the-stop-list)
instead.

```
# 2a. Edit route.json: remove every rule naming one of the three, raise the
# serial by one and keep the route_id. Sign it at a new path: 2c reads the
# old route at its own.
guardana-control route sign --key route.key --out /srv/plane/route-019.json route.json

# 2b. As the plane's account, which owns the list and runs react: a new,
# owner-only stops directory.
mkdir -m 0700 /srv/plane/stops-019

# 2c. The stop list carried into it, judged first under the old route.
guardana-control stops init --route /srv/plane/route-019.json --public-key /srv/plane/route.pub \
  --carry /srv/plane/stops --carry-route /srv/plane/route.json /srv/plane/stops-019

# 2d. In gateway.yaml: reaction.route to /srv/plane/route-019.json and
# reaction.stops to /srv/plane/stops-019.
```

The carry keeps every stop no lift ended. A stop one of the three rules
wrote is kept only where a rule of the new route still stops its procedure,
and only when its span is within that rule's lifetime. A carry that cannot keep a stop is
refused, naming the stop and the `stops lift` that ends
it: run that lift on the old list with the old route, which `stops lift`
takes for that alone, then run 2c again. Point `react` at the new route and
list; no plane reads the old one.

The same evidence now gives these rules' findings rule version `2` and a new
finding id, so `notify` delivers each alert among them once more, as a new
record.

### 3. Add the project to each procedure test case

A `procedure test` cases document states `project` in `run` and in each run
of `tree`: the project the run's record names. A document without it is
refused with exit 2, naming the member
([test a procedure](test-a-procedure.md#2-write-a-case)):

```
"run": {"id": "run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "tenant": "acme", "project": "refunds", "parent": "", "closed": false}
```

A case that expects one of the three rules `CONFIRMED` now fails: expect
`SUSPECTED`.

### 4. Name what notify's program reads

`notify` gives the program only `PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR`
and `USER` of its own environment. Name each other variable the program
needs with `--env`; a
name not set is refused with exit 2 before any program runs
([supervision](../reference/supervision.md#notify)). A program that loses a
variable may still exit 0, so check that the alert arrived.

```
guardana-control notify --findings findings --state notify-state \
  --env WEBHOOK_TOKEN --env HTTPS_PROXY -- ./post-alert
```

### 5. Check the collector's directory and socket

`collect` and `prune` refuse a trail directory that is a symbolic link, and
one whose parent another account than this one or root owns, or the group or
others may write without the sticky bit
([watch a plane without a collector](watch-a-plane-without-a-collector.md)).
Give `--dir` the directory's own path, under a parent the collector's account
or root owns.

`collect` reads `--listen` as a URL: escape `#`, `?` or `%` in a socket path,
as `collect` prints it in `export.endpoint`.

### 6. Replace signed outputs on Linux or macOS

`policy sign`, `route sign`, `operators roster sign`, `policy renew`,
`supervise --view` and the signed pause writers replace an existing output by
swapping two names in one step. Outside Linux and macOS, or on a file system
that cannot swap, such as some network file systems, they refuse to replace
it; a first output is written as before. Keep those
files on a local file system of Linux or macOS.

### 7. Send a result hash the plane takes

Send a `complete`'s `resultHash` as `sha256:` and 64 lower-case hex digits, or
none: a plane serving the enforcement API refuses any other form as malformed.
0.19's Go and Python clients check it before sending; 0.18's Python client did
not.

A plane not under `signed` then starts; a signed plane starts after the
second part.

## A signed plane

### 1. The route and the stop list

Where the route names one of the three rules, sign it again and carry the
list as [upgrade a plane from 0.17](upgrade-a-plane-from-0-17.md#steps) does,
the stop writers' account owning the new directory:

```
# As an admin: the route without the three rules, at the next serial.
guardana-control route sign --key admin.key --out /srv/plane/route-019.json route.json

# As root: a copy of the plane's stop list floor for ops, and the new stops directory.
cp -Rp /var/lib/guardana/stopsfloor /srv/plane/stopsfloor-copy
chown -R ops /srv/plane/stopsfloor-copy
mkdir /srv/plane/stops-019
chown ops:guardana /srv/plane/stops-019
chmod 2750 /srv/plane/stops-019

# As ops, the old list's owner: the carry.
guardana-control stops init --key op.key --route /srv/plane/route-019.json \
  --roster /etc/guardana/roster.json --root-key /etc/guardana/root.pub \
  --carry /srv/plane/stops --carry-route /srv/plane/route.json \
  --stops-floor /srv/plane/stopsfloor-copy /srv/plane/stops-019

# As root: the copy is no longer needed.
rm -r /srv/plane/stopsfloor-copy
```

The carry takes the write bits off the old list before it writes the new
one, so a `react` left on it fails rather than append a stop no plane reads.
Under another account than the list's owner it refuses before it writes
anything. A kept retry stop of an agent or a principal needs a
`REPEATED_DENIAL` rule of its procedure at that scope
([reaction under signed](../reference/reaction-signed.md)). Point
`reaction.route` and `reaction.stops` at the new files, and `react` too.

### 2. The runs directory

A signed plane refuses to start, and `doctor` fails, while `records/` holds
more than the 65,536 records a start reads to carry their closes. As the
operators' account, archive the trees whose every run expired:

```
guardana-control runs prune --expired-before 2026-11-01T00:00:00Z --archive /srv/runs-archive /srv/plane/runs
```

`react` under a signed route reads only a signed `--runs` directory: give it
the plane's, with `--tenant` and `--project`
([runs](../reference/runs.md#a-signed-runs-directory)).

### 3. The inbox and the environment

A signed plane refuses an `approvals.inbox_dir` its own account does not own,
at start, in `doctor` and at every read: `chown` it to the plane's account,
the operators' group kept, mode `1770`
([which account owns what](set-up-signed-operators.md#which-account-owns-what)).
It also refuses a stop list its own account may write through an access
control list (remove that entry), and an export header that a variable sets with its hyphens
spelled as they are, such as `GUARDANA_CONTROL_EXPORT_HEADERS_X-TENANT`: put the header under
`export.headers` in the configuration, which no other account should read.

Then start the plane.

## Verify

- `doctor` passes every check.
- `stops list` on the new directory shows each kept stop and its rule; lift
  any you do not keep.
- `procedure test` passes each cases document.

## Roll back

Stop the plane and start the 0.18 binaries. 0.18 reads the route 0.19 signed
and the list it carried, unless that list keeps a stop of one of the three
rules: 0.18 refuses such a line and will not start on that list. In that case
point `reaction.route` and `reaction.stops` back at the files you kept. Make a
new route floor with `policy state init --kind route --route-id <route_id>` in
a new directory and name it in `reaction.floor_dir`: the old one holds the new
route's serial. Under `signed` the stop list floor holds the carried list's
serial as well: make a new floor with `stops floor init --tenant <tenant>
--project <project>` in a new directory and name it in
`reaction.stops_floor_dir`; a floor holding no serial takes the old list. A
signed carry left that list without its write bits: give them back as its
owner with `chmod u+w` before 0.18's `react` writes to it.

0.18 refuses `project` in a cases document and `notify --env`: remove both.
