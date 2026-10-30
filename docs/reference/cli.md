---
title: Command line
summary: The two binaries, what each prints as its help, and the exit statuses they share.
type: reference
covers: [cmd/guardana-control/**, cmd/guardana-gateway/**, internal/policykey/**, internal/pause/**, internal/trailfile/**]
---

# Command line

Two binaries, built from the repository root with `go build ./cmd/<name>`;
[status.md](../status.md) says what each does today. Each fenced block below
is the help its binary prints on a usage error, byte for byte; the test its
marker names diffs it against the binary, so a flag or command changed
without this page fails the gate.

| Exit status | Means |
| --- | --- |
| 0 | The command did what it was asked. |
| 1 | A case or a check failed, or input refused by a command 2 does not name: stderr says why, one line each; `policy test`, `procedure test`, a scenario, `coverage` and `supervise` print what failed. So do an export with a gap and a failed `notify` delivery. |
| 2 | A usage error (stderr carries the help below or names the flag or argument), a scenario that could not run, an export refused or cut short, an incomplete `observe import`, or a refused `coverage`, `supervise`, `notify` or `procedure` input. |

Without arguments either binary prints its version and one status line on
stdout and exits 0.

Every command of either binary refuses an argument holding a PEM marker, the
start of a key file's body line, a line break or another control character
before it reads a flag, with one line that does not repeat the argument and
status 2: such an argument is key text where a path belongs, or text that
would break the line reporting it. Only the body line's unbroken start is
matched, so a spaced or partial one passes. Key text read from a setting, a
file, the environment or a request is printed as `[key text withheld]`,
keeping the rest, logs included.
A message holding a control character, a line or paragraph separator, a
format character or bytes that are not UTF-8 is printed as a quoted Go string.

## guardana-control

`policy lint`, `policy test` and `policy explain` ([policy-explain.md](policy-explain.md)) read a document without a plane, and
`policy keygen` and `policy sign` make the key and the signed bundle a plane
loads: [guides/write-and-test-a-policy.md](../guides/write-and-test-a-policy.md)
is their page. The `approvals` commands read and answer the records under an
approvals directory, from outside the gateway process.

`policy renew` verifies the bundle against its public key, raises a signer's
floor, then writes the statement it signs with the freshness key. `policy
state init` and `reset` make and lower floors
([ADR-0038](../adr/0038-a-signed-freshness-statement-and-a-serial-floor.md));
a reset reaches a running plane's clock check only when it restarts.

`policy keygen` creates the directory `--out` names, mode `0700`, and refuses a
path that exists. Into it go `signing.key`, the private key as one PKCS#8 PEM
block, mode `0600`, and `signing.pub`, the public key as one line of standard
base64 and a newline, which `policy.public_key` takes as it is. It prints exactly two lines, `key_id: <id>` and `public_key: <line>`,
the two members the gateway's `policy` group takes. The id is `ed25519-` and
the first 16 hex digits of SHA-256 over the public key's 32 bytes; nothing
lets an operator choose it.

`policy sign` prints one `name: value` line each for `bundle_id`, `version`,
`serial`, `digest`, `key_id` and `out`, and writes the bundle mode `0644`,
replacing an earlier bundle at `--out`. It writes nothing when it refuses: a
document that does not parse, refused before the key is opened; a key file
another account owns, one on which the group or others have any permission,
one that is not a regular file, and one that is not exactly one unencrypted
Ed25519 key in PKCS#8, with an OpenSSH, encrypted, EC, RSA or public key each
named; an `--out` that is the key or the document by any spelling or link, and
one that exists and is not a policy bundle, so no other file, another key
included, is replaced; and a bundle the loader would refuse. `--out` is
cleaned as text before anything reads it, so `a/link/../x` names `a/x`
whatever `a/link` points at. If syncing the directory fails after the
rename, `sign` reports it; the new bundle may be in
place.

The key reaches the command only as a path, and no refusal quotes it. Both
refuse on a platform without permission bits
([ADR-0018](../adr/0018-keys-and-bundles-on-disk.md)).

Both answering commands require `--approver-id`, a claim nothing checks;
flags come before the directory and the approval id.

`approvals list` prints, for each record, what the plane wrote — its state,
its resolution and both digests — and beside it the readable fields of the
projection the plane wrote at hold time. Those readable fields are not bound
to the action digest beside them, since the binding is over argument bytes no
record holds; the listing says so above the records. A listing the store
reports incomplete exits 1 and names what it could not read.

`approvals approve` and `approvals reject` write the answer whether or not a
plane runs, and exit 0 either way: the record waits for the next
plane. Where no plane holds the directory they say so on stderr: no held
call waits for the answer, since a hold does not outlive its plane, and a
plane that keeps a hold journal records it on that call's trail as too late.

Both commands refuse, writing nothing, an approval id that is absent, one
an approver answered already, one the plane consumed, one the plane closed
without resuming, one past its expiry, and an approver id or a reason over
its bound — each on its own line, naming what to do about it.

The `pause` commands write and read the pause file a plane names in
`pause.file` ([ADR-0019](../adr/0019-an-operator-can-pause-calls.md)), and
[concepts/enforcement-modes.md](../concepts/enforcement-modes.md) says what a
pause does to a call. `pause init` creates the file, pausing nothing, and
refuses a name that is taken. `pause add` takes exactly one scope: `--global`,
every call; `--provider <p>`, every call to that upstream by its configured
name; or `--action <k>` with `--provider <p>`, where `<k>` is `tool`, `prompt`
or `resource` and a tool also takes `--name <n>`, the name the plane routes
by. A prompt or a resource takes no name. `<f>` is the pause file, relative to the working directory. It prints
only the id it drew for the entry, and `pause remove <file> <id>`
takes that id; removing the last entry leaves a file pausing nothing,
because a missing file blocks every call. `pause list` prints one line per
entry, its reason included, or `no entries`.

Write access to the pause file is the authority to pause and to lift one:
any process running as the plane's user can empty the file, so run the commands
as that user. They refuse, writing nothing, a file or directory the group or
others may write or another account owns, a link, a file the plane would
refuse to read, a second scope or none, a name, a reason or a scope the file
cannot hold, and a 65th entry, each on one line that does not repeat the
value. A writer waits up to ten seconds for another writer's lock; a
running plane takes none. A pause blocks every call not yet handed out
when the plane reads it, within one `pause.poll_interval`; it cancels
nothing already running.

The `runs` commands open, close and list the runs a plane with `runs.dir`
serves: [runs.md](runs.md).

The `observe` commands import spans or access logs into an observation log
and export it: [observations.md](observations.md). `coverage`
is [coverage.md](coverage.md), `supervise`, `notify` and `findings export`
[supervision.md](supervision.md), `--view` [run-view.md](run-view.md), `procedure`
[guides/test-a-procedure.md](../guides/test-a-procedure.md), `route`, `stops`
and `react` [reaction.md](reaction.md), and `hook`, exiting with its
profile's statuses, [extending/runtime-profiles.md](../extending/runtime-profiles.md).

`console` serves a page that answers approvals and writes pauses:
[console.md](console.md).

<!-- generated: go test ./cmd/guardana-control -run TestCLIPage -->
```
usage:
  guardana-control policy lint <file>
  guardana-control policy test <dir>
  guardana-control policy explain <case>
  guardana-control policy keygen --out <dir>
  guardana-control policy sign --key <file> --out <file> <document>
  guardana-control policy renew --key --bundle --bundle-public-key --floor --out
  guardana-control policy state init --kind plane|signer|route
      (--bundle-id <id> | --route-id <id>) <dir>
  guardana-control policy state reset --kind plane|signer --bundle-id <id> --reason <text>
      (--empty | --serial <n> --digest <d> --issued-at <t>) <dir>
  guardana-control approvals list <dir>
  guardana-control approvals approve --approver-id <id> [--reason <text>] <dir> <approval-id>
  guardana-control approvals reject --approver-id <id> [--reason <text>] <dir> <approval-id>
  guardana-control pause init <file>
  guardana-control pause add --provider <p> [--action <k> [--name <n>]]|--global [--reason <r>] <f>
  guardana-control pause remove <file> <id>
  guardana-control pause list <file>
  guardana-control runs open --project --tenant --principal-type --principal --agent
      --ttl [--parent] <dir>
  guardana-control runs close <dir> <run-id>
  guardana-control runs list <dir>
  guardana-control observe import --source <file> --log <dir> <file>
  guardana-control observe export [--after] [--limit] [--max-bytes] <file>
  guardana-control coverage --inventory <file> [--plane <config> [--evidence <export>]]...
      [--source <descriptor> --log <dir>]...
  guardana-control procedure lint <file>
  guardana-control procedure test <cases>
  guardana-control supervise --procedure <file> --runs <dir> --run <run-id> --findings <dir>
      [--evidence <export>]... [--source <descriptor> --log <dir>]...
      [--view <file> [--view-all]]
  guardana-control notify --findings <dir> --state <dir> [--init] [--timeout <duration>]
      -- <program> [<arg>]...
  guardana-control findings export --findings <dir> [--after <cursor>] [--limit <n>]
      [--max-bytes <n>]
  guardana-control route sign --key <file> --out <file> <route.json>
  guardana-control stops init --route <file> --public-key <file>
      [--carry <dir> --carry-route <file>] <dir>
  guardana-control stops lift --route <file> --public-key <file> --key <file> --run <run-id>
      [--through <line>] <dir>
  guardana-control stops list --route <file> --public-key <file> <dir>
  guardana-control react --findings <dir> --runs <dir> --route <file> --public-key <file>
      --stops <dir>
  guardana-control hook (--profile <id> | --profile-file <file>) --socket <path>
      --state-dir <dir>
  guardana-control console --approvals <dir> [--pause <f>] --approver-id <id> [--until-stdin-closes]

Write access to the approvals directory is the approval authority:
--approver-id is a claim recorded as given, never an identity.
Write access to the pause file is the authority to pause a call and to lift a pause.
Write access to the runs directory is the authority to open and to close a run;
a token acts as its run until it expires or is closed, and runs open prints it once.
Write access to a floor directory is the authority to lower its floors;
policy state reset is the one way that records why.
Only the lift key lifts a stop while a plane runs; write access to the stops directory
adds any stop the route allows and, across a restart, can start a new list with none.
```
<!-- /generated -->

## guardana-gateway

`run` serves one plane from a configuration file and `doctor` checks that
file without serving: [guides/run-the-gateway.md](../guides/run-the-gateway.md)
is their page and [configuration.md](configuration.md) lists every key.
`--config` is required. A key naming a file or
directory refuses key text, naming the key, never the value. On an interrupt
or `SIGTERM`, `run` admits no new call, gives admitted ones
`upstream.call_timeout` plus ten seconds, plus any `pdp.timeout`; an
`enforce_api` plane waits ten seconds and abandons open executions. Either
exits 1 when it cut one, lost a closing record or could not close the spool;
`doctor` when its plane does not close or stdout does not take its report.

`collect` and `trail` read no configuration:
[guides/watch-a-plane-without-a-collector.md](../guides/watch-a-plane-without-a-collector.md)
is their page. `collect` listens on a loopback IP address only and appends
what a plane exports, previews cleared, to one file until stopped; `--out`
names a trail file or a new path, and any other is refused untouched. A last
line with no newline is removed only when it can be the start of an evidence
line, so a file of one line that cannot, such as a settings file, is refused
too. `trail` prints one line per request and exits 1 when a chain fails,
cannot be read either way, or the file holds no trail, when the file ends in a
partial line that no running `collect` holds, and when it holds more than
100,000 lines.

`scenario run` holds a running plane to scenario files
([scenario-format.md](scenario-format.md)); it exits 1 when one differed, and
2, a failure too, when one could not run.

`dev`: [dev.md](dev.md).

<!-- generated: go test ./cmd/guardana-gateway -run TestCLIPage -->
```
usage: guardana-gateway [run --config <file> [--run-token-file <file>] | doctor --config <file> | collect --listen <addr> --out <file> | trail [export [--after <cursor>] [--limit <n>] [--max-bytes <n>] [--request <id>]... [--run <id>]... [--tenant <id>]... [--project <id>]... [--kind <kind>]...] <file> | scenario run --config <file> --trail <file> [--control <file>] [--timeout <d>] <path>... | dev --config <file> --policy <file> [--decision-point=silent] [--state <dir>] [--scenario <file>]...]

run
  -config string
    	the configuration file to read
  -run-token-file string
    	a stdio plane with runs.dir: the file holding the token of the one run it serves

doctor
  -config string
    	the configuration file to read

collect
  -listen string
    	the loopback address to listen on, host:port; port 0 takes a free one
  -out string
    	the trail file to append what arrives to

trail
  -after cursor
    	trail export: start after the line this cursor, from an earlier export, names
  -kind kind
    	trail export: write the events of this kind, as the contract spells it; repeatable
  -limit int
    	trail export: the most records to write, every type counted; at most 100000 (default 1000)
  -max-bytes int
    	trail export: the most bytes of whole lines to read; 0 is no bound
  -project id
    	trail export: write the events of this project id; repeatable
  -request id
    	trail export: write the events of this request id; repeatable
  -run id
    	trail export: write the events of this run id; repeatable
  -tenant id
    	trail export: write the events of this tenant id; repeatable

scenario
  -config string
    	the plane's configuration, which names its listener, its /healthz, its approvals directory and its pause file
  -control string
    	the guardana-control that answers approvals and pauses; by default the one beside this binary
  -timeout duration
    	the bound on each wait: the spool's drain, a pause read, a run of guardana-control, and a call past the upstream's own timeout (default 10s)
  -trail string
    	the trail file the plane's collector writes

dev
  -config string
    	the demo's configuration, without the keys dev sets
  -decision-point silent
    	silent makes the plane's decision point a loopback port dev binds and never answers, so every question times out; dev then owns every pdp key
  -policy string
    	the policy document dev signs in memory
  -scenario file
    	a scenario file to run on a plane of its own; repeatable
  -state string
    	a new directory for the plane's state; by default a temporary one
```
<!-- /generated -->
