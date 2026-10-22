# Changelog

Notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

The `0.x` series carries no compatibility promise between minor versions; see
[ADR-0008](docs/adr/0008-branching-and-release-policy.md). Each release is built,
signed and attested from its tag; [RELEASING.md](RELEASING.md) shows how to
verify one.

## [Unreleased]

### Security

- Built with Go 1.27.3, which fixes GO-2026-6809 in `crypto/x509`;
  `govulncheck` found it reachable from the evidence reader under 1.27.2.
- The MCP client the filesystem server's guide is checked with locks
  `certifi` 2026.10.19, which fixes PYSEC-2026-4320 (GHSA-6q48-6c7w-9gw2).
  Neither binary nor the Python client of the enforcement API uses it.

### Fixed

- The enforcement API answers a call whose rewrite moved the decided resource
  with `BLOCK` and the abort's code, `OBLIGATION_NOT_UNDERSTOOD`, after the
  decision's own; it carried the kernel's allow alone, so the hook bridge and
  the Python client reported a block with only `OBLIGATIONS_ATTACHED`.
- The Go and Python clients of the enforcement API refuse an admit answer
  whose decision has no schema version or one on another major as malformed,
  and run no tool on it; the answer vectors and client cases carry the
  version.
- A resource pointer's array index is decimal digits only, as RFC 6901 reads
  it: `+1`, `-0` and `+01` no longer name an element.
- An enforcement API plane in `OBSERVE` handed out a call whose envelope the
  contract refused for more than an unnamed tool, such as a transaction
  naming no resource; it now aborts it and answers `BLOCK`, as the MCP
  adapter does. A `tools` table that
  classes a tool `SPAWN_OR_DELEGATE`, which this API can never decide, is
  refused when the plane starts and by `doctor`.
- The dependency scan in `make security` fails when `osv-scanner` prints no
  "Scanned" line for a `go.mod`, `uv.lock` or `package-lock.json` the
  repository holds, reads any file as holding no package, or finds no
  lockfile at all, instead of passing over a lockfile it could not read; `make scan-repo-files-probe`, now part of `make quality`,
  is its negative control.
- `make test` fails on a package with no test files outside `api/gen/`.
- `make test-race` reads its results through the test reporter, as
  `make test` does, so a package that runs no test under the race detector
  fails it.
- `make check-shell` also checks a file whose first line names `sh`, `bash`,
  `dash` or `ksh` in `/bin`, `/usr/bin` or `/usr/local/bin`, directly or
  through `env`, not only `*.sh`.
- `make fuzz-smoke` fails, naming the file, on a test file it cannot read
  instead of passing over it.
- CI's quality gate checks every pinned action SHA against the commit its
  version comment's tag names in that action's repository, and fails when
  GitHub cannot answer.
- The format versions page names `v1alpha1` as the enforcement API version
  this tree writes and reads, and says which formats carry no version of
  their own: the signed envelopes and the spool's segment framing.

### Changed

- Statements on the public pages that the code contradicted are corrected:
  what `OBSERVE` still blocks, a held trail's closing record after hand-out,
  shutdown of an enforcement API plane, the collector's 415, the hook's
  deadlines, coverage's join and others. The status page, roadmap and backlog
  stop describing the Python client and the hook bridge as planned, and
  ADR-0050 is marked accepted, as it was on merging.

## [0.13.0] - 2026-10-20

A coding runtime's tool hooks can now reach a plane's `experimental`
enforcement API through `guardana-control hook`. The hook only takes calls
away: it lets a call run only when the plane answers `EXECUTE` of exactly the
input the runtime proposed, and reports its completion with the input that ran
([ADR-0056](docs/adr/0056-a-coding-runtimes-hooks-reach-the-plane-through-one-bridge.md)).
The first built-in profile, [for one coding runtime](docs/reference/claude-code-hooks.md),
is `experimental`, qualified on one release of that runtime and labelled
"decided, with failure gaps": the runtime, not the plane, runs the call, so a
hook is not an enforcement point. Outside `OBSERVE`, a call is now handed out
only while the policy it was decided under is still installed and fresh
([ADR-0055](docs/adr/0055-a-call-is-handed-out-only-while-its-policy-stands.md)),
and the enforcement receiver holds a lock beside its socket, so a second plane
on the same socket is refused
([ADR-0054](docs/adr/0054-the-enforcement-receiver-holds-a-lock-beside-its-socket.md)).
Every pull request now runs the guide for connecting an existing MCP setup
with the MCP project's Python SDK
([ADR-0057](docs/adr/0057-an-external-mcp-client-runs-the-guide-on-every-pull-request.md)).
Among the pre-release audit's fixes: the receiver serves only the listener it
locked, and `OBSERVE` counts a stale hand-out only for a call its policy let
run. The project is still alpha, and the `0.x` series makes no compatibility
promise between minor versions.

### Added

- `guardana-control hook` takes a coding runtime's tool events to a plane's
  enforcement API: a call runs only when the plane answers `EXECUTE` of
  exactly the input the runtime proposed, and its completion is reported with
  the input that ran, compared by value
  ([ADR-0056](docs/adr/0056-a-coding-runtimes-hooks-reach-the-plane-through-one-bridge.md)).
  The hook only restricts: it never replies allow, ask or defer. The first
  built-in profile, [for one coding runtime](docs/reference/claude-code-hooks.md),
  is decided with failure gaps and qualified on one release of that runtime:
  20 cases run headless against a plane, with the results beside the profile.
- A CI job runs the guide for connecting an existing MCP setup end to end with
  an MCP client outside the Go SDK, the MCP project's Python SDK, against the
  reference filesystem server, on every pull request
  ([ADR-0057](docs/adr/0057-an-external-mcp-client-runs-the-guide-on-every-pull-request.md)).
  The example now pins the server and its packages in a lockfile, and the
  guide installs it with `npm ci --ignore-scripts`.

### Fixed

- An enforcement receiver's `Serve` refuses any listener but the one its own
  `Listen` bound with the socket's lock held, and that one a second time, so
  the plane never serves a socket whose lock it does not hold.
- In `OBSERVE`, `pipeline_stale_handed_out_total` no longer counts a call the
  kernel blocked or held: only one whose decision let it run, a read the
  fail-closed table opened included
  ([ADR-0055](docs/adr/0055-a-call-is-handed-out-only-while-its-policy-stands.md)).
- `guardana-control react` reads the clock for a stop once it holds the lock
  on the stop list. A stop no longer loses the time spent waiting for the lock,
  and a finding is no longer refused as "not written" because another `react`
  wrote a line with a later clock while this one waited.
- The gateway configuration refuses a double quote inside a plain value, with
  its line, instead of reading a `#` after it as part of the value. A
  configuration that holds one, such as an upstream argument `--name="x"`, no
  longer loads: quote the whole value and write the quote as `\"`.
- The evidence-report example reads a state of any earlier minor version and
  requires only the members that version had, comparing versions as numbers.
- The enforcement receiver holds a lock on `<socket>.lock` beside its socket
  for as long as it listens, and a second plane on the same socket is refused
  while the lock is held. On macOS a live receiver with a full backlog refuses
  connections, so a second plane could remove its socket and take its clients
  ([ADR-0054](docs/adr/0054-the-enforcement-receiver-holds-a-lock-beside-its-socket.md)).
  Built for Solaris, illumos or AIX, which have no `flock`, the receiver now
  refuses to listen, and `doctor` checks the lock file as `run` would.

### Changed

- A call is handed out only while the policy bundle it was decided under is
  still installed and fresh. A bundle replaced, or past its staleness budget,
  between the decision and the hand-out now blocks the call with
  `POLICY_STALE` outside `OBSERVE`, which counts it as `stale_handed_out`; a
  read `policy.fail_open_read` opened still runs while its bundle is the same.
  A resume judges this before it consumes its approval, and a change found
  then spends nothing; one found after the consume still blocks the call, with
  the approval spent
  ([ADR-0055](docs/adr/0055-a-call-is-handed-out-only-while-its-policy-stands.md)).

## [0.12.0] - 2026-10-16

The `experimental` enforcement API gets an `experimental` Python client,
`guardana_control.enforce`. Once this release is published, the release
workflow uploads it to PyPI as `guardana-control` by trusted publishing
([ADR-0053](docs/adr/0053-a-python-client-of-the-enforcement-api-in-this-repository.md)).
It asks a plane for a decision before your tool acts and reports how the call
ended. It cooperates and is not a security boundary, and it passes the same
conformance cases and answer vectors as the Go reference. Each change now
reaches `main` through a pull request that must pass CI's `make quality`
([ADR-0052](docs/adr/0052-a-change-is-gated-on-its-pull-request.md)). Among
the fixes from a code audit: on Linux the enforcement receiver no longer
removes a socket a live receiver may hold, supervision reports a deadline not
checked when an event of the run has no timestamp, and `react` reads the clock
for each stop as it writes it. The project is still alpha, and the `0.x`
series makes no compatibility promise between minor versions.

### Added

- A Python client of the `experimental` enforcement API, under
  `clients/python/` and imported as `guardana_control.enforce`
  ([ADR-0053](docs/adr/0053-a-python-client-of-the-enforcement-api-in-this-repository.md)).
  One synchronous call asks the plane, runs your tool only with the bytes it
  authorized, and closes with one `complete` or one `abort`. It imports the
  standard library alone and needs Python 3.11 or later. It cooperates and is
  not a boundary: its calls are `decided, not enforced`.
- Answer vectors in `testdata/enforce/answers/vectors.jsonl`: a status and a
  body with what a client must do with it. Each is `read`, `refused`, or
  `may_refuse`, where the Go reference reads a form outside the one the
  receiver writes and another client may refuse it. The Go reference, a second
  Go client and the Python client run them, and they seed the decoder's fuzz
  target. `docs/contracts.md` says which form a client may rely on.
- One more client case, `tool-reports-nothing`: a tool that returns without a
  status is completed `UNKNOWN`.
- `make check-python`, part of `make quality`: the client's tests on two
  pinned CPython versions, its linter and type checker, and a build of its
  wheel. `make bootstrap` installs `uv` and both interpreters.
- The release workflow builds the Python client's wheel and source archive
  and attests them before any other tool of the release job runs. After the
  GitHub release is published, a separate job in the `pypi` environment waits
  for a maintainer's approval, then uploads exactly the files the build listed
  to PyPI by trusted publishing, with no stored token, and reads the index
  back. The dry run uploads a development release to TestPyPI the same way,
  from `main`.

### Changed

- A change reaches `main` as one squash-merged pull request whose gate is
  CI's `make quality`, a maintainer's own included; only a release commit is
  still gated cold on a maintainer's machine and pushed directly. Until 1.0 a
  release follows every one to three changes
  ([ADR-0052](docs/adr/0052-a-change-is-gated-on-its-pull-request.md)).
- The race tests run every night with every processor busy, on Linux and on
  macOS, so a test that depends on the clock fails there and not in a release
  gate. A red night opens an issue.
- The README, the site's title and the repository's description call the
  project an AI agent supervision framework; the README opens with what runs
  today and puts the 1.0 goal after it.
- `scripts/pre-push.sh` asks for a gate stamp for commits sent to `main` and
  for the commit a `v*` tag names, and for nothing else: a branch push needs
  none. A `main` the remote does not hold yet counts every commit. The hook
  has a negative control, `make pre-push-probe`, in `make quality`.

### Fixed

- The enforcement receiver removes a socket left at its path only when a
  connection to it is refused. A timeout, a full backlog on Linux or a
  permission error refuses the start with `ErrSocketInUse` and leaves the
  socket of a receiver that may still be live. On macOS a live receiver
  whose backlog is full refuses connections too, so a second plane started
  then can still take its path.
- `supervise` reports `DEADLINE_EXCEEDED` not checked when an event of the
  run has no time and the timed events stay within `deadline_seconds`; it
  was reported checked on a span that may have been longer. A breach on the
  timed events still fires; under a 0.2 procedure the rule is then checked
  for the tree, and a run whose events have no time gets no finding.
- `react` reads the clock for each stop it writes. A pass that ran longer
  than a rule's lifetime wrote a stop that had already expired, counted the
  finding as stopped, and never stopped the run for it again.
- `examples/evidence-report -state` holds a finding or a policy reload linked
  after a request's end to the request's enforcement mode, as the one-shot
  report does: an undeclared or other mode is `lifecycle_unknown`. Its
  `state.json` is now `1.1` and keeps each ended request's mode; a `1.0`
  state is still read, and an annotation after the end of a request it holds
  is unknown, since its mode was not kept.
- The gateway's configuration reader keeps a double-quoted value whole when
  it holds an escaped quote: `"a\" #b"` was cut at the `#` as a comment and
  the file refused.

## [0.11.0] - 2026-10-12

A tool outside MCP can now ask for a decision before it acts and report how
the call ended, through the `experimental` enforcement API (ADR-0051). The
same policy, approvals and trail apply as to an MCP call. A reference client and
conformance cases that a client in another language can run come with it.
`REPEATED_DENIAL` is version 2, which needs a signed route upgrade (see
Changed). Fixes from a code audit bound several waits and refuse records
another account could rewrite. From this release a version is a plain
`X.Y.Z` without the `-alpha` suffix
([ADR-0025](docs/adr/0025-public-repository-merges-and-releases.md)); the
project is still alpha, and the `0.x` series still makes no compatibility
promise between minor versions.

### Added

- The enforcement API contract, `guardana.control.enforce.v1alpha1`: the
  `admit`, `complete` and `abort` messages a tool outside MCP exchanges with
  the plane as JSON over HTTP on a Unix socket (ADR-0051). Unstable and
  outside the v1 promise; `buf breaking` does not compare it.
- `guardana-gateway run` serves it under `listener.kind: enforce_api`, with
  `listener.socket`, `listener.execution_lifetime` (1s to 1h, no default),
  `listener.max_body_bytes` (1 KiB to 256 KiB, default 128 KiB),
  `listener.max_open_per_run` (default 16, below `approvals.max_open`) and a
  `tools` table that classifies each tool by name. Such a plane needs
  `runs.dir` and refuses upstreams, overrides and the keys only an MCP
  listener reads; an MCP listener refuses the new keys. A sweep abandons
  expired handles. A stop abandons every open execution before the spool
  drains. `/healthz` reports the adapter's counts under `enforce`, and
  `doctor` checks an enforcement API plane.
  [A guide](docs/guides/decide-a-tool-of-your-own.md) shows a tool of your
  own decided through it.
- `adapters/enforce`, its adapter, builds a tool's envelope from the run
  token and the operator's tool table. A handle is single use and expires.
  The adapter refuses a duplicate request key, closes an expired execution as
  abandoned and limits a run's open executions. It blocks a rewrite that
  moves the decided resource, and answers `RECORDED` only once the closing
  record is written. It declares cooperative enforcement and reads a
  resource and a run token the way the MCP adapter does
  (`internal/adapterkit`).
- `internal/enforceclient`, the reference client, runs a tool only with the
  bytes an `EXECUTE` answer authorized. It aborts on an obligation it does
  not know, completes `UNKNOWN` when the tool cannot tell how the call ended,
  and never sends a request twice. `testdata/enforce/` holds the client and the receiver
  conformance cases, each with a negative control.
- The coverage inventory kind `enforce_tool`: a tool an enforcement API plane
  classifies is "decided, not enforced" in every mode, since a cooperating
  client, not the plane, keeps it from its effect.
- The pipeline can close an execution nobody completed or aborted as failed,
  with result unknown and the new reason code `EXECUTION_ABANDONED`. It never
  closes one as a success and does not halt the plane for it. A byte mismatch
  a client reports through a cooperating adapter blocks only that run's
  material calls until `flow.max_runs` runs are halted; past that, and
  through an inline adapter, a mismatch halts the plane's material calls.
  Metrics count them:
  `pipeline_runs_halted`, `pipeline_abandoned_total`,
  `pipeline_sink_failures_abandoned_total`, `pipeline_halted_mismatch` and
  `pipeline_halted_sink`.
- [Control and supervision](docs/concepts/control-and-supervision.md)
  explains the 1.0 goal and what the alpha does today: observation across
  connected channels, procedure checks and reactions within scoped authority.
  It keeps the AuthZEN, enforcement and operator API roles apart.
  Backlog task B28 plans continuous supervision.
- Planned requirements (B23–B27, proposed ADR-0050): previewing MCP setup,
  qualifying coding-agent hooks, reviewing tool-definition changes,
  simulating candidate policies and reviewing findings with an incident
  export. None is built.

### Changed

- On an `enforce_api` plane `/metrics` writes the enforcement API adapter's
  counts (`enforce_*`) and the flag `listener_enforce_api`, and leaves out the
  MCP adapter's `adapter_*` metrics. `doctor` checks the socket's directory as
  `run` does, and judges pause entries against the tool table.
- `approvals.max_held_per_run` (default 16, only with `runs.dir`, below
  `approvals.max_held`) bounds one run's held requests; an expired hold no
  longer counts against its run. A configuration with `runs.dir` and an
  `approvals.max_held` of 16 or less no longer loads until
  `approvals.max_held_per_run` is set below it. A tool's `provider` and `resource_type` are
  bounded at 1024 bytes. Under `policy.fail_open_read` an `enforce_tool` line
  says a read runs undecided while the policy is unavailable.
- The configuration loader refuses a tool name over 1024 bytes, a
  `resource_from` the adapters refuse, and a socket path over 103 bytes.
- `examples/evidence-report` reports a timeout or unknown outcome as
  `uncertain`, not `failed`, exits 1 on it, and raises `effect_uncertain`.
- `REPEATED_DENIAL` is version 2. When some denials it would cite are in doubt
  (a broken chain or an event id read with two contents), it cites only the
  clean ones and stays `CONFIRMED` if at least `max_denials` are clean;
  otherwise nothing changes. Its finding ids change with the version.
  `route sign`, `react`, the `stops` writers and a plane refuse a route naming
  `rule_version` `"1"`. To upgrade, set it to `"2"`, raise the route's `serial`
  and sign it, run `stops init --route <new> --public-key <file> --carry <old
  dir> --carry-route <old route> <new dir>`, point `reaction.route`,
  `reaction.stops` and `react` at the new route and list, and restart the
  plane. The carry keeps every unlifted stop, at version 1. A lifted run whose
  denials still meet the rule is stopped again by its version 2 finding, which
  has another id, and is lifted again. Only `--carry-route` reads the old
  version.
- The adapter capability `Block` is now `Enforcement`: none, cooperative or
  inline. `ENFORCE`, `APPROVE` and `LOCKDOWN` need at least a cooperating
  adapter, and the MCP adapter is inline; `doctor` and the modes table name
  cooperative and inline enforcement apart.
- Two approvals from the security maintainers now cover every file ADR-0008
  says the gate is built from (all of `scripts/` and `.github/`, the
  `Makefile`, the linter and buf configurations, `go.mod` and `go.sum`) and
  the gateway's wiring of its decision point, adapter, approvals and stop. A
  test holds the declaration to the record's list.
- README and the home page show exact-action approval, changed tool definitions
  and a denied refund retried through another tool, with their coverage limits
  and links to the policies and runnable example.
- README, the home page and the social card lead with observing agents and
  controlling how they act. The 1.0 goal is marked `planned` beside what the
  alpha does, and the declared repository description says the same.

### Fixed

- `scripts/github-settings-check.sh` and the bootstrap, run by macOS's bash
  3.2 on a loaded machine, could build a declared ruleset as nothing and
  report it unknown: bash 3.2 fails a builtin's write to a pipe that a child's
  exit interrupts ("printf: write error: Interrupted system call"). The
  declarations are now printed through `cat`, which nothing interrupts.
- `/healthz` could show the spool drained while the exporter's
  `acknowledged` count did not yet include what it had released, since it
  read the exporter first and the exporter counted a release after making it.
  On a loaded machine `guardana-gateway scenario run` then failed a foreign
  trail file with the wrong reason. The spool is now read first, and a release
  is counted under the lock the exporter's counters are read under.
- `guardana-control notify` could count a delivered alert as failed with
  "killing the program's process group: operation not permitted". On a loaded
  macOS host the kernel can refuse the program's group with EPERM for a moment
  after its leader was reaped. It is now asked again for up to a second; a
  group still refused after that is reported as before.
- Opening a findings log, an observation log or a trail file cut a torn last
  line by the length read before the file was locked. When a second writer
  opened the same file, cut the tail and committed a write between the first
  one reading the length and taking the lock, the first then truncated that
  committed write. Open now reads the length and judges the file again once
  it holds the lock.
- The records, markers, state and lock files under an approvals, a runs and
  a hold journal directory were read when a group or the world could write
  them, and all but the hold journal's also when another account owned them.
  An account with write access to such a file could rewrite it in place,
  granting an approval, extending a run or washing a root clean. Each is now
  refused as a file that is not the directory's.
- A hold journal entry was read whatever schema version its approval carried.
  An approval of another major, or with none, now leaves the entry unreadable.
- Closing an approvals handle while a call ran on it was a data race on whether
  the handle was open.
- A pause, a stop or a halt that came while an opened run's root was being
  raised was missed, and the call was recorded as started anyway. The plane
  now checks them again after a raise that wrote, and a halt raised after
  admission also blocks a material call before a resume spends its approval
  and before it starts.
- One opened run can hold at most 16 requests for approval, so it cannot fill
  `approvals.max_held` for every other run; a hold past that is blocked
  `EVIDENCE_UNAVAILABLE`, like one past `approvals.max_held`.
- `/healthz` names only the plane's own halts: a mismatch that halted one run
  no longer sets `halt.executed_args_mismatch`, and `halt.evidence_unwritable`
  is set beside it when both stand.
- A client's abort whose record the sink refused counts as a lost closing
  record, so `run` exits 1, as a lost completion did.
- `make quality` runs every check even when make is told one is up to date
  (`-o`, `--old-file`, or either in `MAKEFLAGS` or `GNUMAKEFLAGS`), and refuses
  a `MAKE` or `GO` from the environment, any command-line variable but
  `GO=go`, `-e`, a `FUZZTIME` or `RANGE` from the environment, a makefile read
  beside the `Makefile`, and an `--eval` or `-E` string for any target; its
  second make starts with none of the first's flags, and CI clears make's
  flag variables before running it.
- The test report refuses a passing package in which a test started and never
  reported a result, as when the test ends the process with exit status 0. A
  test that writes its own pass before it exits still hides the tests after
  it; review catches that.
- The documentation checks read the commit's own file list in a gate-commit
  export instead of a walk that skips dot-directories.
- The release gate refuses a commit that is not main's head, and refuses
  unless main's newest CodeQL analysis is of the commit being released.
- `guardana-gateway` waited at start, with no listener bound, on an upstream
  that took the connection and never answered its initialization. The
  connect is now bounded by `upstream.list_timeout`, and the configuration
  reference says so.
- `runs open`, `runs close`, `runs list` and `supervise --runs` waited without
  a bound for another operator command's lock while opening the directory;
  their ten-second bound now covers the open too.
- `supervise` read a request whose events name two runs as one run's request.
  Such a request is now in doubt and confirms nothing.
- A floor store that stopped answering kept one call per policy poll waiting
  in the background; calls to it now take turns, so at most one waits.
- A raise of a policy floor could wait out its deadline while reads of the
  same floor directory in the same process ran back to back, since each read
  took the lock again before the raise next tried. Reads that start while a
  raise of the process waits now go after it; across processes the lock
  still favours no one.

## [0.10.2-alpha] - 2026-10-10

Fixes and release tooling from an outside audit of 0.10.0-alpha, with no new
feature: `react` no longer times a whole pass by its lock wait, the release
scans every binary it ships before attesting it, the website names the
published release rather than the next one, the repository's GitHub settings
have a read-only check, and a pause file replaced during a read is read
again. 0.10.1-alpha was tagged with most of these changes and never
published: its release job stopped at the new image scan.

### Added

- The release scans every binary it ships before anything is attested or
  published: each binary of every archive and the image's binary for
  linux/amd64 and linux/arm64, with `govulncheck` in binary mode
  (`scripts/scan-binaries.sh`). A known vulnerability, or a scan that could
  not run, stops the release; the dry run scans its archives and image too.
- An issue template for a report from trying it with your own MCP client and
  server.
- [docs/reference/versions.md](docs/reference/versions.md) lists every format
  a user writes or reads with the version this release writes, the versions it
  reads and its stability, held to the code's constants by a test. The wire
  contract's `1.0` is the one stable format; the product is still 0.x.

### Changed

- The website names the published release, which `docs/docs.json` sets once a
  release is out, rather than the newest dated section of this file, and each
  page's footer links that release's documentation at its tag
  ([ADR-0049](docs/adr/0049-the-site-names-the-published-release.md)). The site
  had named 0.10.0-alpha a day before it was published.
- The home page leads with what runs today, a gateway that decides MCP tool
  calls, states what it does not cover, and says what each planned task
  brings. It no longer says the product watches by default: the enforcement
  mode has no default
  ([ADR-0032](docs/adr/0032-the-enforcement-mode-has-no-default.md)).
- The repository's GitHub settings are declared once, in
  `scripts/lib/github-settings.sh`: `scripts/github-bootstrap.sh` applies them,
  and `scripts/github-settings-check.sh` compares them with GitHub without
  writing (rulesets, required checks, bypasses, who holds maintain or admin,
  labels and milestones), exiting 1 on drift and 2 when something could not be
  read. Two approvals and code-owner review now also cover `adapters/authzen/`
  and `adapters/mcp/`; the paths are spread over rulesets of at most 15
  patterns each, GitHub's limit per reviewer, which the bootstrap checks
  before it writes anything. Milestones follow the roadmap, and labels use
  GitHub's `good first issue` and `help wanted`.
- CI's quality job may run 45 minutes; its fuzz smoke alone took 14 of the 30
  it had.

### Fixed

- A plane reading the pause file while a writer replaced it, as
  `guardana-control pause add` and `remove` and most editors do, turned the
  pause state unknown for a poll interval and blocked every call meanwhile. A
  read that finds the file replaced between judging its name and opening it
  now starts again, up to three times in all, with every check each time; a
  link swapped in is still refused and a file replaced at every attempt is
  still unknown.
- The release job's image scan pulled every platform of the image by the
  index's digest, which Docker's default image store refuses for a second
  platform ("cannot overwrite digest"), so 0.10.1-alpha's release stopped
  before it attested or published anything. Each platform is now pulled by
  its own manifest's digest.
- `react` gave its whole pass the ten seconds meant for waiting on another
  writer's lock, so a pass over a list near its bound, judged again before
  each line, could end with `context deadline exceeded` while no other writer
  ran. Each line now waits up to ten seconds for the lock and nothing else is
  timed. A wait that runs out, or an interrupt, now ends the pass after the
  lines already written; `react` prints them and its count line, then exits 1.
  Once the list refuses a line for its bounds, `react` names every later
  finding as not written without taking the lock again, so a long pass over
  a full list no longer shuts out `stops lift`.

## [0.10.1-alpha] - 2026-10-09

Tagged and never published: the release job stopped at its new image scan
before it attested or published anything. Its changes are listed under
0.10.2-alpha.

## [0.10.0-alpha] - 2026-10-08

One supervised run is now whole. A procedure of schema `0.2` names the
resources its steps bind, the exceptions it allows and how a run's children
are judged; `supervise` reports a resource outside the run, a denied action
retried in another form and an exception taken, judges a run's tree, and
draws one run as a static page. A finding is confirmed only on the named
run's own calls, so no run can get another one stopped, and a child run can
now be stopped on its own. `procedure lint` and `procedure test` check a
procedure with cases, and `findings export` reads the findings log with a
cursor. The fixes come from an audit of this release's own changes.

### Security

- Built with Go 1.27.2, which fixes GO-2026-6599, GO-2026-6600, GO-2026-6603,
  GO-2026-6604, GO-2026-6605, GO-2026-6607, GO-2026-6608 and GO-2026-6610 in
  `crypto/tls`, `net/http` and its HTTP/2 code, `html/template`,
  `mime/multipart` and `os`; `govulncheck` found the plane's calls reaching
  the HTTP/2 ones under 1.27.1.

### Added

- Procedure schema `0.2`, read beside `0.1`
  ([ADR-0047](docs/adr/0047-a-procedure-states-its-exceptions-resources-and-children.md)).
  `bindings` name the resource type each binding holds and `binds` ties a
  step or an allowed tool to one; `exceptions` waive one rule for one step or
  tool, on a granted approval, a failed step or a reason code; `children` is
  `inherit`, which judges a root run and its whole tree, or `separate`, which
  judges one run's own calls and lists its children. A rule that may stop a
  run is waived only on an approval. A `0.1` document reads as before, with
  the same digest and the same confirmed findings.
- Under a `0.2` procedure `supervise` reports `RESOURCE_OUTSIDE_RUN` when one
  binding's calls carry more than one resource, and
  `DENIED_ACTION_RETRIED_ARGUMENTS`, `_RESOURCE` and `_AROUND` when a policy
  denial is followed by the same tool with other arguments, another tool or
  upstream on the same resource (not a read after a denied non-read), or a source's report of the denied tool that no plane
  call joins. An exception taken raises `EXCEPTION_TAKEN`, never stronger than
  the finding it waived. A finding names the run whose call it rests on, a
  child included, and the report lists the run tree.
- A child run can be stopped. `react` writes a stop for a confirmed finding
  about an open child of the finding's tenant, and a plane refuses that
  child's next call while its parent and siblings run on.
- `guardana-control findings export` writes the findings log with a cursor,
  in the format `guardana.control.findings-export` `0.1`, up to the last
  write a report closed
  ([ADR-0048](docs/adr/0048-one-run-drawn-as-a-page-and-findings-exported-with-a-cursor.md)).
  A log this release creates starts with a header holding a random `log_id`,
  which its cursors bind to; an older log is known by its first line.
- `guardana-control procedure lint` prints a procedure's id, version, digest,
  children mode and each rule with its version and whether it may stop a run;
  `procedure test` runs a document of cases against it and passes a case only
  on an exact match ([guide](docs/guides/test-a-procedure.md)).
- `supervise --view <file>` draws the run as one static HTML page: the
  expected steps beside the calls observed, each marked enforced, decided not
  enforced, observed, exception or approval, blocked or not seen, by shape and
  line as well as colour. It shows each finding's calls and their neighbours,
  or with `--view-all` every call up to a bound
  ([run view](docs/reference/run-view.md)).

### Changed

- Every reader of a route (`route sign`, `react`, a plane at start, `doctor` and
  the `stops` commands) refuses one that names a rule or a rule version outside
  the six whose finding may stop a run: `REPEATED_DENIAL`,
  `STEP_OUTSIDE_PROCEDURE`, `DEADLINE_EXCEEDED`, `RESOURCE_OUTSIDE_RUN`,
  `DENIED_ACTION_RETRIED_ARGUMENTS` and `DENIED_ACTION_RETRIED_RESOURCE`, each
  at version `1`. Only `route sign` checked a route's rules before, so a route
  signed by other means could name any rule.
- A finding record that carries a run on its event references, a count of
  references left out, a children mode or a run tree is schema `0.2`, and a
  0.9 reader refuses it by name. Read a findings log this release writes with
  this release's `notify` and `react`.
- `supervise` reads from the runs directory only the run's own tree, so a
  directory holding more than 1000 runs no longer refuses a supervision.
- `supervise` counts a source as heard only from import reports of its
  descriptor's tenant and project, as `coverage` does, and bounds each span
  walk on its own as well as in total. Either can move a finding below
  `CONFIRMED`; a changed verdict is a new record, and so a second alert.
- `STEP_OUT_OF_ORDER` and `CONTINUED_AFTER_FAILURE` are version `2`. Two
  proposals of one instant are now untold even within one export, since a
  plane ships several batches at a time, so a finding that rested on their
  place in the export is indeterminate. The rule version is part of a
  finding's id, so supervising a run again writes their findings as new
  records and alerts again. Neither may stop a run; the six that may stay at
  version `1`, so a route signed before still holds.

### Fixed

- A finding that rests on many events, such as ten thousand denials, was past
  the log's line bound and refused the whole write. It now cites ten
  references, the most doubtful first, and counts the rest; its verdict is
  still weighed over all of them.
- Under a `0.2` procedure judging a run's tree, one run's calls could confirm
  a finding against another: a child's denial made the root's later call a
  confirmed retry, a child's probe of another order confirmed
  `RESOURCE_OUTSIDE_RUN` on the root, and a closed child took the tree's
  `REPEATED_DENIAL` and deadline. A finding is now confirmed only on the named
  run's own calls (a retry by a descendant of the denied run included); one
  that needs another run's call is suspected at most and stops nothing. Each
  run's deadline is still timed from the tree's first event, which may be
  another run's.
- The retry rules turned themselves off past about a thousand denials; they
  now judge every denial. A tree is bounded at 400 runs, where its report
  still fits the log's line.
- `DENIED_ACTION_RETRIED_AROUND` read as checked with a source never heard,
  silent or not read, and so did `STEP_OUTSIDE_PROCEDURE` when a span walk ran
  out of steps; both read not checked now, and `procedure test` compares the
  sources a case expects to be unheard.
- A rule that is never confirmed could be recorded as confirmed; it is capped.

## [0.9.0-alpha] - 2026-10-07

A confirmed finding can now stop the run it is about. An operator signs a
route that says which findings may stop a run and which key lifts a stop,
and starts a stop list; after `guardana-control supervise`,
`guardana-control react` writes a stop for each deterministic, confirmed
finding the route allows about an opened run that is still open. A plane
configured with the route refuses that run's later calls, and no other
run's, and blocks every call while it cannot read or trust the list. A call
already running is not cut, and only a lift signed with the route's lift key
ends a stop while a plane runs. The refund example shows it on a live plane
with two runs. The other changes and fixes come from an audit of 0.8.0, and
four of them matter on upgrade. The gateway refuses a configuration file
when it, or a directory or link on its path, belongs to an account other
than its own or root, when another account or its group may write it, or
when it has a second name: a checkout under a umask of 002 needs
`chmod g-w`, and a container's configuration has to be owned by the image's
user. An upstream that asks for more input ends the call as failed. A second
override of one tool is refused at start. `runs open --parent` refuses a
child whose expiry would pass its parent's.

### Added

- A confirmed finding can stop the run it is about
  ([ADR-0046](docs/adr/0046-a-finding-stops-one-run-through-a-signed-route.md)).
  An operator signs a route with `guardana-control route sign`, naming the
  procedures and rules whose findings may stop a run and the key that lifts a
  stop, and starts a stop list with `stops init`. `guardana-control react`
  appends a stop for each deterministic, confirmed finding the route allows,
  about an opened run that is open, and never lifts one; `stops lift`, signed
  with the lift key, ends a run's stops, and `stops list` shows them. A plane
  configured with the `reaction` keys checks the route against its own floor
  at start and reads the list every poll interval: a stopped run's later calls
  are refused `RUN_STOPPED` (45) and no other run's, and every call is blocked
  `STOP_STATE_UNAVAILABLE` (46) while the list cannot be read, shrinks, is
  rewritten or does not verify. A call already running is not cut, and a
  stopped run's children are not stopped. `doctor`, `/healthz` and `/metrics`
  report the route and the list; `examples/refund-supervision/` stops one of
  two runs on a live plane and lifts the stop.

### Changed

- The policy key and the freshness key, in the configuration and in
  `guardana-control policy renew`, are compared as points up to their sign:
  one private key signs for a point and its negation, so two keys that
  differ only there were taken as two authorities.
- An upstream that answers a call, a read or a prompt with `input_required`, or
  with input requests of any kind, ends that call as failed, with a fixed
  answer the gateway does not relay. The
  library had sent the same call to the upstream again on its own, up to ten
  times, for the one call the plane decided and recorded.
- A second override of the same tool on one upstream is refused at start. The
  last one won, so an `effect: READ` after an `effect: DELETE` classified a
  delete as a read.
- `guardana-control runs open --parent` refuses a child whose expiry would
  pass its parent's.
- The MCP adapter refuses an obligation that carries a parameter its type does
  not read, as the gateway already did; a non-advisory one stops the call. The
  obligations page lists the parameters each type reads.
- The gateway refuses a configuration file when the file, or any directory or
  link on its path, is owned by an account other than its own or root, or
  another account may write it (a sticky directory, or root's on a read-only
  mount, excepted), and a file with a second name. Its group may not write it
  either: a checkout under a umask of 002 needs `chmod g-w`. The file names
  the policy keys, the pause file and the credentials the plane sends, and was
  read whatever its owner and mode. A container's configuration now has to be
  owned by the image's user.
- Each agent connection gets a 64 KiB send buffer, so on Linux, as on macOS,
  the answer bound measures a slow client's progress in steps of that size.
  Linux grows a connection's buffer to megabytes, which cut off a client
  reading steadily but slowly.

### Fixed

- A plane whose policy floor is read back below the statement it confirmed,
  a copy restored from before its raise, counts the poll as refused under
  `floor` and logs it; it went unremarked.
- `guardana-control coverage` counts a span that claims two parents once, so
  a few dozen observations whose spans form a ladder of diamonds no longer cut
  a walk as past 65,536 spans. Counting such spans is bounded per source, and
  a count past that bound cuts the walk.
- The evidence-report example stops reading an endless line at the export's
  byte bound, and refuses a header without a well-formed source and a cursor
  that is not one of its file; the demo's `call.sh` exits 1 on an HTTP status
  that is not 2xx. The benchmarks page's argument sizes are what the
  benchmarks measure now, held by a test.
- A release refuses a commit while main has an open CodeQL alert of severity
  high or critical, and its verification requires a bill of materials for each
  archive, not one for all. The gate refuses lint ignore comments in the
  protocol files, compares the installed tools with their pins, and holds the
  CI job that runs it, the secret scan's configuration and the code owners of
  every guarded tree to what they must be.
- An agent that cancels a call no longer leaves its trail without a closing
  record, a held request open for the plane's life, or a sink failure counted
  for a sink that did not fail: once proposed, a call's records, its hold and
  its consume finish whatever the agent does.
- A call whose opened run the plane cannot read or name is blocked before the
  external decision point is asked about it.
- An approval or a rejection the store returns that does not check out (another
  major, another request time, no decision time or one outside the request's
  window, another id, a state that is not an answer) is recorded as the plane's
  own expired approval, never as decided. An agent that
  cancels before its approval is consumed spends nothing.
- `guardana-control observe export` judges the log as the reader does: a link,
  a file another account owns, one the group or others may reach, or one with
  a second name is refused; it was exported.
- An observation import refuses a write that would take the log past its
  1 GiB bound, which the reader then refused.
- Coverage counts a source's records only in the tenant and project its
  descriptor names; bounds each walk of a trace's spans on its own, walking a
  long chain once, and a walk cut at its bound reads not checked and exits 1,
  since an agent can cut one on purpose; and prints a join as not checked where the plane's
  record of that call does not validate, rather than as joined or as a call
  around the plane.
- Supervision tells no order between two steps whose proposals, in two
  planes' exports, carry the same time; the order of the `--evidence` flags
  decided it.
- `doctor` judges the approvals and hold journal directories for owner and
  mode as `run` does; it reported ok for a directory `run` refuses. It also
  names the bytes of a torn evidence tail it cut, and a floor directory that
  would not close is no longer ok.
- A scenario step whose arguments canon cannot hash compares the recorded
  proposal's hash with none, where it printed "not compared" and passed.
- The runs directory's reader refuses a string that is not valid Unicode. It
  read an unpaired surrogate or a bad byte as U+FFFD, so two different files
  could read as one record.
- A plane whose bundle and statement do not change judges its serial floor at
  every poll as a raise would, and counts a floor it cannot read, one holding a
  newer serial or another digest at its serial, and a clock behind it, as a
  refused poll; it read the floor only when a file changed.
- With an authenticator that names no user, the forwarded resource, template
  and prompt lists are refused as the tool list is.
- An approval whose own schema version is not of major 1 is refused when it is
  held, answered or read, and an answer dated after the moment it would be
  spent, or with no date, is not yet an answer.
- The hold journal, and the markers of the approvals and journal directories,
  refuse a member named twice, in another case or unknown, and the journal an
  expiry spelled otherwise than the plane writes it.
- The start's sweep of expired approval records says it is unmeasured when the
  directory holds more records than `approvals.max_records`; it gave a count
  as if it had read them all.
- The approvals page refuses an answer to an id an incomplete listing left out
  as unknown, where it said there was no such approval.

## [0.8.0-alpha] - 2026-10-06

One agent run can now be checked against the procedure it was meant to
follow. `guardana-control supervise` reads a plane's evidence export for a run
an operator opened, and the observations the agent's runtime reported for that
run, and writes findings that cite both. `guardana-control notify` hands each
alert to a program the operator names, and marks it delivered only once the
program accepts it, so a crash or a failure makes the next run hand it over
again. `guardana-control coverage` gives each path an operator declares one
state: enforced by a plane, decided but not enforced, observed by a source,
unknown, or not covered; where a source observed a call that no plane's export
records, it says so. None of these commands contacts a plane or changes a
decision, and a finding that rests on what the runtime reported is marked
suspected, not confirmed. An upstream answer that quotes a credential the plane
sends is replaced by a fixed answer from the plane, so the agent does not
receive the credential. On upgrade, two changes: a call that needs an approval
under a run an operator opened is held for the approval, where before it was
blocked; and a call refused as too large records the digest of its over-long
name or resource. Fixes from an audit of this release include: coverage took a
prompt or a resource read through the plane for the plane's record of an
observed tool call, and supervision let the runtime's own report of a step
count as the step. [docs/status.md](docs/status.md) says what is
`implemented` and what is `experimental`. Nothing here is a security boundary
yet.

### Added

- `guardana-control coverage` prints, for each path an operator declares in an
  inventory, whether a plane enforces it, decides it without enforcing it, a
  live source observed it, nobody can tell, or nothing covers it, and a
  standing row for the paths nobody declared
  ([ADR-0041](docs/adr/0041-coverage-per-declared-path.md),
  [ADR-0044](docs/adr/0044-coverage-judges-each-plane-and-joins-only-a-whole-export.md)).
  It reads the planes' configurations, source descriptors, observation logs
  and evidence exports, and contacts no plane. Against a whole evidence export
  it shows an observed call no plane recorded as a call around the plane, and
  exits 1 for it.
- `guardana-control supervise` checks one run an operator opened against a
  versioned procedure, from the plane's evidence export and the observations
  that claim the run, and appends findings with typed references to a
  findings log; `guardana-control notify` hands each alert to a program of the
  operator's, at least once, keyed on the finding's id
  ([ADR-0045](docs/adr/0045-one-run-is-supervised-against-its-procedure.md)).
  Six rules: repeated denial, a step outside the procedure, a deadline, a
  skipped required step, a step out of order, and a run that carried on after
  a failure. A finding resting on what the agent's runtime reported is
  suspected at most, and a skipped step is never confirmed. No plane reads a
  finding, and no finding stops a run. `examples/refund-supervision/` runs it
  on a live plane.

### Changed

- An upstream's answer, wire error, listed item or tool definition that quotes
  a credential the plane sends reaches the agent as a fixed answer, never with
  the upstream's text
  ([ADR-0042](docs/adr/0042-an-answer-that-quotes-a-configured-credential-is-withheld.md)).
  The plane looks for the credentials in its endpoints, headers and proxies,
  and, from 8 bytes, for query values and the variables a command upstream
  receives: as written, percent-encoded, JSON-escaped and in base64. A
  withheld `tools/call` success says the call ran; a read, a prompt or a list
  answers `-31103`; a tool whose definition quotes one is never listed. The
  closing record keeps the upstream's outcome and hash, with `withheld:` before
  its protocol status. `doctor` names the values too short to scan, and
  `/metrics` counts withheld answers.

### Fixed

- A call that needs an approval, under a run an operator opened, was blocked
  with `EVIDENCE_UNAVAILABLE` on a live plane instead of held: the run's expiry
  was judged at the call's first clock reading, which the kernel's later
  reading had already passed. A test clock that never moves had hidden it.
- An upstream could put the gateway's `_meta` namespace inside a content
  block, an embedded resource or a prompt message, where it reached the agent;
  it is now stripped from every `_meta` an upstream's result carries.
- A `tools/list` right after a manifest refresh could be answered with the
  list cached from the previous manifest.
- A call refused as too large records `overlong:sha256:` and the digest of its
  over-long action name or resource id in their place, so the recorded
  proposal validates
  ([ADR-0043](docs/adr/0043-a-refused-over-long-name-is-recorded-by-its-digest.md));
  both were left empty, which a validating reader refused.

## [0.7.0-alpha] - 2026-10-05

An agent runtime's OpenTelemetry GenAI traces can now be imported as
observations. `guardana-control observe import` keeps what each span reports
was done, by which source, when and how it ended, in an observation log;
`observe export` writes that log in the evidence export's shape. The record,
`guardana.control.observe.v1alpha1`, is outside any compatibility promise; it
keeps no prompt, output, argument or result, and the plane never reads it. A
call that carries W3C trace context records its trace and span ids, so its
evidence trail can be joined to the runtime's traces. On upgrade: a
configuration with a negative duration no longer loads, and `run` now exits 1
when it stopped uncleanly. An audit of the whole tree before the release
fixed defects, among them: an upstream's failure reached the agent and the
log with its endpoint, and any credential in it; a stop closed the evidence
under a call whose agent had dropped its connection, and exited 0; an HTTP
upstream's answer was read whole, whatever its size; a rewriting obligation
could send a call on a resource no decision covered; the approvals store
accepted another account's directory; and the commit gate could stamp a
commit that broke the wire contract. [docs/status.md](docs/status.md) says
what is `implemented` and what is `experimental`. Nothing here is a security
boundary yet.

### Added

- Observations: `guardana-control observe import` reads an agent runtime's
  OpenTelemetry GenAI spans (OTLP/JSON, conventions 1.41.0) for one source an
  operator describes, keeps what each span reports was done, by which source,
  when and how it ended, and appends
  it to an observation log; `observe export` writes the log in the evidence
  export's shape. The record is `guardana.control.observe.v1alpha1`, version
  `0.1`, outside any compatibility promise. No prompt, output, tool argument
  or result is kept, and reasoning is counted and dropped. An observation is
  testimony: the plane never reads one.
- A call to the MCP gateway that carries W3C trace context in
  `_meta.traceparent` records the trace id and the caller's span id in its
  envelope's `trace_id` and `span_id`, so a trail can be joined to the agent
  runtime's traces. A missing or malformed value leaves both empty and changes
  nothing else.

### Changed

- The plan follows [ADR-0039](docs/adr/0039-many-channels-into-one-core.md):
  MCP is one channel of several. The next milestone is one task under
  supervision across two channels, the plane and an agent runtime's
  OpenTelemetry traces, with a coverage map, findings, a local notifier and a
  stop of one run, before any public SDK. Extensions are planned as separate
  programs speaking versioned data contracts. The README and the website
  describe this plan, marked `planned` wherever nothing is built yet.
- The website's home page draws its three diagrams as cards and arrows in
  text, readable on a phone, instead of animated scenes and flowcharts.
- The website's header stays on one row on a phone and shows the newest
  release, which `make docs-gen` takes from this file. Documentation pages get
  a menu above the content on narrow screens, and a wide table scrolls inside
  itself instead of breaking words.

### Fixed

- A stateful listener near its `listener.max_sessions` cap no longer refuses
  an open while the previous open's answer is still being written: a session
  whose answer has begun is counted once, not twice.
- The gateway's configuration refuses a negative value for every duration
  key and names that key in the error. `approvals.ttl`,
  `approvals.retry_after`, `export.linger`, `export.backoff`,
  `export.max_backoff` and `list.ttl` accepted a negative value before, and a
  negative `policy.max_stale` was refused under another key's name.
- `policy renew` holds the signer floor directory's lock from the raise of
  the floor until its statement is written, so two renews of one bundle can
  no longer leave the older statement in `--out` while the floor holds the
  newer. Renews under different floor directories are not ordered. Waiting
  for the lock, opening included, ends after 10 seconds.
- An evidence line that does not decode is refused naming where it went wrong,
  never quoting the value or member name it held, so a sender cannot put a
  credential into the collector's log through a malformed line.
- `guardana-gateway doctor` names a command upstream's program and how many
  arguments it takes, never the arguments, which can carry a credential.
- The approvals store refuses a directory another account owns, as every
  other store already did, and a record that repeats a member. A record, a
  hold journal entry or a file whose filing failed after it was linked is
  unlinked again. An answer the plane spent before the failed filing is
  reported as filed. One already gone when it is unlinked is reported as of
  unknown outcome, never as not filed, and `approvals approve` and `reject`
  then say to list before answering again.
- The evidence spool refuses a segment or its quarantine that another account
  owns or the group or others may write, keeps every quarantined id so a crash
  cannot quarantine a record twice, syncs a repair before it continues, and
  refuses an append once its sequence is spent. The trail file's recovery cuts
  only a tail its writer could have left, and an export reads the line that
  would cross its byte bound no further than the bound.
- The `evidence-report` example refuses an export past 100 000 records and
  its trailer or 64 MiB after its header, and a trailer without
  `scanned_bytes` or with a `dedup_scope` other than `export`. The demo's
  servers do not start on a journal that is a link, a pipe, a file with a
  second name, or a file another account owns or may read or write.
- The MCP gateway answers an upstream failure that is not the upstream's own
  wire error, on a call, a read, a prompt or a forwarded list, with `-32603`
  `the upstream did not answer`, and logs a refresh failure by what failed:
  neither the agent nor the log sees the endpoint, which can carry a
  credential. A transport failure is printed and logged by its operation and
  a cause its error's type gives, never by its text, which can quote what the
  upstream echoed of the request, the Authorization header included; the OTLP
  exporter's log does the same for the collector. Run and doctor also
  withhold a refusal that quotes an endpoint's userinfo, raw, decoded or as
  the Basic credentials sent, its query or its fragment. An HTTP upstream's
  answer, other than an event stream, is read no further than 16 MiB, so an oversize answer fails the call instead of
  being held whole.
- A rewriting obligation that changes the member a tool's `resource_from`
  reads, or anything inside it when it is an object, a list or a boolean,
  aborts the call with `OBLIGATION_NOT_UNDERSTOOD` instead of sending
  it. A call nothing classifies is held to the rest of the envelope contract,
  and each name, client tag or resource id past the string bound is left
  off, so the proposal can still be recorded.
- A closing record the sink refused no longer forgets the held request, an
  OTLP request of many records is decoded in one pass, and a collector's
  answer of exactly 64 KiB is read as whole.
- `guardana-gateway run` and `dev` stop admitting calls when they stop and
  wait for every call admitted before, one whose agent dropped its
  connection included, on HTTP and stdio, and exit 1 when one was cut, a
  closing record was lost, even after the plane closed, or the plane did not
  close; `doctor` fails its `close` check, and a scenario whose
  plane did not stop cleanly could not run. The configuration, a scenario
  file and the trail it reads are read only as regular files, so a named pipe
  no longer holds them. A test case refuses `null` for a member that takes a
  string, a boolean or a list.

## [0.6.0-alpha] - 2026-10-03

A plane now takes its policy as current only on a signed freshness
statement, which `policy renew` writes, and keeps on disk the serial floor
that refuses an older bundle, so a restart cannot roll the policy back;
`/healthz`, `/metrics` and `doctor` say how fresh the policy is. An upgrade
needs five more configuration keys, a freshness key apart from the bundle's,
a floor directory that `policy state init` makes, and a statement renewed
within the budget: the first entry under Changed says how. A zero
`upstream.call_timeout` is now refused. `examples/evidence-report`, a Go
module of its own, follows the evidence export, reports what was decided and
why, and raises local alerts. An audit before the release fixed defects,
among them: a clock reading before 1970 let an expired delegation pass, and a
clock set back after a decision let an expired run or approval through; the
release gate counted a pull request run and could be passed by a tag named
`main`; the hold journal and the trail file accepted a directory or a file
another account owned; and a stateful listener kept any number of sessions
open. [docs/status.md](docs/status.md) says what is `implemented` and what is
`experimental`. Nothing here is a security boundary yet.

### Added

- `examples/evidence-report -state <dir>` follows a trail one export after
  another and raises local alerts: a JSON line each, appended to
  `<dir>/alerts.jsonl` and repeated on standard error, for a gap, a
  conflicting event, a lifecycle it cannot finish, an undetermined verdict, a
  block of the plane's own, an expired approval and its own bound. A repeated
  delivery, a crash and an outage neither lose nor repeat an alert, and it
  prints no field outside an allowlist
  ([guide](docs/guides/read-the-evidence-from-a-program.md)).
- `guardana-control policy renew` verifies a bundle under its public key,
  raises a signer's serial floor and writes a signed freshness statement for
  the bundle; it refuses a bundle below that floor
  ([ADR-0038](docs/adr/0038-a-signed-freshness-statement-and-a-serial-floor.md)).
- `guardana-control policy state init` makes a floor directory and a bundle
  id's floor, never replacing one, and `policy state reset` lowers a floor,
  recording the reason and the value it replaced.
- `/healthz` carries a `policy` object: `freshness`, one of `confirmed`,
  `unconfirmed` and `expired`, the confirmation and its expiry, the seconds
  left and what the plane's polls of its policy found. A plane whose policy is
  not confirmed answers `"status":"degraded"` with `200`; a halted plane still
  answers `halted` with `503`.
- `/metrics` carries `guardana_control_policy_freshness`,
  `guardana_control_policy_confirmation_seconds_left`,
  `guardana_control_policy_seconds_since_poll`, and counters of the
  policy's refusals by cause, bundles awaiting a statement, statements
  awaiting a bundle and withdrawals by a clock set back
  ([metrics](docs/reference/metrics.md)).
- `guardana-gateway doctor`'s `policy` line judges the floor, the bundle and
  the statement as a start would, without raising the floor, and fails for a
  statement missing, expired, dated ahead or naming another bundle, and for a
  bundle below its floor or at its serial with another digest.
- `listener.session_idle` sets how long a `stateful_http` session may sit idle
  before it ends, from one minute to a day; the default stays 30 minutes. A
  client that only listens on its GET stream is idle. Another listener kind
  refuses the key.
- `listener.max_sessions` caps a `stateful_http` listener's live sessions,
  from 1 to 16384, 1024 by default; an open past it is answered `503`, and a
  request whose body is still arriving holds no place. Another listener kind
  refuses the key. `/metrics` carries
  `guardana_control_adapter_sessions_live` and
  `guardana_control_adapter_sessions_refused_total`.
- `guardana-control policy explain` prints a `clock` line: `usable`, or why
  the clock stopped the decision.

### Changed

- **Breaking:** a plane's configuration needs five more keys:
  `policy.statement_file`, `policy.state_dir`, `policy.freshness_key_id`,
  `policy.freshness_public_key` and `policy.poll_interval`. A configuration
  without them is refused at start, naming the first key it lacks. The
  freshness key may not be the bundle's key; `state_dir` must be a directory
  `policy state init --kind plane` made; `poll_interval` is at least `1s` and
  shorter than `policy.max_stale`. No setting keeps the old behaviour. To
  migrate, run the first three commands where the keys live and the last on
  the plane's host, then set the five keys and keep renewing the statement
  within the budget ([run the gateway](docs/guides/run-the-gateway.md),
  [ADR-0038](docs/adr/0038-a-signed-freshness-statement-and-a-serial-floor.md)):

  ```
  guardana-control policy keygen --out freshness
  guardana-control policy state init --kind signer --bundle-id <id> signer-floors
  guardana-control policy renew --key freshness/signing.key --bundle <bundle> \
      --bundle-public-key <bundle key dir>/signing.pub --floor signer-floors --out <statement>
  guardana-control policy state init --kind plane --bundle-id <id> <state_dir>
  ```

- A plane's policy is confirmed only by a freshness statement bound to its
  bundle, never by installing the bundle again. The plane reads the bundle and
  the statement every `policy.poll_interval`, installs a newer bundle only with
  its statement, and refuses every bad replacement without moving the
  confirmation. Without a statement in its budget it decides every call
  `POLICY_STALE`, from the start or once the budget runs out, until a renewal
  arrives; a restart no longer resets the budget. A wall clock set back more
  than a second withdraws the confirmation until it is back and a statement
  issued after the withdrawal arrives.
- A plane's serial floor is kept on disk: a start onto a bundle below it, at
  its serial with another digest, or above it without a statement is refused,
  naming both serials.
- `/healthz` leaves out `bundle.confirmed_at` while no statement confirms the
  bundle.
- `dev` makes the plane's floor directory, writes the bundle's freshness
  statement under a second key held only in memory and renews it every third
  of the budget, sooner when the poll interval asks for it, so a session or a
  scenario past the budget stays fresh. It prints `statement`, `state_dir`,
  `freshness_key_id`, `freshness_key` and `renewal`, and no longer `stale_at`.
- `scenario run` refuses a plane whose policy is not confirmed.
- `POLICY_STALE`'s summary names an unconfirmed policy and a clock the plane
  cannot judge by too; its identifier and number are unchanged.
- `examples/evidence-report` prints a `block` column after `reasons`: the
  decision on the request's `ACTION_BLOCKED`, `=` when it is the kernel's, so a
  call the plane blocked itself, paused or unclassified, shows why. Every later
  column moves one to the right.
- `examples/evidence-report` is a Go module of its own, `example.com/evidence-report`,
  which reaches this repository's generated wire contract and nothing else of it;
  build it with `go -C examples/evidence-report build -o "$PWD/bin/" .`
  ([ADR-0037](docs/adr/0037-an-evidence-consumer-in-a-module-of-its-own.md)). Every
  Go target of the gate runs once per module.
- The release workflow refuses a tag whose commit is not main's head or an
  ancestor of it, or has no successful CI and Security run started by a push
  to `main` of exactly that commit: a pull request run never counts, a commit
  that is not on main never passes, a tag named `main` included, and a listing
  longer than one page is refused. Its dry
  run takes the version the tag will carry, makes the same check and prints
  that version's release notes.
- The configuration refuses a negative `upstream.call_timeout`,
  `upstream.list_timeout`, `pdp.timeout` or `export.timeout`, naming the key,
  and a zero `upstream.call_timeout`, `pdp.timeout` or `export.timeout`. A
  negative `upstream.call_timeout` left upstream calls without a bound and
  dropped an obligation's shorter timeout too; the other three were refused
  only later, at start, without the key. A configuration that set
  `upstream.call_timeout: 0` for no bound sets a positive one, `30s` by
  default. `upstream.list_timeout: 0` still means the adapter's own 30
  seconds, which `doctor` now prints.
- `guardana-gateway doctor`'s `policy` line and `run`'s first line say whether
  `policy.fail_open_read` lets a read run while the policy is unavailable.

### Fixed

- `runs list` and `runs close` no longer make an empty directory a runs
  directory; they refuse it, and only `runs open` makes one. A temporary file
  left by a crash while `runs open` made the directory no longer makes every
  later command and plane refuse it.
- The evidence spool now refuses a segment or its quarantine log that is a
  link, has a second name or was replaced since the spool listed or created
  it, for appends, reads and truncation alike. A named pipe at a segment's
  name is refused rather than waited on.
- The evidence spool reaches every file through the directory it checked and
  locked at start, so a directory renamed or replaced under `evidence.dir`
  receives no segment. Refusing a segment with a second name, it gives the
  device and inode, so `find -inum` finds the other name. A quarantine log
  whose directory entry could not be synced is synced by the next append to it.
- An upstream's JSON-RPC error to a `resources/read` or `prompts/get` keeps
  every number in its data exactly as sent when the plane strips a key under its
  namespace; an integer past 2^53 or a long decimal was rounded.
- An HTTP listener refuses a request whose body has not arrived within 30
  seconds and, for any request that carries a body, cuts the answer when
  64 KiB of it cannot reach the client within 30 seconds, so neither a client
  trickling its body nor one that stops reading holds a connection and a
  handler; a slow client that keeps reading gets the whole answer. A session's GET stream is not bounded.
- The plane's listener and health address close a kept-alive connection that
  sends no next request within two minutes.
- The plane strips a key under its namespace from an upstream's `_meta` and
  error data in any letter case, since a client may match keys to its own
  fields without regard to case.
- `guardana_control_policy_refresh_refused_total` counts a refusal the build
  cannot name under `cause="unknown"` and a bundle the plane's holder fails to
  load under `bundle_invalid`; both were counted under `floor`, which now means
  only a floor that could not be read or raised, a raise that timed out
  included.
- A freshness statement that expires while the plane reads it is refused
  under `statement_expired`, and nothing is raised or published; it was
  published already expired, raised the floor and counted as a confirmation.
- A shaped `tools/list` answer is cached under the policy bundle it was shaped
  under, so a list shaped under one bundle is no longer served once another
  is in force.
- The health listener bounds a whole request at 30 seconds, so a trickled
  body no longer holds a connection.
- An answer write that moves no bytes fails instead of being retried without
  end.
- The hold journal and the trail file refuse a directory or a file another
  account owns, and a platform that names no owner; the hold journal reaches
  its entries only through the directory it opened and refuses one swapped in
  at its name later. A plane no longer starts over a journal directory another
  account owns, and `collect --out` refuses a path that names no file, such as
  one ending in a separator.
- A clock reading before 1970, the zero time among them, after 9999, or
  earlier than the verified time, the latest `issuedAt` of a
  statement it confirmed or of its floor, no longer lets the kernel decide:
  the call is `INDETERMINATE` with `POLICY_STALE` and blocks on every effect
  class, fail-open reads included, and `/healthz` reports a confirmed policy
  `expired`. Such a reading let an expired delegation pass and could make a
  bundle confirmed at the zero time read as fresh. Before it hands out an
  approved or run-bound call, the plane treats as expired a reading outside
  1970 to 9999 or earlier than one the call already relied on or than the
  approval's `requested_at`, so a clock set back after the decision no longer
  runs an expired call, and a resume refused this way no longer spends its
  approval.

## [0.5.0-alpha] - 2026-10-02

An author can now see why a call got its decision: `policy explain` names the
rules that matched and the fields a rule could not read. Two starter policy
packs, read-only and approval-for-writes, come with cases that show what they
decide. A guide puts the plane between an MCP client and a server already in
use. An audit before the release fixed defects, among them: a call the agent
cancelled could lose its closing record, and enough of them blocked every later
call; other accounts could write the evidence directory; a configuration
refusal printed a header credential; and some MCP clients refused the plane's
answers as schema errors. [docs/status.md](docs/status.md) says what is
`implemented` and what is `experimental`. Nothing here is a security boundary
yet.

### Added

- `guardana-control policy explain <case>` decides one case as `policy test`
  does and says how: the decision's verdict, action, mode, policy digest and
  codes, what the kernel found before the policy, and a line per rule, matched,
  undetermined with the field it could not read and the input that field
  lacked, or not matched on the fields that failed. It reads the kernel's own
  evaluation, so it never describes a decision the kernel would not make for
  the same case
  ([ADR-0036](docs/adr/0036-policy-explain-reads-the-kernels-own-evaluation.md),
  [reference/policy-explain.md](docs/reference/policy-explain.md)).
- Two starter policy packs under `examples/starter-packs/`, read-only and
  approval-for-writes, each a document with allow, deny and unknown cases, and
  a page that says what each assumes about the plane and leaves unguarded
  ([reference/starter-packs.md](docs/reference/starter-packs.md)).
- A guide that puts the plane between an MCP client and a server already in
  use, and a profile for the MCP project's reference filesystem server that
  classifies its 14 tools and holds every write for approval
  ([guides/connect-an-existing-mcp-setup.md](docs/guides/connect-an-existing-mcp-setup.md)).

### Fixed

- A `tools/call` the plane blocked or held for a tool that declares an output
  schema reached the agent as a schema error from any client that checks
  structured content, the MCP project's own TypeScript client among them,
  instead of `APPROVAL_PENDING` or the block's codes. The plane's own answers
  now carry their fields in the result's `_meta` under its namespace and no
  structured content.
- A configuration value the reader refused (a flow character, an unknown
  escape, an unclosed quote) was printed in `doctor`'s and `run`'s refusal,
  credentials included: an `export.headers` or `pdp.headers` value, the
  `pdp.proxy`, an endpoint with userinfo. Those are now named without the
  value.
- The evidence spool took a directory other accounts could write, or another
  account owned, and appended through a link put at a segment's name. It now
  refuses both, as the approvals, runs and pause directories do, and opens
  every segment without following a link.
- The configuration reader kept a tag (`!!str x`) or a single-quoted value
  (`'acme'`) as text, marks included, so a tenant id written `'acme'` matched
  no run and no rule. Both are now refused; quote a value with double quotes.
- A call the agent cancelled after the plane handed it out lost its closing
  record: the trail stopped at `ACTION_STARTED`, material calls halted, and the
  spool kept the call's reservation, so enough cancelled calls blocked every
  call until a restart. The closing record is now written whatever the agent
  does.
- A stateful HTTP session was never ended, so sessions a client opened and
  abandoned held the plane's memory until it stopped. A session idle for 30
  minutes now ends.
- A `shorten_timeout` obligation whose `ms` a duration cannot hold wrapped
  when converted, and the call ran with no bound or with one nobody wrote. It
  is now refused like a non-positive `ms`.

## [0.4.0-alpha] - 2026-10-01

An operator can now open runs for an agent, and a plane with `runs.dir`
accepts a call only under a run token that resolves: two runs of one agent
keep their flow state apart, and a run's flow state survives a restart. A
plane without `runs.dir` behaves as before. A stdio plane no longer writes its
start lines into the protocol stream.
[docs/status.md](docs/status.md) says what is `implemented` and what is
`experimental`. Nothing here is a security boundary yet.

### Added

- Runs an operator opens
  ([ADR-0034](docs/adr/0034-a-run-the-operator-opens-has-an-identity-of-its-own.md)):
  `guardana-control runs open`, `close` and `list` over a runs directory, and
  `runs.dir` on the plane, under which every call needs a run token, in the
  `Run-Token` header on HTTP or from `run --run-token-file` on stdio. Two
  runs of one agent keep their flow state apart, a run opened under a parent
  shares the flow state of the parent's top-level run, the state survives a
  restart, and a held call resumes only from its own run. A refused token is
  answered with HTTP 401 or the JSON-RPC error `-31102`, and the refusals are
  counted by cause. A plane without `runs.dir` is unchanged.

### Changed

- The release job waits for a maintainer to approve it in the `release`
  environment before it builds; [RELEASING.md](RELEASING.md) has the step.

### Fixed

- A plane with a stdio listener wrote its start lines, the mode and the count
  of held calls lost to a restart among them, to standard output, which is the agent's protocol stream,
  so a client's first read failed; they now go to standard error.

## [0.3.0-alpha] - 2026-10-01

A configuration must now name its enforcement mode: one that relied on the
`OBSERVE` default no longer loads. The demo now starts with
`dev --decision-point=silent` and needs a system with process groups. A
resource prefix now refuses the dot segments, percent escapes, queries and
fragments that let an id leave it; evidence no longer carries previews; and a
result that cannot be hashed is recorded as `UNKNOWN`, not as a success. New
are a demo archive that runs without Go, an evidence export another program
resumes by cursor, and the documentation on the website.
[docs/status.md](docs/status.md) says what is `implemented` and what is
`experimental`. Nothing here is a security boundary yet.

### Changed

- `mode` has no default: a configuration that names no enforcement mode is
  refused at load instead of starting a plane in `OBSERVE`, which stops nothing
  its policy decides. Add `mode:` to a configuration that relied on the
  default ([ADR-0032](docs/adr/0032-the-enforcement-mode-has-no-default.md)).
- The demo's decision point no longer listens on the fixed port
  `127.0.0.1:18213`, so demos run side by side: start the demo with
  `dev --decision-point=silent`, which the old command lacks and now needs.
  `dev` refuses a system without process groups before it starts anything.

### Added

- A website for `control.guardana.dev` in `site/`: one static page with
  no script and nothing loaded from another host, whose diagrams
  `make docs-gen` draws from README's, and the project's mark in the
  README header ([ADR-0030](docs/adr/0030-a-static-website-drawn-from-the-repository.md)).
- The documentation on the website: every page, record, the roadmap and
  the changelog rendered under `control.guardana.dev/docs/` by
  `make docs-gen`, with links, anchors and diagrams that mean there what
  they mean on GitHub, and a check that fails when a page and its rendering
  drift ([ADR-0031](docs/adr/0031-the-documentation-is-served-on-the-website.md)).
- A demo archive per platform, `guardana-control-demo_<version>_<os>_<arch>.tar.gz`,
  that runs the tutorial and every scenario without Go or a checkout; each
  release runs its scenarios from the linux/amd64 archive before it is
  published
  ([ADR-0033](docs/adr/0033-a-demo-archive-a-release-user-runs-without-go.md)).
- `dev --decision-point=silent`: a decision point on a port `dev` binds and
  never answers, so a rule reading `external` is undetermined with
  `PDP_TIMEOUT`.
- `guardana-gateway trail export`: a trail file in a versioned format another
  program reads, with a cursor to resume from, a record for every line it
  cannot read, and a trailer; `examples/evidence-report` rebuilds each call's
  lifecycle from it without importing the project's internals
  ([ADR-0035](docs/adr/0035-a-versioned-evidence-export-and-a-bounded-query.md)).

### Fixed

- A `restrict_resources` obligation with a `prefix` let a resource id such
  as `/srv/data/../../etc/passwd`, `/srv/data/%2e%2e/etc` or
  `https://api.example/pub/..?x` through; under a prefix, an id holding a
  segment of dots, an empty segment, a backslash, a `%`, a `;`, a `?`, a `#`
  or a byte outside printable ASCII is now refused.
- The plane recorded whatever preview an adapter put on a call's arguments or
  its result; every event now reaches the sink without previews, as capture
  is off.
- A tool result that could not be encoded was recorded as a success with no
  hash; it is now `UNKNOWN`, with the protocol status `unhashable`.
- An approver's answer succeeded beside a consumed or not-resumed record it
  could not read; the store now refuses it and takes the answer back.
- An approver whose answer the plane spent between the approver's write and
  its check was told the approval had been consumed; it is now told the
  answer was filed, and any other consumed record still refuses it.
- The collector kept the argument and result previews another producer sent;
  it now clears them before the trail file holds an event. A trail file that
  already holds such an event reads a copy sent again as other content.
- A pending call told the agent to retry after 0 seconds when
  `approvals.retry_after` was under a second; the hint now rounds up to whole
  seconds.
- A scenario stopped as one that could not run when the plane's read of its
  pause file ran late on a busy machine and `/healthz` briefly reported the
  pause state stale; the runner now reads it again until its timeout, and any
  other unknown cause still stops it.

## [0.2.0-alpha] - 2026-09-28

The second release. It fixes how an approval's expiry is kept, how much
of the plane a stdio upstream is handed, where a plaintext export may go,
and how numbers and uncertain results are recorded. It adds an image of
the gateway beside the archives, and pages that say what the plane
protects, what it records and which failures it survives.
[docs/status.md](docs/status.md) says what is `implemented` and what is
`experimental`. Nothing here is a security boundary yet.

### Added

- Reason code `APPROVAL_STATE_UNKNOWN` (44, `INDETERMINATE`): a lost hold
  whose approval the plane could not read or trust closes with it, where
  it closed as `APPROVAL_EXPIRED` before
  ([ADR-0027](docs/adr/0027-expiry-at-hand-out-and-an-unreadable-lost-hold.md)).
- A benchmark of the gateway round trip, and `scripts/bench.sh --publish`,
  which records a run from a clean tree, with its hardware and Go
  settings, in a tracked file under `bench/results/`
  ([docs/reference/benchmarks.md](docs/reference/benchmarks.md)).
- Each release is to publish `ghcr.io/guardana/control-gateway:<version>`
  for linux/amd64 and linux/arm64, signed keyless and with build
  provenance, its digest named in the release notes;
  [RELEASING.md](RELEASING.md) says how to check it and
  [docs/guides/run-in-a-container.md](docs/guides/run-in-a-container.md)
  how to run it.
- A page of the failures the plane is built to survive: the collector, the
  spool, the decision point, an upstream dying mid-call, the pause file
  and a restart with calls held, each with a test that runs the built
  binary against a real failure
  ([docs/reference/failure-modes.md](docs/reference/failure-modes.md)).
- A threat model and a privacy page: what the plane protects, from whom
  and where it stops; what a record holds, where it goes and how long it
  stays ([docs/concepts/threat-model.md](docs/concepts/threat-model.md),
  [docs/concepts/privacy.md](docs/concepts/privacy.md)).

### Changed

- A stdio upstream no longer inherits the plane's environment. It gets
  `PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR` and `USER`, each where the
  plane has it, and the variables its new `upstreams.N.env` list names;
  a name under `GUARDANA_CONTROL_` is refused, so the exporter's and the
  decision point's header credentials are no longer handed to it. An
  upstream that read any other inherited variable starts without it:
  list each one it needs, and `doctor` marks a listed name the plane's
  environment lacks
  ([ADR-0028](docs/adr/0028-a-stdio-upstream-gets-only-the-environment-it-is-given.md)).
- `export.allow_plaintext` admits a plaintext collector on a loopback IP
  literal only, as `pdp.allow_plaintext` already did and as
  [ADR-0020](docs/adr/0020-a-trail-and-counters-without-a-collector.md)
  states. A plaintext endpoint on any other host, a name such as `localhost`
  included, is refused at start.

### Fixed

- A tool whose definition holds a fractional number, such as
  `"default": 0.7`, is fingerprinted and can be classified, and a call
  whose arguments hold a fraction a double represents exactly is decided.
  The digest binds a number's value, so `1.0` and `1` digest alike, and
  every digest of arguments accepted before is unchanged
  ([ADR-0029](docs/adr/0029-exact-fractions-in-the-canonical-form.md)).
- A resumed call whose approval expired by the plane's clock before it
  was handed to the upstream is not sent: it is blocked with
  `APPROVAL_EXPIRED`, and the approval stays spent.
- A call whose answer the gateway could not read, or could not complete
  over HTTP (a malformed answer, a connection the upstream closed after
  reading the call, a 429 or 5xx status), is recorded with an `UNKNOWN`
  result rather than as the upstream's failure: whether it took effect
  is unknown.
- A decision point's answer that reaches the gateway after the call's
  deadline is a timeout (`PDP_TIMEOUT`), whatever its status and headers.
  Such an answer could be read as refused or as unavailable instead.

## [0.1.0-alpha] - 2026-09-25

The first public release. [docs/status.md](docs/status.md) says what is
`implemented` and what is `experimental`. Nothing here is a security boundary
yet.

### Added

- Wire contracts, frozen at `1.0`: eight protobuf files for the action
  envelope, the decision, approvals, results, events, findings, policy bundles
  and the shared types, with the generated Go. `pkg/contract` decodes them
  strictly, refusing unknown fields and undeclared enum numbers, and validates
  an envelope within stated bounds
  ([ADR-0002](docs/adr/0002-wire-contracts-and-versioning.md)).
- A canonical form for an action and the digest built on it, with golden
  fixtures ([ADR-0005](docs/adr/0005-canonical-action-digest.md),
  [ADR-0010](docs/adr/0010-digest-domain-separation.md)).
- Policy documents in `agent-policy/v1alpha1`, read as strict JSON; bundles
  signed with Ed25519 over the DSSE pre-authentication encoding; a three-valued
  matcher where `DENY` overrides; and the decision kernel with its fixed order
  and fail-closed table, under which `INDETERMINATE` never allows a material
  call ([ADR-0012](docs/adr/0012-policy-kernel-semantics.md)).
- `guardana-control`: `policy lint`, `test`, `keygen` and `sign`; `approvals
  list`, `approve` and `reject`; `pause init`, `add`, `remove` and `list`; and
  `console`, a page on the loopback that answers held calls and pauses
  ([ADR-0018](docs/adr/0018-keys-and-bundles-on-disk.md),
  [ADR-0019](docs/adr/0019-an-operator-can-pause-calls.md),
  [ADR-0023](docs/adr/0023-a-local-page-answers-through-the-directory.md)).
- `guardana-gateway`, an MCP gateway that decides each call before it reaches
  the server: `run` and `doctor`; the enforcement modes; approvals bound to one
  action digest and consumed once; obligations; a check that the executed
  arguments are the authorized ones; evidence kept in a local spool and exported
  over OTLP ([ADR-0013](docs/adr/0013-mcp-interception-approvals-and-modes.md),
  [ADR-0014](docs/adr/0014-evidence-spool-and-sinks.md),
  [ADR-0016](docs/adr/0016-approval-providers-and-the-lost-hold.md)).
- An external AuthZEN decision point that can veto what the signed policy
  allows, and never grant
  ([ADR-0017](docs/adr/0017-an-external-decision-point-can-veto.md)).
- `guardana-gateway collect` and `trail`, a trail file without a third-party
  collector, and `GET /metrics` in the Prometheus text format
  ([ADR-0020](docs/adr/0020-a-trail-and-counters-without-a-collector.md)).
- Run flow: the plane records whether a run took in untrusted input, so a
  policy's flow rule can block a later send to an untrusted destination
  ([ADR-0021](docs/adr/0021-a-run-carries-what-it-took-in.md)).
- `guardana-gateway scenario run`, which holds a live plane to
  `agent-scenario/v1alpha1` files, and `guardana-gateway dev`, one command for
  a local plane with its collector and approvals page
  ([ADR-0022](docs/adr/0022-scenarios-are-data.md),
  [ADR-0023](docs/adr/0023-a-local-page-answers-through-the-directory.md)).
- A demo, `examples/vulnerable-mcp-agent`, with seven scenarios, and
  [its tutorial](docs/get-started/try-the-demo.md).
- One quality gate, `make quality`, which CI runs on every push to `main` and
  every pull request, and a documentation structure the gate checks
  ([ADR-0015](docs/adr/0015-documentation-structure-and-checks.md)).
- Release archives for Linux and macOS on amd64 and arm64, with a CycloneDX
  bill of materials per archive, signed checksums and build provenance
  ([ADR-0025](docs/adr/0025-public-repository-merges-and-releases.md)).
- Governance: DCO sign-off, Conventional Commits, a security policy, a code of
  conduct, trademark terms and 25 architecture decision records, among them the
  independence of this project from Guardana
  ([ADR-0024](docs/adr/0024-control-and-guardana-are-independent.md)).

[Unreleased]: https://github.com/guardana/control/compare/v0.13.0...HEAD
[0.13.0]: https://github.com/guardana/control/releases/tag/v0.13.0
[0.12.0]: https://github.com/guardana/control/releases/tag/v0.12.0
[0.11.0]: https://github.com/guardana/control/releases/tag/v0.11.0
[0.10.2-alpha]: https://github.com/guardana/control/releases/tag/v0.10.2-alpha
[0.10.1-alpha]: https://github.com/guardana/control/releases/tag/v0.10.1-alpha
[0.10.0-alpha]: https://github.com/guardana/control/releases/tag/v0.10.0-alpha
[0.9.0-alpha]: https://github.com/guardana/control/releases/tag/v0.9.0-alpha
[0.8.0-alpha]: https://github.com/guardana/control/releases/tag/v0.8.0-alpha
[0.7.0-alpha]: https://github.com/guardana/control/releases/tag/v0.7.0-alpha
[0.6.0-alpha]: https://github.com/guardana/control/releases/tag/v0.6.0-alpha
[0.5.0-alpha]: https://github.com/guardana/control/releases/tag/v0.5.0-alpha
[0.4.0-alpha]: https://github.com/guardana/control/releases/tag/v0.4.0-alpha
[0.3.0-alpha]: https://github.com/guardana/control/releases/tag/v0.3.0-alpha
[0.2.0-alpha]: https://github.com/guardana/control/releases/tag/v0.2.0-alpha
[0.1.0-alpha]: https://github.com/guardana/control/releases/tag/v0.1.0-alpha
