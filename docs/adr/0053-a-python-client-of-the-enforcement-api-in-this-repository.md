# ADR-0053: A Python client of the enforcement API lives in this repository

Status: accepted
Date: 2026-10-13

Builds on [ADR-0051](0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md),
whose conformance files it is held to. Amends
[ADR-0007](0007-repository-layout-and-dependency-rule.md): the layout gains
`clients/`.

## Context

The enforcement API has one client, the Go reference in
`internal/enforceclient`, and the tools it was written for are Python
functions inside agent frameworks. Each of them would otherwise write its own
client and get the hard parts wrong one at a time: running the proposed bytes
where the authorized ones differ, treating an unknown outcome as a go-ahead,
aborting where the effect may have happened, sending a call twice.
`testdata/enforce/client` states some of those rules as files any language
can run; the Go reference keeps more of them in Go tests alone. The repository
has no Python, so the first module also decides where a second language lives,
what it may depend on and how the gate runs it.

## Decision

- **Where.** `clients/python/`, a project of its own with a `src/` layout,
  beside the Go module and outside it. The distribution is named after the
  product's slug and imported as `guardana_control`; the client is
  `guardana_control.enforce`. `clients/` is where a client in another language
  goes.
- **What it is.** One synchronous call that owns an execution, with the Go
  reference's rules. Arguments are bytes in and bytes out; the module never
  parses or serialises them. Beneath the call sits one layer of three
  single-request operations that reads each answer and applies every rule
  that needs no tool, and returns a plain value. That layer is not public
  until a consumer that splits the lifecycle across processes has a record and
  cases of its own. An `asyncio` entry point comes with the first framework
  integration, wraps the same layer and is held to the same cases.
- **The tool.** It returns a result naming its status; none, or one the
  contract does not declare, is completed `UNKNOWN`. It raises one named
  exception, matched by type and never through a chain, to say its bytes never
  left. Any other exception, `BaseException` included, is completed `UNKNOWN`
  and raised again unchanged. A coroutine function or a generator function is
  refused before admit. A tool that returns anything but a result or nothing
  was entered: it is completed `UNKNOWN`, and the call raises.
- **A held handle gets exactly one closing request**: an abort if the tool was
  not entered, a complete if it was, the mark set before the tool is called.
  Nothing is retried. A killed process leaves the handle to the receiver's
  sweep.
- **The caller.** An optional "the caller is gone" check, read before admit
  and before the tool, after the obligation and byte checks; anything but
  `False` reads as gone. No request is tied to it, so a closing request is
  sent whatever it says. Socket, run token and a finite positive timeout are
  required, and the timeout bounds a whole request, not each read.
- **What it returns.** Returning normally means the tool ran and the closing
  record landed, not that the tool succeeded. A blocked, pending, refused,
  aborted, unrecorded or unanswered call raises, and every exception of the
  module says whether the tool ran and carries the decision, the ending and
  the tool's result. A call that was misused raises a plain `TypeError` or
  `ValueError` before anything is sent. A tool's own exception leaves as it
  was raised, after its run was reported; when it is an exception of this
  module, because the tool made a call of its own, it leaves inside one that
  carries the outer call's answer.
- **It cooperates and is never a boundary.** It runs inside the process it
  constrains. A plane it talks to reports every path `decided, not enforced`,
  as ADR-0051 says, and no page calls this module an enforcement point. It
  computes no digest and verifies no signature.
- **No runtime dependency.** The standard library alone, held by a test that
  reads the module's imports. An agent's process already carries its
  framework's pins, and a client that adds its own cannot be installed beside
  some of them.
- **Answers are read in the form the receiver writes**: the JSON name of each
  member, once; an enum as a declared name or an integer in int32 range; an
  int64 as a decimal string; bytes as padded standard base64; a Timestamp as
  RFC 3339 with `Z` and up to nine fractional digits; a Duration as decimal
  seconds with `s`. Anything else, `null` and a repeated member included, is a
  malformed answer. This is narrower than the protobuf JSON mapping on
  purpose: nothing the Go reference refuses is read. A generator in this
  repository writes the messages' members, types and enums from the compiled
  descriptors into a Python table and refuses a field kind the reader has no
  rule for; a pinned test fails when the table and `api/proto` differ.
  `docs/contracts.md` says this form is what a client may rely on.
- **Conformance from the shared files.** The tests read `testdata/enforce`
  where it is, never a copy. The client, and a second client written apart
  from it, pass every client case; the second, told to break one rule, fails
  that rule's case. Requests are compared with `expect.json` as JSON values,
  member for member, with no table between. `testdata/enforce` gains answer
  vectors, a status and a raw body with the reading or the refusal expected,
  which the Go reference and the Python client both run; one is a fully
  populated answer as the receiver marshals it. It gains one client case, a
  tool that reports nothing. One Python test drives a real plane through
  built binaries the make target hands it: an allowed call whose answer is
  larger than one chunk, a blocked one, and the trail read back.
  `go test ./...` needs no Python.
- **Pins.** Python 3.11 is the floor. The gate runs the tests on two exact
  interpreter versions, the floor and one named newer line, and the linter and
  the type checker on the newer. `uv` installs the interpreters and the
  development tools; its version and digest sit in
  `scripts/tool-versions.env` like every other binary tool, and moving it is
  an interpreter change. `uv.lock` pins `ruff` and `mypy` with hashes. Tests
  use `unittest`. The build backend is `flit_core`, pinned by hash in a
  build-constraints file. Each gets its row in `docs/dependencies.md` as
  tooling.
- **The gate.** One make target, part of `make quality` and not of
  `quality-quick`, so CI's quality job and a release commit's cold gate both
  run it. It runs `uv` in an emptied environment with no user configuration,
  managed interpreters only and the lock enforced, downloads no interpreter
  (`make bootstrap` installs both and its check verifies them), builds no
  locked tool from source and runs Python isolated from the environment.
  What it examines is what the commit holds: the project file declares the
  project its own workspace root, so no project file above it names another
  lock; the linter and the type checker are given that file as their only
  configuration, and the linter obeys no ignore file; and the target refuses,
  inside the project, a symbolic link, bytecode, a stub, an extension module
  and a directory a checker skips by its name. `scripts/check-python-probe.sh`
  plants each. It fails on zero tests, on any skip, on a test whose body
  never runs, on a case or a vector that did not run on each interpreter, and
  when a test this record or a page rests on did not run. It
  builds the wheel and checks that it declares no requirement, carries the
  licence and has the release's version. It writes nothing into the tree.
- **Releases.** The module's version equals the newest dated section of
  `CHANGELOG.md`, a preview suffix written as Python spells it; the release
  commit sets it and refreshes the lock. The release workflow builds the wheel
  and the source archive from the tag, through `scripts/build-python-dist.sh`
  as the gate does, and attests them before any other tool of the release job
  runs. Once the release is published, a job of its own in the `pypi`
  environment, the one the index trusts, which admits `v*` tags and which a
  maintainer approves, verifies their provenance and commit and uploads them
  to the public package index through trusted publishing, with no stored
  token, then reads the index back. It is given the version the release job
  built and refuses files of any other. Run again alone, it skips what the
  index holds. The dry run uploads a development release to the test index the
  same way, from a job in the `testpypi` environment, which admits `main`
  alone. Each upload is given the files' digests as the build step listed
  them, before any other tool of its job ran, and refuses other files. Each
  index's trusted publisher names this repository, `release.yml` and the
  job's environment; the index holds that setting, not the tree, so a
  maintainer reads it there before a release.
  Between releases the tree names the last release.
- **Review.** `clients/` is not a two-approval path, since nothing in it
  decides, except the files at the top of the client's project: its project
  file, lock and build constraints and the two programs the gate runs, which
  are gate inputs. `testdata/enforce`, which it is judged by, stays one. The
  client's sources and tests are reviewed like any source: a test runs inside
  the runner's process and can defeat it, as a Go test can defeat its report,
  and review is the defence there.

## Security / compatibility impact

No authorization path changes and the plane gains no code. The module adds
tools to the gate, not to any request path. A user of the module runs no
third-party code at run time; a wheel installs without building anything. The
first upload claims the distribution name on the public package index; until
it exists, an install by that name would fetch whatever a stranger put there,
into a process that holds a run token. An upload cannot be replaced, so a
broken one is followed by the next version, as a release is. If the release
job fails after the release is public, the upload job does not run and that
version's client is never uploaded; the next version carries it. The contract is
`v1alpha1`, so the module's interface may change with any release. A client
is tested with the plane of its own release. With a newer plane it may refuse
every answer, because a strict reader does not know a member or an enum name
added since; the error names what it did not know. The import name is a new
spelling of the product name: it is a constant of `internal/brand`, a test
holds the package's directory to it, and `scripts/rename-product.sh` rewrites
and moves it. The brand check does not forbid that spelling outside the
module, since generated Go identifiers already carry it. CodeQL analyses Go
only; the module is read by the linter's security rules and its lock by the
vulnerability scan until a second language is added there in a change of its
own.

## Alternatives considered

- A repository of its own: its own releases and issue tracker, and a
  conformance suite that reaches the client only as a copy or a submodule,
  which is how a client drifts from the contract it is held to.
- The `protobuf` package with generated messages: less code, a pinned
  dependency inside every agent process where its version range collides with
  the frameworks' own, and still no reading equal to the Go reference's.
- The whole protobuf JSON mapping by hand: unbounded, and it would copy the
  reference's quirks.
- Lenient decoding with the standard `json` module alone: no table, and the
  client would run a tool on an answer it only partly understood. Read
  naively, a repeated `outcome` member takes the last value and `true` reads
  as the number 1.
- One judge in Go driving every client as a subprocess: the best independence
  and no harness per language, at the cost of a cancel signal across
  processes. Taken up when a third language arrives.
- Keeping the module off the package index for now: no new release step, and
  a free name on the index that anyone could take and fill, for a module
  imported into processes that hold run tokens.
- A CI job of its own for Python: the required check, the release gate and the
  cold gate all hang on `make quality`.

## Consequences

A Python tool gets the client rules by importing one module. The gate grows a
second toolchain that must be installed, pinned and kept current. A proto
change now has a generated Python table to refresh, and an additive change to
a message a client reads stops an older client. `testdata/enforce` grows
vectors both clients run, so rules the Go reference kept to itself become
files. A second client language has a place and a pattern.

## Validation

- Every client case passes on both interpreters for the client and for the
  second client without a defect, and every negative control fails its case.
- The answer vectors: both clients read alike, both refuse, or the Go
  reference reads and a client refuses; never a different reading. A Go test
  runs them through the reference's decoder and seeds its fuzz target.
- Python tests for the rules no case file holds: an `EXECUTE` with no handle
  or no execution; an error body under status 200; only `RECORDED` saying the
  record landed; a refused abort still reported as an abort; an ended caller
  sending nothing; the bound on an answer's size; the timeout over a receiver
  that trickles; no redirect followed; an interrupt between admit and the
  tool (abort) and inside the tool (complete `UNKNOWN`, the same exception
  raised again); a not-sent exception met only in a chain (complete, not
  abort); a coroutine tool refused.
- The generated table's pin fails when a member or an enum value is added to
  a message the client reads.
- The end-to-end test shows a blocked call that never reaches the tool and an
  allowed one closed in the trail.
- The gate's runner fails on an empty or a skipped run; the wheel check fails
  on a declared requirement, a missing licence or a version that is not the
  release's. Tests of the two programs hold both, and the runner requires
  those tests to have run.
- The release workflow's dry run builds both files as a development
  release, checks, attests and uploads them to the test index, and reads
  them back.
