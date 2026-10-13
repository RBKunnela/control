# ADR-0007: Repository layout and the dependency rule for the decision path

Status: accepted
Date: 2026-09-09

Amended by [ADR-0026](0026-first-value-and-external-extension-paths.md): of the
four public packages only `pkg/contract` exists. The other three are reserved
names, and a Go seam is promoted only through its own record after two
consumers have used it.

Amended by [ADR-0039](0039-many-channels-into-one-core.md): detectors run
over exports, outside the plane, so `detectors/builtin/` is withdrawn; new
supervision logic goes to `internal/supervise`, a guarded tree.

Amended by [ADR-0053](0053-a-python-client-of-the-enforcement-api-in-this-repository.md):
a client of a contract in another language lives under `clients/`, a project
of its own outside the Go module.

Amended by [ADR-0037](0037-an-evidence-consumer-in-a-module-of-its-own.md):
`examples/evidence-report` is a module of its own, and the gate runs over every
module.

## Context

The part of the system that decides has to stay small enough for one person to
audit. Left alone, a decision path grows an HTTP client, a database handle and a
vendor SDK, and after that nobody can say what it depends on.

## Decision

Layout:

- `internal/` holds everything that is not intentionally public.
- The public Go surface is exactly `pkg/contract`, `pkg/adapter`,
  `pkg/detector` and `pkg/policyprovider`.
- Protocol and framework code lives in `adapters/`, built-in detectors in
  `detectors/builtin/`.
- Contracts live in `api/proto`, generated code in `api/gen/go`.

The dependency rule is an allowlist. A package in `internal/core`,
`internal/policy`, `internal/canon`, `internal/evidence` or `pkg/contract` may
import three kinds of package and nothing else: packages of this module outside
`adapters/`, `internal/storage`, `internal/controlapi`, `internal/gateway` and
`internal/ingest`; packages of `google.golang.org/protobuf`; and the standard
library packages named in `scripts/lib/dependency-rule.sh`, among which is no
network, file, process, system call, randomness, `unsafe` or plugin package.
Every package of this module that a guarded tree reaches is held to the same
rule, except the generated code under `api/gen`, which is accepted whole. In the
same trees golangci-lint refuses by name the functions of allowed packages that
read the clock, standard input, the zone database or the system's randomness.
Only reads a name reveals are refused; the local zone behind
`time.Unix(...).Format` passes, and the kernel's tests hold it. The same two
checks refuse, in a guarded package, every file `go list` reports under
`IgnoredGoFiles` or `IgnoredOtherFiles` and every non-Go source it compiles or
links (`SFiles`, `CgoFiles`, `SysoFiles` and the rest), so the package builds
from the same Go files on every platform and the gate on one platform speaks
for all.
Test files there may also import what a test needs to read fixtures, parse
source and run the go command, and still no network, system call, randomness,
`unsafe` or plugin package.

`internal/canon` and `internal/evidence` joined that list when they were
created. Both compute over data that has not been authorized yet, so they
belong to the set someone auditing a decision has to read.

## Security / compatibility impact

Someone auditing the decision path reads the decision path, not a transitive
dependency graph. The rule sandboxes nothing: adapter and core run in one
process, so a compromised adapter dependency can still affect the program. What
the rule buys is that the set of code able to influence a decision stays small
enough to read and to review, and that no module and no standard library package
can enter that set without an edit to the rule itself, in the three places the
agreement tests compare. The rule trusts each allowed package whole: what `fmt`
or `crypto/ed25519` import in turn is not examined, and an interface a caller
implements can still do I/O. Everything under `pkg/` is a compatibility promise,
so keeping that list to four packages keeps the promise small.

## Alternatives considered

- A flat layout with code review as the only guard. A reviewer sees the one line
  that adds an import, not the transitive graph it pulls into the decision path.
- A per-file lint exception for an import that is inconvenient once. The
  exception is invisible at the call site, so the next reader has no way to know
  the rule no longer holds there.

## Consequences

Adapters may import core; the rule only constrains what core imports. Core that
needs adapter behaviour declares an interface and the adapter implements it,
which costs a little indirection. Adding a package to `pkg/` is a compatibility
decision and needs its own record.

## Validation

Runnable today, and all in `make quality`: depguard in `.golangci.yml` through
`make lint`, `scripts/check-imports.sh` through `make check-imports`,
`internal/core/layering_test.go` through `make test`, and
`scripts/check-imports-probe.sh` through `make check-imports-probe`. The probe
plants, in every guarded tree of a copy of the repository, a package that dials
an address read from the environment, reads a file and the clock, imports an
adapter and an unlisted module, and reaches `os/exec` through a helper outside the
guarded trees; it fails unless each mechanism refuses it for the reasons that
mechanism covers. `make tidy-check` fails when `go.mod` or `go.sum` differ from
what `go mod tidy` writes.

The script and the test walk the dependency graph of every guarded tree and
judge the direct imports of every package of this module they reach. A package
from the layout that does not exist yet is reported as skipped and counted
separately, never as a pass.

The three mechanisms name the guarded trees and the allowed set separately, so
they can drift apart. `TestAllThreeMechanismsAllowTheSameSet` and
`TestAllThreeMechanismsGuardTheSameTrees` compare both across the three files and
fail when any two disagree.
