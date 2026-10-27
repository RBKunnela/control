# ADR-0063: A skipped test fails the gate unless the repository expects it

Status: accepted
Date: 2026-10-27

Builds on [ADR-0062](0062-the-gate-is-guarded-at-its-entry-points-and-fuzzed-at-night.md),
which narrowed the gate to what its entry points start.

## Context

`make test` and `make test-race` read `go test -json` through
`scripts/test-report.go`, which refuses a failure, an unfinished test, a
package that ran no test and one with no test files. A skipped test was listed
and counted, and passed. Sixteen tests skip on CI's Linux runner and thirteen
on a maintainer's Mac: a helper that runs only as the child process of another
test, a check that needs root to give a file away, a case the file system
cannot build. A `t.Skip` added to a security test, or one whose condition
started holding everywhere, passed the gate the same way, seen only by whoever
read the transcript.

The Python client's runner already refuses every skip.

## Decision

`scripts/expected-skips.txt` names every test some run of the gate may skip,
one per line: the import path, the test or subtest name, and text its skip
message holds, which says why. `internal/testreport` fails a stream holding a
skip the list does not name, or a listed test whose skip line, the last line
it printed, does not hold that text, and names it. A listed test that ran, or
never started, where its package was tested is printed, not refused, because the list is the union over Linux and
macOS under an ordinary account; a run as root skips other tests and is not
covered. A malformed list, or one naming a test twice, fails the reporter
before it reads the stream.

## Security / compatibility impact

No product code changes. A new skip needs an entry in the same change, which
review reads with its reason. An unconditional `t.Skip` added to a listed test
passes only when its message holds the listed text. A skip whose name changes
between runs, such as a subtest named from a temporary path, cannot be listed
and has to be renamed.

## Alternatives considered

- Refuse every skip, as the Python runner does: the child-process and
  file-system tests run where they can, and the root-only ones, which no gate
  of record runs, would have to be deleted or moved to a job that runs as
  root.
- Keep listing and counting skips: a reader of the transcript is the only
  check, and nobody reads a green transcript.
- A list per platform: four lists to keep, for no check the union lacks.

## Consequences

The list changes with the tests. The gate run as root fails on the tests that
skip only for root; no gate of record runs as root.

## Validation

`internal/testreport`'s tests refuse an unlisted skip, a listed test skipped
with another message and a subtest of a listed test, pass a listed one, print
a listed one that ran, and refuse a malformed or doubled list.
`scripts/check-modules-probe.sh` plants a skipping test in a staged module:
`make test` fails naming it, and passes once the staged list names it.
