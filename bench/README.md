# Benchmarks

Three benchmarks on the authorization path, `contract.Validate`,
`canon.DigestV1` and `core.Decide`, and one MCP tool call through the gateway.
What they measure and what the numbers are not is in
[docs/reference/benchmarks.md](../docs/reference/benchmarks.md).

## Run

    scripts/bench.sh
    COUNT=5 BENCHTIME=1s scripts/bench.sh --publish

`BENCHTIME` and `COUNT` default to `1s` and `1`. A run goes to
`bench/results/local/`, which git ignores. `--publish` writes
`bench/results/<stamp>-<os>-<arch>.txt`, which is tracked: commit it with the
page that cites it, on a quiet machine. The script refuses to record a run when
the guard test fails or nothing was measured. It refuses to publish from a tree
that differs from its commit when the run starts or ends, that git is told to
overlook or ignores Go sources in, under a workspace, `GOFLAGS` or
`GOEXPERIMENT`, for a platform other than the host's or translated, or when it
cannot read the CPU, cores or memory.

## Test

    go test ./bench/

The `TestBenchmarked*` guards check every input before it is timed: each
measured call returns early on input it refuses, so without them a broken
fixture, a stale snapshot or a blocked call would be reported as fast work.

## Traps

- A results file records the date, the commit, the CPU, cores, memory, OS,
  usable CPUs, Go version, the Go environment variables and the load average,
  because a duration without them says nothing.
- The round trip runs the real exporter against a collector in the same
  process while it is timed and checks delivery after the timer stops, so the
  timed calls compete with the exporter's work but never wait for its
  acknowledgements.
- No gate fails on a duration: it would be reporting on the host rather than
  on the change.
- `BenchmarkDecide` and the round trip read the real clock; on a busy machine
  read the medians, not the tails.
