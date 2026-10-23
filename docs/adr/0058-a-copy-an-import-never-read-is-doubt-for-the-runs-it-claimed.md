# ADR-0058: A copy an import never read is doubt for the runs it claimed

Status: accepted
Date: 2026-10-23

Amends [ADR-0040](0040-observations-a-record-a-log-and-one-importer.md): the
record reader's table holds `0.1` and `0.2`, and an import report states the
runs its refusals put in doubt. Amends
[ADR-0045](0045-one-run-is-supervised-against-its-procedure.md): a run in
doubt at its source leaves the two rules that read a source's reports not
checked, and a finding citing such a run's observation is `INDETERMINATE`.

## Context

An import counted the spans it refused and the observations the log refused
for an id it already held with other content, and nothing read the counts.
Each such copy was never written, or kept in place of the other, so it may be
the very call a procedure rule looks for: a step outside the procedure, or a
denied action retried another way. `supervise` read the log as if every call
the source sent were in it, and could say a rule held where the source had
said otherwise.

Counting alone could not scope the doubt: a source that refused one span of
one run would leave every rule of every run of that source unchecked for as
long as the log lasts.

## Decision

1. An `ImportReport` names the runs its refused copies claimed:
   `doubted_run_ids`, run ids in ascending order, each once, at most 64. A
   refused span names the run its run attribute holds; a conflict names both
   the refused copy's run and the run of the copy the log kept, which a kept
   copy claiming no run leaves out, since no run's supervision reads it.
2. A refused copy that claims no run, a claim that is not a run id, a line refused
   before its spans are read, or a 65th run sets `every_run_doubted` instead,
   with the list empty. A copy that could be any run's leaves no run clear.
3. A report carrying either member is schema `0.2`; every other report and
   every observation stays `0.1`. The reader takes both and refuses a `0.2`
   record with neither member and a `0.1` report with one. A reader of `0.1`
   alone refuses every `0.2` line rather than read past the members.
4. `observelog.Write` refuses a caller's report the codec would refuse, then
   adds the runs of the conflicts it finds itself. A `0.1` report that counts
   a refusal or a conflict is read as doubting every run.
5. `supervise` takes, per source, every run its log's reports doubt. When a
   run the evaluation judges is among them (the root, or under `inherit` any
   run of the tree), `STEP_OUTSIDE_PROCEDURE` and
   `DENIED_ACTION_RETRIED_AROUND` are not checked, findings kept. A finding
   citing an observation is `INDETERMINATE` when that observation's own run
   is doubted, `SUSPECTED` otherwise. The reason names every cause that cut
   the rule.
6. A doubt has no time bound: it holds while the log holds the report, and
   rotating the log by hand ends it.

## Security / compatibility impact

Doubt only lowers a verdict or leaves a rule unchecked; it never confirms a
finding or clears one. An agent that writes its own telemetry can put another
run in doubt by claiming it in a span the import refuses, which makes
supervision of that run stricter, not more lenient. `supervise` stays pure:
the command line reads the reports and passes the runs in.

`0.2` is additive to the record's shape. A log holding a `0.2` report cannot be
read by an earlier release, which refuses the line loudly (invariant 3). The
observation export carries each report's line as written.

## Alternatives considered

- A sum of the counts, as the first version of this change had: doubt that
  reached every run of the source for the log's life.
- An unbounded list of runs: one import of hostile spans could grow a report
  without limit; past 64 the doubt is coarser, never absent.
- Bounding a doubt of every run by the report's receive time against the
  judged run's opening: the import and the run need not share a clock, and a
  skew would clear a doubt that should hold.
- The new members under `0.1`: an earlier reader would refuse them as unknown
  fields, but the version would name two shapes.

## Consequences

One undecodable line in an import leaves the two rules unchecked for every
later run of that source until the log is rotated; `supervise` exits 1 and
says why. `coverage` and `react` read no doubt. An observation kept with a
malformed run attribute is left out of supervision with no doubt, as an
omitted span would be.

## Validation

- `internal/ingest/otelgenai/doubt_test.go`: a refused span puts its run, or
  every run, in doubt; past 64 runs, every run.
- `internal/observelog/doubt_unix_test.go`: a conflict puts the runs of both
  copies in doubt across a reopen; a caller's malformed report refuses the
  write and leaves the file unchanged; a `0.2` report exports as a record.
- `internal/observe/doubt_test.go`: the codec holds the list to one form and a
  record to `0.2` exactly when it carries a `0.2` member; `DoubtedRuns` reads
  a `0.1` report that counts a refusal as every run.
- `internal/supervise/doubt_test.go`: the scope by run and tree, the verdict
  by the cited observation's run, every cause named.
- `cmd/guardana-control/supervise_sources_test.go`: a copy the import refused
  is not a pass; a refused copy of another run leaves this run checked.
