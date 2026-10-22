---
title: Run view
summary: The page guardana-control supervise --view draws for one run, what each mark on it means, and what the command refuses to overwrite.
type: reference
covers: [internal/runview/**, internal/supervise/instances.go, cmd/guardana-control/supervise_view.go]
---

# Run view

`guardana-control supervise --view <file>` draws the run it has just
supervised as one HTML page, beside the findings it appended to the log
([supervision.md](supervision.md)). The page draws only what the supervision
returned and judges nothing itself
([ADR-0048](../adr/0048-one-run-drawn-as-a-page-and-findings-exported-with-a-cursor.md)).

## What the page shows

- The run, its tenant and project, the procedure's id, version and digest,
  and under a `0.2` procedure the children mode and the run tree.
- What was read: how many events and observations were used and left out,
  how many evidence exports were read whole (header to trailer, no gap), and
  the plane's own blocks, such as a pause, counted by reason code.
- The expected steps in the procedure's order, each with the numbers of its
  calls, or marked not seen.
- The first 1000 findings, each with its rule, verdict, escalation, id, under
  a `0.2` procedure the run it names, and the numbers of the calls it cites;
  and how many more there are.
- The observed calls: number, mark, request or observation id, tool and
  upstream, step, run, time, export, outcome with the approval and the reason
  codes, resource, and the findings that cite the call.
- Every source the run was not checked against, and the state of every rule.

Calls are ordered by the time their plane recorded the proposal, calls with
no time last. A plane call with no time, whose time another call shares, or
read beside timed calls of another export, whose clock is not its plane's, is
marked "order not told". A source's report is placed by its
source's time and marked "the source's clock, not ordered against the
planes'": its place beside a plane call says nothing of which came first.

## Marks

Each mark is a shape and a line style as well as a colour, and its label is
written beside it, so the page reads the same without colour and to a screen
reader. The legend at the foot of the page summarises this table.

| Mark | Shape and line | Means |
| --- | --- | --- |
| enforced | filled square, solid | A plane decided the call in `ENFORCE`, `APPROVE` or `LOCKDOWN` mode and its trail is one coherent chain. |
| decided, not enforced | triangle, dashed | A plane decided the call in another mode or recorded no mode, the trail is in doubt, or the call came through the enforcement API (protocol `enforce`), whose client runs it, in any mode. |
| observed | circle, dotted | Only a source reported the call, with the trust its descriptor declared. |
| exception or approval | diamond, dash and dot | An exception waived the call, or the approvals store granted it. |
| blocked | cross, long dashes | The policy denied the call, or the plane blocked it: a pause, a stop, an approval refused or expired, or a verdict such as `INDETERMINATE`. |
| not seen | hexagon, sparse dashes | A step with no call, or a source never heard, silent or not read. |

A source's report is marked observed. A plane's call is marked blocked when
it was denied or blocked; else decided when its trail is in doubt; else
exception or approval; else decided when its protocol is `enforce`; else
enforced when its recorded mode acts on its decision; else decided. No mark says "inferred": the page draws a
call only from a plane's or a source's record, never from a guess.

Colours come in a light and a dark scheme, chosen by the reader's system
setting. In both, every colour on the page has at least 4.5:1 contrast
against its background.

## Which calls are drawn

By default the page draws, for each finding it lists, the calls it cites and the call
just before and just after each, and counts the calls between as not drawn. A
run with no finding that cites a call draws no call. `--view-all` draws every
call of the run. Either way the page draws at most 1000 calls, and when it
stops there it says so and counts what it left out.

## A string an input chose

Tool names, upstreams, resource fields, reason codes, request, run,
observation, source and finding ids, and every other string a run's records
carry are written as text and never as an attribute, a link or a style. Each
is cut at 80 characters with `[cut]` written apart from it. A character that
does not print is written as an escape: a line break as `\x0a`, a direction
override as `\u202e`. A backslash is written as `\u005c`, so an escape on the
page is never the string's own text.

The page carries a `Content-Security-Policy` meta tag that allows inline
style alone: no script runs on it and it fetches nothing. Nothing on it moves
and nothing reads a clock, so one supervision draws the same bytes twice.

## The file

| `--view` path | What happens |
| --- | --- |
| does not exist, in a directory that does | the page is written there |
| a page supervise drew, a regular file this account owns | it is replaced |
| any other file, a link, a directory, a path in a missing directory, or a file another account owns | refused with status 2 before any input is read |

The page is written after the findings log, with mode `0600` whatever an old
page's mode was. It replaces the old page by a rename, so the path holds the
old page or the new one, never part of either. A failure to write it exits 2,
prints no report and says the log was written. When the page is written,
what `supervise` prints and its exit status are the same as without
`--view`. `--view-all` without `--view`, and `--view` given twice, are usage
errors.

The page holds what the findings log holds and more: tool names, resource
ids and reasons a run's agent chose. Share it as you would share the log.
