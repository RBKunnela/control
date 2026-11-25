# A refund run, supervised and stopped

[An operator opens a run for an agent's refund on a live plane, checks it
against its procedure and stops it on a confirmed finding](../../docs/guides/supervise-and-stop-a-run.md). The `*_test.go`
files run every step on a Unix-like system;
[supervision.md](../../docs/reference/supervision.md),
[reaction.md](../../docs/reference/reaction.md) and
[run-view.md](../../docs/reference/run-view.md) are the references.

| File | Holds |
| --- | --- |
| `plane.yaml` | The plane and the orders server of [vulnerable-mcp-agent](../vulnerable-mcp-agent/) |
| `policy.json` | `ord-1` may be read, and refunded once approved; `ord-2` to `ord-5` neither; a status may be set; a customer export needs an approval |
| `refund.procedure.json` | `0.1`: fetch the order, then refund it |
| `refund-0.2.procedure.json` | `0.2`: the same, bound to one order, with an approved export waived |
| `refund-0.2.cases.json` | `procedure test` cases |
| `route.json` | Findings that may stop a run |
| `runtime.source.json` | The spans' descriptor |

Each test signs the policy and the route as
[run-the-gateway.md](../../docs/guides/run-the-gateway.md) shows, opens two
runs, starts a collector and the plane, and after the agent's calls exports
the trail and imports the runtime's spans.

**Under `0.1`.** The agent reads `ord-1`, then `ord-2` to `ord-5` (denied),
then refunds. `supervise` confirms `REPEATED_DENIAL` and suspects an upload
the plane never saw. `react` stops the first run: its next call is refused
`RUN_STOPPED`, the second run's go on. `stops lift` ends the stop; `notify`
delivers each alert once.

**Under `0.2`.** The agent reads `ord-1`, exports the customer's orders once
a person approves, is denied a refund of `ord-2`, and sets `ord-2`'s status
to `refunded` instead. `supervise --view` confirms `RESOURCE_OUTSIDE_RUN`
and `EXCEPTION_TAKEN` (the export), suspects
`DENIED_ACTION_RETRIED_RESOURCE`, and draws a page without script.
`findings export` writes them. `react` stops the first run on
`RESOURCE_OUTSIDE_RUN`; the second run's call runs. `procedure test` passes three cases.

Not shown: a child run, the rules about what is missing (both runs stay
open), the other retry forms, and an exception on a step. Whoever can write
the approvals directory approves.
