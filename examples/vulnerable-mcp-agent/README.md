# A vulnerable MCP agent

The demo the [tutorial](https://control.guardana.dev/docs/get-started/try-the-demo)
walks through: two MCP servers an agent should not be trusted with, the plane's
configuration and policy in front of them, and seven scenarios.

A scenario is the agent's script: the gateway's `dev --scenario` command
plays it against the plane as an MCP client and checks every answer,
decision and trail.

| File | Holds |
| --- | --- |
| `main.go`, `servers.go` (the archive's `bin/`) | One binary, `--serve orders` or `--serve web`, that the plane starts as an upstream over standard input and output. `orders` has `read_order`, `update_order`, `refund` and `export_orders`; `web` has `fetch_page`, whose page asks the agent to mail an order away, and `send_mail`. |
| `journal.go`, `journal_unix.go` | On Unix, with `VICTIM_JOURNAL_DIR` set, each server appends what it received to `orders.jsonl` or `web.jsonl` there, so the test sees a blocked call never arrived. The journal file, not its directory, must be this account's alone. |
| `demo.yaml` | The plane: `ENFORCE`, both servers started from `../../bin/`, every tool classified, and no decision point. `dev` sets the addresses, the key, the state and the approvals, and with `--decision-point=silent` the decision point. |
| `policy.json` | Reads run; updates need an approval; refunds are denied; an export is asked of the decision point, whose silence blocks it; mail to an untrusted destination is blocked once the run has read untrusted text. |
| `scenarios/` | `allow`, `deny`, `approval`, `digest-invalidation`, `fail-closed`, `pause` and `toxic-flow`. |
| `call.sh` | One tool call by hand, as an agent makes it. |

Run `dev` with `--decision-point=silent`: it binds a loopback port
that takes the plane's question and never answers, so the export's ask times
out and is blocked. Without the flag the plane refuses the policy,
whose decision point `demo.yaml` does not name. On a Unix-like system the
tests run every scenario and the tutorial's calls, read the journals, and
fail one mutant of each scenario on purpose.
