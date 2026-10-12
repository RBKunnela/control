# Receiver cases for the enforcement API

What a receiver of [ADR-0051](../../../docs/adr/0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md)
must answer and record. `go test ./adapters/enforce/` runs every case against
the adapter in front of an in-process plane, then again with each negative
control's defect from `../cases.json`, which must fail it.

`<case>/setup.json` is the plane: its `mode`, the policy `rules` (signed as
one `agent-policy/v1alpha1` bundle), the `tools` table (each tool's
classification, `returns_trust` and `returns_sensitivity` among it), the
`execution_lifetime`, and the `runs`, each `for` the listener, for `other` (another agent) or for `nobody` (a token no
record holds), possibly `closed`. The listener is principal `user-1` of type
`user` in tenant `tenant-1`, agent `agent-1`, project `proj-1`, environment
`prod`. The clock starts at 2026-10-11T12:00:00Z and moves only when a step
says so.

`exchange.jsonl` holds one step per line: a request (`as` the run whose token
goes in `Run-Token`, none without it; `post` the path; `body` as JSON or
`raw` as text; the `status` and `answer` it must get), an `advance` of the
clock, a `sweep` and how many executions it abandons, an `approve` of a
captured approval id, or requests sent `together`, whose `answers` may come
in any order. In a body, `{"$b64": text}` is the base64 of text and
`{"$same": name}` a value captured earlier. In an answer, `"*"` matches any
present value, `{"$capture": name}` captures one, `{"$same": name}` matches a
captured one and `{"$b64": text}` matches bytes; a member not named must be
absent.

`trail.json` lists every event the plane wrote, in order unless `unordered`:
its `kind`, a decision's reason `codes`, a result's `status` and `code` (its
`tool_protocol_status`). A request refused before it was decided writes
nothing.

A receiver in another language builds the plane `setup.json` describes, plays
`exchange.jsonl` against it, compares what it wrote with `trail.json`, then
breaks each rule and watches its case fail.
