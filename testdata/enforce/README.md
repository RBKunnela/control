# Conformance cases for the enforcement API

The cases of [ADR-0051](../../docs/adr/0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md),
as files any language can run. Where a file disagrees with the record, the
file is wrong.

`cases.json` lists each case with its side, contract version, rule and
negative control: a client or receiver that breaks the rule, which must fail
the case. `go test ./internal/enforceclient/` runs every client case against
the reference client, and against a second client given each negative
control's defect; [receiver/](receiver/README.md) holds the receiver cases.

## A client case

`client/<case>/call.json` is the call: tool, proposed arguments as text, run
token, an optional `deadline_ms` for the caller, and `tool_does`, what the
tool does when run. It reports a status and times; or `timed_out` (got the
bytes, cannot tell what happened); or `context` with `cancel_caller`
(cancelled while running); or `not_sent` (never reached).

`answers.jsonl` is the receiver's script, one answer per request in order:
`status`, and `body` as JSON or `raw` as text. A request to a path other than
`for`, or past the script, gets 400 `ERROR_CODE_MALFORMED`. `then` acts first:
`cancel_caller` cancels the caller; `await_caller` expires its deadline, then
answers.

`expect.json` holds whether the tool was reached and the bytes it got; every
request in order, each carrying the run token in `Run-Token`; the one abort
cause or completion status; and `returns`, what the call tells its caller:
`none`, `blocked`, `pending`, `refused`, `aborted`, `not_recorded`,
`malformed_answer` or `tool_error`.
A body is decoded strictly as its path's message and compared as protojson
writes it; `"*"` matches any present value, and a member not named must be
absent.

## Another language

Serve a Unix socket that answers from `answers.jsonl` and records each
request. Make the call through your client with a tool that does what
`tool_does` says, then compare with `expect.json`. Then break each rule and
watch its case fail.
