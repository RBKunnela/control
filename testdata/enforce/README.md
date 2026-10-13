# Conformance cases for the enforcement API

The cases of [ADR-0051](../../docs/adr/0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md),
as files any language can run; the record wins where they disagree.

`cases.json` lists each case's side, contract version, rule and negative
control, a defect that must fail it. `go test ./internal/enforceclient/` runs
the client cases and answer vectors against two clients;
[receiver/](receiver/README.md) holds the receiver cases.

## A client case

`client/<case>/call.json` is the call: tool, proposed arguments as text, run
token, optional `deadline_ms`, and `tool_does`: a status and times, or
nothing; or the error `timed_out` (effect unknown), `context` with
`cancel_caller`, or `not_sent` (never reached).

`answers.jsonl` is the receiver's script, one answer per request in order:
`for`, `status`, and `body` as JSON or `raw` as text. A request to another
path, or past the script, gets 400 `ERROR_CODE_MALFORMED`. `then` acts first:
`cancel_caller` cancels the caller; `await_caller` expires its deadline, then
answers.

`expect.json` holds whether the tool was reached and the bytes it got; every
request, in order, carrying `Run-Token`; the abort cause or completion status;
and `returns`: `none`, `blocked`, `pending`, `refused`, `aborted`,
`not_recorded`, `malformed_answer` or `tool_error`. A body is decoded strictly
and compared as protojson writes it; `"*"` matches any present value; a member
not named must be absent.

## Answer vectors

`answers/vectors.jsonl` holds one answer a line:

```
{"id": "<unique>", "for": "admit" | "complete" | "abort", "status": 200, "raw": "<the body>",
 "raw_repeat": [{"text": "<a part>", "times": 3}],    <- in place of raw: the parts, joined
 "class": "read" | "refused" | "may_refuse",
 "expect": {"tool_reached": true, "tool_received": "<text, if reached>",
            "requests": ["admit", "complete" | "abort"], "returns": "<as above>",
            "code": "<declared ERROR_CODE_, if any>", "ending": "<declared ENDING_, if any>"}}
```

Each is one call: `refund`, `{"amount":10,"to":"acct-7"}`, `run-token-1`, a
tool reporting `COMPLETION_STATUS_SUCCESS`. An `admit` vector answers the
admit; later requests get 200 `{"ending":"ENDING_RECORDED"}`. `complete` and
`abort` vectors follow the admit answers of `execute-plain` and
`unknown-obligation`. A 3xx carries `Location: /enforce/v1alpha1/admit`.

`read` and `refused`: every client behaves as `expect`. `may_refuse`: a client
other than the reference may return `malformed_answer` and send nothing more.

## Another language

Serve a Unix socket that answers from the script and records each request,
call with a tool doing what `tool_does` says, and compare. Then break each
rule and watch its case fail.
