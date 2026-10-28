# An evidence report from the export

A program outside the plane that reads an export and prints a row per
request, then totals: the action, the kernel's verdict and codes, the block,
the hold, and how approval and action ended. It imports only the wire
contract.
[Read the evidence from a program](../../docs/guides/read-the-evidence-from-a-program.md)
shows both modes.

`block` is the decision `ACTION_BLOCKED` carries, beside the kernel's: `=`
when its `decision_id` is the kernel's, else its own verdict and
codes, as `DENY PAUSED`, or `-`.

```
go -C examples/evidence-report build -o "$PWD/bin/" .
<gateway> trail export <state>/trail.jsonl | bin/evidence-report
```

It exits 0 only when every request ended on an unbroken chain of one run the
plane allows and the export was whole. A request is `blocked`, `completed` only on
success, `aborted` when nothing was sent, `failed` on a failure,
`uncertain` on a timeout or an unknown outcome, otherwise `unknown`: the
effect may have happened, as with a run under an enforcing mode against its
decision. Anything unknown, uncertain, open or missing exits 1, as does an
export over 100 000 records or 64 MiB; a usage error, 2.

## Following a trail

```
bin/evidence-report -state s -init
after=$(bin/evidence-report -state s -cursor)
<gateway> trail export ${after:+--after="$after"} trail.jsonl | bin/evidence-report -state s
```

One run at a time reads the next export, logs each new alert to
`s/alerts.jsonl` as a JSON line, `"v":1`, `experimental`, and to stderr after
`evidence-report: alert`, then prints requests that ended. Exit 1 is a new alert. Exit 2 leaves
`state.json` unchanged unless only its last sync failed; logged alerts stay, not raised again, and
rows may print again.

## What it cannot see

- A record the plane quarantined never reaches the file: inside a chain it
  shows as `unknown` or `open`, after a trail's end it leaves the row
  complete, and as a request's first it hides that request.
- `prev_event_id` orders records; it does not show one altered.
- It reads no effect class, so a material run under `APPROVE` or `LOCKDOWN`
  is not told from a read.
- A filtered or cut export can split a request.
