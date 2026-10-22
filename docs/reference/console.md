---
title: The approvals page
summary: What guardana-control console serves, what it prints, what it refuses and what it cannot tell you.
type: reference
covers: [cmd/guardana-control/console.go, internal/console/**]
---

# The approvals page

`guardana-control console` serves a page in your browser that lists the
calls held for an approval and answers them, and, with `--pause`, shows,
adds and lifts pauses. It writes exactly what the `approvals` and `pause`
commands write ([cli.md](cli.md)), and it adds no authority: it runs as
whoever starts it, and anyone who can write the approvals directory or the
pause file can already do everything the page does.

```
guardana-control console --approvals <dir> [--pause <f>] --approver-id <id> [--until-stdin-closes]
```

Every answer carries `--approver-id`. It is the starter's claim, recorded as
given; the page has no field that changes it, and nothing authenticates it.
An id the approvals store would refuse, an empty one included, is refused
before the page starts.

## What it prints

It listens on `127.0.0.1` at a port the system picks and prints exactly one
line on stdout:

```
page: http://127.0.0.1:<port>/#t=<token>
```

The token is 32 random bytes in base64url, in the link's fragment, which a
browser never sends to a server. It is good for one trade, within ten minutes
of the start: the page's script sends it once to `/api/session` and receives
a session token of the same strength, which the tab keeps and sends in a
header with every other request. After the trade, or after ten minutes, the
printed token is refused; the ten minutes are counted on the wall clock as
well, so a machine that slept through them does not extend them. The script
takes the token out of the address bar at once; the link may stay in the
browser's history and session files, but what it carries is spent. The session belongs to the tab that traded it and to a
copy of that tab, which a browser makes when a tab is duplicated. A tab that
lost its session, and any other tab, says to start the console command again
and open the link it prints. Nothing else is printed on stdout; diagnostics go to
stderr.

It serves until interrupted. With `--until-stdin-closes` it also stops when
its standard input ends, which lets the process that started it stop it by
closing a pipe. A request still running a second into the stop is dropped.
Either way it exits 0, or 1 when the page or the approvals store cannot be
closed cleanly.

## What it refuses

- A request under any host name but `127.0.0.1:<port>`, so a name that
  resolves to the loopback reaches nothing: 403.
- A trade at `/api/session` without the printed token, or once it was traded
  or is ten minutes old: 401. Any other request to the page's API without the
  session token: 401.
- A request to the page's API, with its token, that the browser says came from
  another origin or another site: 403.
- A write whose body is not `application/json`: 415; one over 4 KiB: 413; one
  that is not valid UTF-8, with a `\u` escape of half a UTF-16 pair that no
  other half completes, with a member the write does not take, a member name
  spelled in another case, a member named twice, or anything after the
  object: 400.
- An answer whose `action_digest` is not the record's: 409, and nothing is
  written. The digest compared is the record's, never the one its projection
  names.
- An answer to an id the store cannot hold, or to a record the listing names
  among its problems, a record file the page cannot open included: 409, in
  the store's own sentence, or for a record the one its problem carries.
- An answer to an id a listing cut short at its bound does not name: 409, saying
  whether it is held is unknown, and nothing is written.
- An answer, and the listing, once the approvals directory changed since the
  page opened it: another directory at its name, another owner, or a group or
  world write bit. An answer is refused with 409 and the listing fails, both
  in the store's own sentence. A plane that finds its directory changed
  refuses it the same way. The page reaches every file through the directory
  it opened, never through its name, so a directory put at the name between
  that check and a read or a write is never read or written.
- Any path but the page, its script and its stylesheet, all built into the
  binary, and `/api/` followed by `session`, `state`, `approve`, `reject`,
  `pause` or `unpause`: 404, under `/api/` only after the session token check.
  It opens no file by a name a request chose.

Every answer, a refusal included, forbids framing, caching and referrers,
cuts the page off from any window that opened it, and allows the page's own
script and stylesheet only, with no inline script.

## How an answer is made

Approve and Reject each take two clicks. The first opens a confirmation in
the card that names the tool, the upstream and the first 12 hex digits of the
action digest; the second sends the answer with that digest, and the page
files it only for the record that carries it. A plane consumes the answer
when the agent retries the call.

Cards keep their place. They are ordered by the time their call was held, a
new one goes after all of them, and none is removed while the page is open: a
card whose call was answered, consumed or closed says so, and one whose
record left the directory says that it did. The answer buttons wait one
second after any change to the list.

## What it shows

What `approvals list` and `pause list` show, and no more: no arguments, no
preview, no trail. The readable fields of a held call come from a projection
and are not bound to the action digest beside them, and the page says so.
Every value from a record, its projection or the pause file is withheld and
quoted as the commands print it: key text becomes `[key text withheld]`, and
a value holding a control, format, bidirectional, line or paragraph separator
character is shown quoted. The page's script also quotes a replaced byte, so
it shows at least what the command line quotes. Every value is set as text,
never as markup.

The words claim no more than the records. An approved call can resume on the
agent's retry before the approval expires; the page never says it ran. A
listing that is not the whole directory is a warning, never an empty list. A
record whose resolution the store cannot give reads "cannot say", and a
listing that failed cannot say whether a plane holds the directory. A pause
file that cannot be read is shown as one under which a plane blocks every
call. A refusal from the store or the pause file is shown in its own words.

## What it cannot tell you

- Whether a plane reads the pause file it writes.
- Whether the readable fields match the call the approval binds.
- Anything about a process running as the same user, which can write the
  directory and the file without the page.

The page's JSON is private to its own script and carries no version: it is
not an interface to build on.
