# Fixtures of the claude-code profile

These events are written from the runtime's published hook documentation.
None was recorded from the runtime: they show what the documentation says an
event looks like, not what a release sends. What Claude Code 2.1.303 sent is
judged by the qualification in `../qualification/`. Ids and paths are
scrubbed.

The file name is the case id a claim in `../profile.json` names in
`backed_by`, and `../cases.json` holds what each one must come to.

- `pre-*` that read: an admit of a shell call, a file write, a file edit and a
  question, the integer and depth bounds of a tool input on both sides.
- `post-success`, `post-failure*`: completions, with the interrupt flag true,
  false and absent.
- `post-same-*`: a completion whose input is the admitted one written
  another way (key order, escapes, a number's spelling, white space); the
  plane records it as the call that ran.
- `post-differs-*`: a completion whose input is another value (a member
  added, removed or null, a number written as a string, array order); the
  plane records `EXECUTED_ARGS_MISMATCH`.
- The rest are refused before anything is sent: a member named twice, a
  member name in another case, an input that is null, a string or absent, no
  call id, an event the profile does not name, bytes after the event, and
  invalid UTF-8 (`pre-invalid-utf8.json` holds one byte that is not, on
  purpose).

An event over the profile's 16 MiB bound is built by the test from
`post-success.json` rather than kept here.
