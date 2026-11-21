# ADR-0042: An answer that quotes a configured credential is withheld

Status: accepted
Date: 2026-10-05

Amends [ADR-0013](0013-mcp-interception-approvals-and-modes.md): upstream wire
errors still pass through with their own code, but no longer with their own
message and data when either quotes a credential the plane sends. Builds on
[ADR-0004](0004-evidence-and-privacy-defaults.md) and
[ADR-0028](0028-a-stdio-upstream-gets-only-the-environment-it-is-given.md).

## Context

The plane calls each upstream as itself, with credentials the operator
configured: the userinfo and query of an HTTP upstream's endpoint, the
variables a command upstream receives, and the headers and proxy credentials
of the decision point and the exporter. The agent never holds them: that is
what lets the plane stand between the agent and the upstream.

An upstream's answers reach the agent. ADR-0013 passes a wire error's code,
message and data through, and a tool's result as the upstream wrote it. An
upstream that echoes what it was sent, such as a 401 page quoting the request
URL, a stack trace printing its environment, or a debug tool returning its
configuration, hands the agent the plane's credential for that upstream, and
the agent can then call the upstream around the plane. Under ADR-0028 a command
upstream can read the plane's files and process environment, so it can echo
another upstream's credential too.

## Decision

**One set of secrets for the plane.** Two kinds:

- A credential by where it is configured. These are the password of an
  endpoint's or a proxy's userinfo (the user name when there is no password),
  the `Authorization: Basic` token the HTTP client builds from that userinfo,
  and the values of `pdp.headers.*` and `export.headers.*`. Proxies include
  `pdp.proxy` and the proxy variables the HTTP client reads. These are matched
  whatever their length.
- A value that may be one. These are the query values of an upstream's
  endpoint and the values of the variables listed in a command upstream's
  `env`, other than the few every command receives anyway (`PATH`, `HOME` and
  their like), whose values ordinary answers quote. They are matched from 8 bytes. `guardana-gateway doctor` names each
  shorter one by its key, never its value, as not scanned.

Query keys, the fragment (never sent), a command's arguments and the endpoint's
path are not in the set. One set serves every upstream: an upstream's answer is
withheld for any upstream's credential, not only its own.

**The spellings.** The scan decodes the answer and reads every key, every
string and the text of every number. Each is read as written; again after
percent-decoding (`%xx` in either case, and `+` as a space); again after
undoing the escapes of a JSON string held as text, which catches any mix of
escaped and plain characters; and after both, in either order. In each, it
looks for every secret:

- raw;
- JSON-escaped, as a string holding JSON text would carry it: the standard
  escape, the HTML-safe `\u003c` form, `\/`, and non-ASCII as `\uXXXX`;
- in base64, standard and URL alphabets, at each of the three byte alignments,
  by the part of its encoding no neighbouring byte changes, when that part is
  at least 8 characters.

A number written with a fraction or an exponent that denotes an integer is
also read as that integer's digits, as a JSON reader would print it back,
when the integer has at most 400 digits, however long the number is written. The Basic token is a secret of its own, so it is found as
written, and so is the credential after the scheme of an `Authorization` or
`Proxy-Authorization` header, each as the HTTP client sends it.

**Where it runs.** On a `tools/call`, `resources/read` or `prompts/get`, the
scan runs after the upstream answered and before the closing record is written.
It reads the encoding that is hashed for the record, or the error's message and
data. It also runs on each item of a forwarded resource, template or prompt
list, and on each tool definition when the manifest is refreshed. Its verdict
has three values: clean, found, or not scanned. Not scanned is the zero value,
and it withholds like found. An answer that does not encode, or error data that
does not parse, is not scanned. The scan runs in every mode, `OBSERVE`
included: it changes no decision, only what the agent is shown.

**What the agent sees instead.** A fixed answer, never the upstream's with the
secret masked, marked as the plane's own by `answer: withheld` under the
product's `_meta` namespace (stripped from what an upstream sends, like every
key there). On a `tools/call` it also carries the trail's ids:

- A `tools/call` the upstream answered with a success becomes a result whose
  text says the call ran, its answer was withheld, and calling again repeats
  its effect. Its `isError` is false, unless the tool declares an output
  schema, which no fixed answer meets; then it is true, and the text is the
  same.
- A tool result with `isError` stays an error result, with the fixed text.
- A wire error keeps its code; its message is fixed, and its data is the mark,
  with the ids on a `tools/call`.
- A `resources/read` or `prompts/get` success becomes the JSON-RPC error
  `-31103`, since those results cannot say `isError`.
- A forwarded list with one such item fails whole with `-31103`, as it does
  today when one upstream fails.
- A tool definition with a secret is never classified and never listed, under
  any shaping, and the manifest refresh's log says why. A call to it by name
  is unclassified, which every mode but `OBSERVE` blocks; in `OBSERVE` it runs,
  and its answer is scanned like any other.

**What the record keeps.** The closing record's `status` and `result_hash`
stay the upstream's. The effect happened or not, and the hash ties the record
to the bytes the upstream sent. `tool_protocol_status` becomes `withheld:`
followed by what it would have been, such as `withheld:ok` or
`withheld:jsonrpc:-32603`. A mismatch between the authorized and the sent
bytes still overwrites it with `EXECUTED_ARGS_MISMATCH`, which says more. The
plane counts withheld answers. It logs each with the request id, the matched
secret's configuration key and the spelling found, never the text.

**Where the code lives.** `internal/secretscan` holds the spellings and the
scan. It is pure and protocol-neutral. `gatewayconfig` lists the secrets with
their keys and kinds, the command resolves the variables' values, and
`adapters/mcp` applies the verdict. The adapter refuses a configuration
without a secret set, as it refuses one without a clock: a forgotten wiring
would otherwise turn the scan off unseen. An empty set is allowed.

Amended in 0.19: a name an agent calls is withheld from the record too. A
`tools/call` tool name, a `prompts/get` name or a `resources/read` URI that
quotes a configured credential, cannot be scanned, or starts with
`withheld:sha256:` is recorded as `withheld:sha256:` followed by the
lower-case hex SHA-256 of the name as sent, in the action's name and, for a
read, the resource's id. The upstream still receives the name as called. A
name the agent spells with the prefix is digested again, so a withheld name on
the record is never one the agent wrote. A policy reads the withheld form in
every mode, so a rule that names the tool or the resource does not match the
call. The digest is unsalted, as `overlong:sha256:` is
([ADR-0043](0043-a-refused-over-long-name-is-recorded-by-its-digest.md)): it
ties the record to a name someone already holds, and reveals the name to
whoever can guess it.

## Security / compatibility impact

This is a tripwire for an upstream that echoes what it was sent, not a
guarantee. An upstream that means to give its credential away can spell it in
hex, change its case, reverse it, split it across fields, or wrap or
compress its base64. A credential the plane
does not hold, or one in the endpoint's path, is not known to the scan, and a
configured value that is not valid UTF-8 is never found inside a JSON string,
whose decoding replaces the invalid bytes.

A false match withholds an answer that held no credential. The effect still
happened, the record says so, and the agent is told not to repeat it. That is
why the floor applies to values that may not be credentials, and why the
command's arguments, which name directories and ports, are left out. A
credential shorter than 8 bytes is matched anyway, so it withholds every
answer that merely holds it; `doctor` names each one by its key.

Withholding is also an answer. An agent that can make an upstream echo text
it chose, through an error that quotes a missing name or a tool that returns
what it was given, learns from whether the echo comes back withheld whether a
guess is one of the plane's credentials, and by halving a list of guesses it
can find one in a few calls. The set is the plane's, so this reaches every
credential in it. The scan does not hide that; each withheld answer is a
warning in the log naming the matched key and is counted in
`adapter_answers_withheld_total`, which is how an operator sees it happen.
A short or common credential is the one such guessing finds first.

The wire contract does not change. `tool_protocol_status` is a string whose
values the adapter already writes; `withheld:` is a new prefix, documented with
the others. No reason code is spent: the registry holds a decision's codes, and
a withheld answer has no decision of its own. A reader that knows only
`status` still reads the effect correctly.

The hash of an answer holding a weak credential, if the rest of the answer can
be guessed, lets whoever holds the evidence test guesses offline. The hash was
already recorded before this decision; the record keeps it so the result can
still be tied to its bytes.

## Alternatives considered

- **Mask the secret in place.** The rest of the answer stays readable, but one
  missed spelling leaks, and the context around a mask often says what it hid.
- **Always `isError: true`.** A model reads it as a failure and may call
  again, repeating an effect that already happened.
- **Always `isError: false`.** A client that checks a declared output schema
  refuses a success without structured content, which no fixed answer can
  supply.
- **A scan where the answer is shaped.** The record is written before that,
  so it could not say the answer was withheld.
- **A yes-or-no verdict.** "No" would mean both clean and could not scan.
- **A set per upstream.** A command upstream can read the plane's other
  credentials.
- **The floor for every secret.** A short password would never be matched.
- **Refusing a short value at load.** `?v=2` is a version, not a credential.
- **A reason code for the withholding.** The registry is closed over what a
  decision says, and a protected number would be spent on what is not a
  decision.
- **Scanning the shaped tool list.** One tool would empty every principal's
  list; refusing the whole refresh would drop the upstream.

## Consequences

An operator who configures a credential in an endpoint, a header or a variable
gets this protection without a setting, and sees in `doctor` which values are
too short to scan. A value that appears in normal answers, such as a variable
holding `production`, withholds those answers; there is no switch to exempt it
yet. Every answer is decoded once more before it is sent.

## Validation

- An upstream echoing each kind of secret in each spelling: in a tool result's
  text, its structured content, an object key, `_meta`, a resource blob, a wire
  error's message, and its data as an object, a string and an array. Also in a
  `resources/read`, a `prompts/get`, each forwarded list and a tool definition.
  Each answer is withheld and the record is marked.
- A withheld success is recorded as a success with `withheld:ok` and the
  upstream's hash.
- An answer that cannot be scanned is withheld, never delivered.
- A configuration without a secret set is refused.
- In `OBSERVE` the answer is withheld too.
- An upstream that sends `answer: withheld` itself loses the key.
- A short query or variable value is not matched, and `doctor` names its key.
- A command's directory argument in every answer withholds nothing.
