# ADR-0061: An obligation's parameters are the catalogue's

Status: accepted
Date: 2026-10-24

Amends [ADR-0012](0012-policy-kernel-semantics.md) on what a policy document
an author signs may say about an obligation.

## Context

A rule names an obligation by a type of the catalogue in
`internal/policy/rules` and gives it string parameters. The parser held a
parameter's key to the envelope's rule for a map key and its value to the
rule for a string, and nothing more: the catalogue was a list of type names.
What each type reads lived with its applier, in a table in
`internal/gateway/rewrite.go` and another in `adapters/mcp/obligations.go`,
which is policy meaning held in an adapter. The reference page read the
parameters out of those two tables.

So a document could sign and load with a parameter no applier reads, a
missing one, or a value no applier parses, and the author learned of it only
from a denied call, or never, when the obligation was advisory. The signed
samples showed it: one capped an amount with a `currency` nothing reads, and
others gave `cap_rate`, which nothing in the tree applies, a `per_minute`.

## Decision

The catalogue states each type's parameters. An entry is the type, its
parameters, each with a name, whether it is required and the grammar of its
value, and, for a type that needs one of several, the set of which one must
be present. `rules.Obligations` returns it and `rules.ParamNames` gives one
type's names.

| Type | Parameter | Required | Value |
| --- | --- | --- | --- |
| `redact_fields` | `fields` | yes | comma-separated member names, each non-empty, without `.`, `/` or white space |
| `cap_amount` | `max` | yes | a base-10 integer in 64 bits, with an optional sign |
| `cap_amount` | `field` | no | any string, the exact name of one top-level member |
| `restrict_resources` | `ids` | one of `ids`, `prefix` | comma-separated ids, none empty, each one the identifier rule admits |
| `restrict_resources` | `prefix` | one of `ids`, `prefix` | an identifier; its last `/`-separated segment printable ASCII without `%`, `;`, `?`, `#` or `\` |
| `shorten_timeout` | `ms` | yes | a base-10 integer from 1 to 9223372036854 |

`read_only`, `deny_external_sink` and the five types nothing in this build
applies take no parameters. A parameter of a type nobody applies is an
instruction nobody follows; the applier that comes for one of them declares
its parameters here first.

`rules.CheckObligations` holds a parsed document to the catalogue. It refuses
a parameter the type does not declare and a missing required one with
`ErrObligationParam`, and a value outside its grammar with
`ErrObligationValue`, naming the rule and the parameter's position, never its
key or value. `policy.Sign` calls it and refuses such a document with
`ErrObligationParams`, so every path that signs refuses it: `policy sign`,
which runs the check before it opens the key, `policy test`, and
`guardana-gateway dev`, which signs the bundle it runs. `policy lint` runs it
too. `rules.Parse` and `policy.Load` do not: a bundle that is already signed
loads as before, and its applier decides at run time as before, a
non-advisory obligation it cannot apply denying the call with
`OBLIGATION_NOT_UNDERSTOOD` and an advisory one skipped. `policy explain` is a
diagnostic of what a plane would decide, so it explains every document a
plane loads: it signs its case's document in memory without the check, and
loads it as a plane does.

A grammar is the set of values its applier acts on as written, read from what
the applier parses, not from a reading of the parameter's name. So `max` and
`ms` take a sign and leading zeros, which `strconv.ParseInt` reads, and
`field` takes any string, which the gateway looks up as written. An `ids`
entry that is empty, or that the identifier rule refuses, is refused although
the adapter applies the rest of the list: it skips the first and can never
match the second, since every envelope's resource id passes that rule. A
`prefix` whose last segment holds a byte the adapter refuses below a prefix is
refused, since no id under it can pass.

The appliers refuse a parameter outside `rules.ParamNames` and keep parsing
the values themselves; their own parameter tables are gone. The reference
page renders from `rules.Obligations`, with a row for each parameter.

## Security / compatibility impact

No decision changes, and no bundle that loaded is refused: the check runs only
where a document is signed or linted. A document that signed before is
refused by `policy lint`, `policy test`, `policy sign` and
`guardana-gateway dev` when it holds a
parameter its type does not declare, a parameter on any type that takes
none, a missing `fields`, `max` or `ms`, a `restrict_resources` with neither
`ids` nor `prefix`, or a value outside its grammar. Each of those was an
obligation its applier would not apply as written, or a parameter nobody
read.

`policy lint` exiting 0 still means the document would sign and load. The
converse no longer holds: a document lint refuses for a parameter can still
load from a bundle signed elsewhere.

## Alternatives considered

- Check in `Parse`, so `Load` refuses too: a bundle signed before would stop
  a plane from starting, for a parameter its applier already refuses call by
  call.
- Keep the tables with the appliers: the meaning of a policy's words stays
  in an adapter, and a second applier of one type can read different
  parameters with nothing to hold them equal.
- Take the obvious reading of each name for its grammar, a `max` without a
  `+` or a `field` without a `.`: the check would refuse values the applier
  applies, and a lint that disagrees with what runs teaches an author to
  ignore it. Tightening an applier is a change of what runs, decided on its
  own.

## Consequences

An author learns of a parameter the tree does not apply when linting or
signing, from the rule and the position. A new parameter, or a type that
gains an applier, is declared in the catalogue first, and the page follows
from it. A grammar and its applier are two readings of one rule: parsing a
value stays with its applier, as decided above, and a property test in each
applier's package holds the two together.

## Validation

- `internal/policy/rules`: refusal cases beside the twin each differs from by
  one parameter (an undeclared parameter, a case variant of a declared one, a
  parameter on `read_only` and on `cap_rate`, a missing `max`, `fields` and
  `ms`, a bad `ms`, a `restrict_resources` with neither), each grammar at the
  values on either side of its rules, the catalogue refused with a parameter
  that has no grammar, and a document the check refuses that still parses.
- `internal/policy`: `Sign` refuses both classes with `ErrObligationParams`,
  and `Load` takes the same document signed without the check.
- `cmd/guardana-control`: `policy lint` names the refusal, `policy sign`
  refuses before it opens the key, `policy test` refuses a case whose
  document holds a `cap_rate` with `per_minute`, and `policy explain`
  explains the same case; explain's signer returns `Sign`'s bundle for every
  document `Sign` accepts.
- `cmd/guardana-gateway`: `dev` refuses that document as its `--policy`.
- `internal/gateway` and `adapters/mcp`: a property test that any value the
  grammar accepts, the applier applies, and a test that each applier's
  parameter names are `rules.ParamNames`.
- `internal/docscheck`: the reference page is what the renderer makes of the
  catalogue, its Parameter column holds `rules.ParamNames` for each type, and
  the renderer refuses a catalogue that gives parameters to a type nothing
  applies.
