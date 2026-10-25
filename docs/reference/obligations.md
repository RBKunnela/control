---
title: Obligations
summary: The catalogue of obligation types a policy rule may name, the parameters each takes, and what the tree does with one.
type: reference
covers: [internal/policy/rules/catalogue.go, internal/policy/rules/obligations.go, internal/gateway/rewrite.go, adapters/mcp/obligations.go, internal/docscheck/obligationdoc/**]
generated: scripts/gen-obligations.go
---

# Obligations

An obligation is a condition on a call that proceeds. It travels on a
decision in `Decision.obligations`, under `ALLOW_WITH_OBLIGATIONS` and
under `REQUIRE_APPROVAL` once the approval is given. A policy rule names an
obligation by its type, with string parameters and an `advisory` flag that
is false by default: false means the call proceeds only if the obligation is
applied ([ADR-0011](../adr/0011-contract-corrections-before-publication.md)).

The table below is the catalogue, the closed set of types a policy document
may name, with the parameters each type takes and who in this build applies
it. Recognising a type is `implemented`: the parser and `policy lint` refuse
a document naming a type outside it, and the kernel refuses a configuration
whose applicable types include one outside it. The gateway rewrites the
arguments for its types before the decision it records, and an adapter
applies the types it declares to the call it sends. A decision carrying a
non-advisory obligation that nothing here applies is `DENY` with
`OBLIGATION_NOT_UNDERSTOOD`, and no fail-open setting relieves that; an
advisory one is skipped.

Checking parameters is `implemented`: `policy lint`, `policy test`,
`policy sign` and `guardana-gateway dev` refuse a parameter the type does
not declare, a required one that is missing, and a value outside the
grammar its row states
([ADR-0061](../adr/0061-an-obligations-parameters-are-the-catalogues.md)).
A type nothing in this build applies takes no parameters. The first two
refusals read
`rules: a parameter the obligation's type does not declare or requires`,
at `rules[0].obligations[0].params[1].key` for a key or at
`rules[0].obligations[0].params` for one missing, and the third
`rules: a parameter value the obligation's type cannot apply`, at
`rules[0].obligations[0].params[0]`: a parameter is named by its position in
sorted key order, never by its key or value. `policy explain` and loading a
bundle do not check parameters, so a bundle signed elsewhere still loads and
is explained. Its applier reads only the parameters the type declares and
parses each value itself, and an obligation it cannot apply as written is
not applied: a non-advisory one stops the call and an advisory one is
skipped. What is built and what is not is in [status.md](../status.md).

Rendered from the catalogue in `internal/policy/rules/catalogue.go` and the
types the gateway and the MCP adapter declare. Rebuild it with
`make docs-gen`; an edit made here does not survive the next run.

| Type | Applied by | Parameter | Required | Value |
| --- | --- | --- | --- | --- |
| `redact_fields` | the gateway | `fields` | yes | comma-separated top-level member names, each non-empty and without `.`, `/` or white space |
| `read_only` | the MCP adapter | none |  |  |
| `restrict_resources` | the MCP adapter | `ids` | one of `ids`, `prefix` | comma-separated resource ids, none empty and each one the identifier rule admits |
| `restrict_resources` | the MCP adapter | `prefix` | one of `ids`, `prefix` | an identifier whose last `/`-separated segment is printable ASCII without `%`, `;`, `?`, `#` or `\` |
| `require_idempotency_key` | `planned`: nothing in this build | none |  |  |
| `cap_amount` | the gateway | `max` | yes | a base-10 integer that fits in 64 bits, with an optional sign |
| `cap_amount` | the gateway | `field` | no | the exact name of one top-level member |
| `cap_rate` | `planned`: nothing in this build | none |  |  |
| `require_sandbox` | `planned`: nothing in this build | none |  |  |
| `second_approver` | `planned`: nothing in this build | none |  |  |
| `emit_alert` | `planned`: nothing in this build | none |  |  |
| `shorten_timeout` | the MCP adapter | `ms` | yes | a base-10 integer from 1 to 9223372036854 |
| `deny_external_sink` | the MCP adapter | none |  |  |
