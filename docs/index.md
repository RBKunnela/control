---
title: Documentation
summary: Every page, grouped by the question it answers, and every decision record.
type: project
covers: [docs/**]
generated: scripts/gen-index.go
---

# Documentation

Rendered from every page's own frontmatter and from the records. Rebuild it
with `make docs-gen`; an edit made here does not survive the next run.

## Get started

- [Try the demo](get-started/try-the-demo.md): Start a plane in front of two vulnerable MCP servers, answer a held call, pause a server, read the trail and the counters, and run the demo's scenarios.

## Guides

- [Connect an existing MCP setup](guides/connect-an-existing-mcp-setup.md): Put the plane between an MCP client and a server you already use, classify the server's tools, hold its writes for approval, and end in a local report.
- [Decide a tool of your own](guides/decide-a-tool-of-your-own.md): Serve the enforcement API, classify your tools by name, and have a client ask before each call and report how it ended, under one policy and trail.
- [Keep two tasks apart](guides/keep-two-tasks-apart.md): Open a run per task in a runs directory, point a plane at it, and give each agent its token, so what one task took in never decides another's calls.
- [Let a decision point veto calls](guides/let-a-decision-point-veto.md): Point the gateway at an AuthZEN decision point, write the two rules that let it veto a scope, test what each answer does, and check the plane before it serves.
- [Read the evidence from a program](guides/read-the-evidence-from-a-program.md): Export a trail file in the versioned format, resume where the last export stopped, and rebuild each call's lifecycle without importing the project's internals.
- [Run the gateway in a container](guides/run-in-a-container.md): Run the release image of the gateway with Docker, with its evidence on a volume and its port reachable from the host alone.
- [Run the gateway](guides/run-the-gateway.md): Set up a plane's policy files, start the MCP gateway in OBSERVE, keep its policy confirmed, read its health, classify the tools it sees, and move it to ENFORCE.
- [Supervise and stop a run](guides/supervise-and-stop-a-run.md): Run the refund example by hand on a live plane, supervise the run against its procedure, read its page, and stop it on a confirmed finding.
- [Test a procedure](guides/test-a-procedure.md): Lint a procedure document, then prove what supervise finds with cases that state a run, its evidence and every expected finding.
- [Watch a plane without a collector](guides/watch-a-plane-without-a-collector.md): Run the collector the gateway binary ships, point a plane's export at it, and check each request's trail in the file it writes.
- [Write and test a policy](guides/write-and-test-a-policy.md): Write an agent-policy/v1alpha1 document, lint it, prove what it decides with cases, sign it into the bundle a plane loads, and vouch that the bundle is current.

## Concepts

- [Approvals and the held request](concepts/approvals-and-the-held-call.md): What the enforcement point holds when a call needs an approval, what a retry must equal to resume it, and the ways a hold ends.
- [Architecture](concepts/architecture.md): The system in context, its containers, the request path from a proposed action to a decision and its evidence, the dependency rule, and where it is going.
- [Control and supervision](concepts/control-and-supervision.md): The 1.0 goal for connected observation, procedure checks and scoped reactions, with today's alpha and the three API roles kept explicit.
- [Enforcement modes](concepts/enforcement-modes.md): What each mode does with the kernel's decision, what it needs from an adapter, and which modes this build runs.
- [Evidence and the spool](concepts/evidence-and-the-spool.md): The trail every call leaves, the order its events may take, and how the spool keeps them on disk before an exporter sees them.
- [Glossary](concepts/glossary.md): One name per concept, as the pages and the code use it, with the symbol or path that defines each.
- [How a call is decided](concepts/how-a-call-is-decided.md): From a proposed action to one of five verdicts and the action enforced for it, including what happens when the kernel cannot decide.
- [The MCP gateway](concepts/mcp-gateway.md): How a tools/call becomes a decision, an authorized set of bytes and a trail, before the server sees it.
- [Observations, coverage, supervision and a stop](concepts/observations-coverage-and-supervision.md): How what a source reports, the coverage map, the supervisor's findings and a stop of one run fit together, and what each promises and does not.
- [Privacy](concepts/privacy.md): What the plane records about a call, where each record goes and who can read it, how long it stays, and that nothing goes to the project.
- [Threat model](concepts/threat-model.md): What the plane protects, from whom, what it does about each attacker today with the code and the test behind it, and where it stops.

## Reference

- [Benchmarks](reference/benchmarks.md): What three calls on the authorization path and one tool call through the gateway cost on one machine, how they are measured, and what the numbers are not.
- [Claude Code hooks](reference/claude-code-hooks.md): What the claude-code hook profile covers, the hook settings it needs, what the bridge reads and answers per event, and the gaps it leaves.
- [Command line](reference/cli.md): The two binaries, what each prints as its help, and the exit statuses they share.
- [Configuration](reference/configuration.md): Every key the gateway reads, with its environment variable, kind, default, whether it is required and the spellings it takes.
- [The approvals page](reference/console.md): What guardana-control console serves, what it prints, what it refuses and what it cannot tell you.
- [Coverage](reference/coverage.md): What guardana-control coverage reads, the inventory it takes, the state it gives each declared path, the join with a plane's evidence, and its exit status.
- [Dev mode](reference/dev.md): What guardana-gateway dev lays out, refuses, prints and stops, and how --scenario runs each scenario on a plane of its own.
- [Failure modes](reference/failure-modes.md): What a plane does when its collector, spool, decision point, upstream, pause file, stop list, freshness statement or clock fails, or it is killed holding calls.
- [MCP enforcement coverage](reference/mcp-coverage.md): Per revision, transport and method, what the gateway enforces today and what it does not.
- [Metrics](reference/metrics.md): Every metric a plane answers on /metrics, with its type, its label, the statistic it reads and what it counts.
- [Obligations](reference/obligations.md): The catalogue of obligation types a policy rule may name, and what the tree does with one.
- [Observations](reference/observations.md): The source descriptor, what an import of OpenTelemetry GenAI spans keeps and drops, the observation log and its export.
- [Policy explain](reference/policy-explain.md): What `guardana-control policy explain` reads, every line it prints, which rule decided and which input a rule could not read, and its bounds.
- [Policy document format](reference/policy-format.md): Every member of an agent-policy/v1alpha1 document, the values each admits, the bounds, and the members of a policy test case.
- [Reaction](reference/reaction.md): The signed route, the stop list and the commands that write them, and how a plane refuses a stopped run's calls and reports its stops.
- [Reason codes](reference/reason-codes.md): Every reason code a decision may carry, with its number and the verdict it usually accompanies.
- [Run view](reference/run-view.md): The page guardana-control supervise --view draws for one run, what each mark on it means, and what the command refuses to overwrite.
- [Runs](reference/runs.md): The runs directory, what runs open, close and list print and refuse, and what a plane with runs.dir does with a token.
- [Scenario format](reference/scenario-format.md): Every member of an agent-scenario/v1alpha1 document, how scenario run holds a live plane to one, and what it exits with.
- [Starter policy packs](reference/starter-packs.md): The read-only and approval-for-writes packs, what each decides, what it assumes about the plane, the cases that prove it, and what it leaves unguarded.
- [Supervision](reference/supervision.md): The procedure document, what guardana-control supervise checks for one opened run, the finding record and its log, and how notify delivers findings.
- [Format versions](reference/versions.md): Every versioned file and message a user writes or reads, the version this tree writes, the versions it reads, and how stable each is.
- [action_envelope.proto](reference/wire/action_envelope.md): The messages and enums of action_envelope.proto as the compiled descriptor declares them, each field with its number, cardinality and type.
- [approval.proto](reference/wire/approval.md): The messages and enums of approval.proto as the compiled descriptor declares them, each field with its number, cardinality and type.
- [bundle.proto](reference/wire/bundle.md): The messages and enums of bundle.proto as the compiled descriptor declares them, each field with its number, cardinality and type.
- [common.proto](reference/wire/common.md): The messages and enums of common.proto as the compiled descriptor declares them, each field with its number, cardinality and type.
- [decision.proto](reference/wire/decision.md): The messages and enums of decision.proto as the compiled descriptor declares them, each field with its number, cardinality and type.
- [event.proto](reference/wire/event.md): The messages and enums of event.proto as the compiled descriptor declares them, each field with its number, cardinality and type.
- [finding.proto](reference/wire/finding.md): The messages and enums of finding.proto as the compiled descriptor declares them, each field with its number, cardinality and type.
- [result.proto](reference/wire/result.md): The messages and enums of result.proto as the compiled descriptor declares them, each field with its number, cardinality and type.

## Specification

- [Wire contracts](contracts.md): What the v1 messages are versioned by, what a receiver refuses them for, and how the evidence events chain.

## Extending

- [Writing an adapter](extending/adapters.md): The internal seam a protocol adapter implements, the capabilities it declares, and the conformance each one owes.
- [Adding a coding runtime's hooks](extending/runtime-profiles.md): The profile a coding runtime's hook protocol is described by, what the hook bridge does with it, and what a profile needs before its page may claim anything.

## Project

- [Adoption and incident workflows](adoption-and-incident-workflows.md): Planned acceptance requirements for MCP setup, coding hooks, tool-definition review, policy simulation and incident review.
- [Delivery backlog](backlog.md): Planned work ordered by user value, with dependencies and observable acceptance checks.
- [Dependencies](dependencies.md): Every direct dependency and pinned tool of the module, why the standard library will not do, its licence and whether it sits in the request path.
- [Implementation status](status.md): What exists in this repository today, component by component, the one inventory every other page points to.

## Decision records

- [ADR-0001: Go, one pinned compiler version](adr/0001-language-and-toolchain.md): accepted
- [ADR-0002: Protobuf contracts, generated code committed](adr/0002-wire-contracts-and-versioning.md): accepted
- [ADR-0003: Structured predicates, deny-overrides, external PDP over AuthZEN](adr/0003-policy-model-and-external-pdp.md): accepted
- [ADR-0004: Evidence defaults to metadata; content capture is opt-in](adr/0004-evidence-and-privacy-defaults.md): accepted
- [ADR-0005: One canonical digest identifies an action](adr/0005-canonical-action-digest.md): accepted
- [ADR-0006: The product name is a working name and can be switched](adr/0006-product-name-switch.md): accepted
- [ADR-0007: Repository layout and the dependency rule for the decision path](adr/0007-repository-layout-and-dependency-rule.md): accepted
- [ADR-0008: Protected main, DCO, semver, releases built by CI](adr/0008-branching-and-release-policy.md): accepted
- [ADR-0009: Everything in this repository is Apache-2.0 and stays open](adr/0009-open-core-boundary.md): accepted
- [ADR-0010: The digest domain tag is fixed and carries no product name](adr/0010-digest-domain-separation.md): accepted
- [ADR-0011: Corrections to the v1 contract before it is first published](adr/0011-contract-corrections-before-publication.md): accepted
- [ADR-0012: How the built-in policy kernel decides](adr/0012-policy-kernel-semantics.md): accepted
- [ADR-0013: The MCP gateway intercepts a call before it happens](adr/0013-mcp-interception-approvals-and-modes.md): accepted
- [ADR-0014: Evidence goes to a local spool first, and the spool decides what blocks](adr/0014-evidence-spool-and-sinks.md): accepted
- [ADR-0015: The documentation is a checked structure](adr/0015-documentation-structure-and-checks.md): accepted
- [ADR-0016: An approver outside the plane answers, and a lost hold is closed](adr/0016-approval-providers-and-the-lost-hold.md): accepted
- [ADR-0017: An external decision point can veto what the signed policy allows](adr/0017-an-external-decision-point-can-veto.md): accepted
- [ADR-0018: A policy key and a signed bundle each have one format on disk](adr/0018-keys-and-bundles-on-disk.md): accepted
- [ADR-0019: An operator can pause calls, and a pause the plane cannot read blocks](adr/0019-an-operator-can-pause-calls.md): accepted
- [ADR-0020: A plane's trail can land in a local file, and its counters in /metrics](adr/0020-a-trail-and-counters-without-a-collector.md): accepted
- [ADR-0021: The plane keeps what each run took in, so a flow rule can fire](adr/0021-a-run-carries-what-it-took-in.md): accepted
- [ADR-0022: A scenario is data a live plane is held to](adr/0022-scenarios-are-data.md): accepted
- [ADR-0023: A local page answers through the directory](adr/0023-a-local-page-answers-through-the-directory.md): accepted
- [ADR-0024: Guardana Control and Guardana are independent](adr/0024-control-and-guardana-are-independent.md): accepted
- [ADR-0025: The public repository: who pushes, who merges, who releases](adr/0025-public-repository-merges-and-releases.md): accepted
- [ADR-0026: First value and readable evidence come before the supervisor's breadth](adr/0026-first-value-and-external-extension-paths.md): accepted
- [ADR-0027: An approval's expiry holds until the call is handed out, and an unreadable lost hold is unknown](adr/0027-expiry-at-hand-out-and-an-unreadable-lost-hold.md): accepted
- [ADR-0028: A stdio upstream gets only the environment it is given](adr/0028-a-stdio-upstream-gets-only-the-environment-it-is-given.md): accepted
- [ADR-0029: The canonical form accepts a fraction a double holds exactly, and a tool definition any finite number](adr/0029-exact-fractions-in-the-canonical-form.md): accepted
- [ADR-0030: A static website drawn from the repository](adr/0030-a-static-website-drawn-from-the-repository.md): accepted
- [ADR-0031: The documentation is served on the website](adr/0031-the-documentation-is-served-on-the-website.md): accepted
- [ADR-0032: The enforcement mode has no default](adr/0032-the-enforcement-mode-has-no-default.md): accepted
- [ADR-0033: A demo archive a release user runs without Go](adr/0033-a-demo-archive-a-release-user-runs-without-go.md): accepted
- [ADR-0034: A run the operator opens has an identity of its own](adr/0034-a-run-the-operator-opens-has-an-identity-of-its-own.md): accepted
- [ADR-0035: A versioned evidence export and a bounded query](adr/0035-a-versioned-evidence-export-and-a-bounded-query.md): accepted
- [ADR-0036: `policy explain` reads the kernel's own evaluation](adr/0036-policy-explain-reads-the-kernels-own-evaluation.md): accepted
- [ADR-0037: An evidence consumer in a module of its own](adr/0037-an-evidence-consumer-in-a-module-of-its-own.md): accepted
- [ADR-0038: A signed freshness statement and a serial floor that outlives the process](adr/0038-a-signed-freshness-statement-and-a-serial-floor.md): accepted
- [ADR-0039: Many channels into one core: what each may see, claim and do](adr/0039-many-channels-into-one-core.md): accepted
- [ADR-0040: Observations: a record, a source descriptor, a log and one importer](adr/0040-observations-a-record-a-log-and-one-importer.md): accepted
- [ADR-0041: Coverage per declared path](adr/0041-coverage-per-declared-path.md): accepted
- [ADR-0042: An answer that quotes a configured credential is withheld](adr/0042-an-answer-that-quotes-a-configured-credential-is-withheld.md): accepted
- [ADR-0043: A refused over-long name is recorded by its digest](adr/0043-a-refused-over-long-name-is-recorded-by-its-digest.md): accepted
- [ADR-0044: Coverage judges each plane and joins only a whole export](adr/0044-coverage-judges-each-plane-and-joins-only-a-whole-export.md): accepted
- [ADR-0045: One run is supervised against its procedure](adr/0045-one-run-is-supervised-against-its-procedure.md): accepted
- [ADR-0046: A finding stops one run through a signed route](adr/0046-a-finding-stops-one-run-through-a-signed-route.md): accepted
- [ADR-0047: A procedure states its exceptions, resources and children](adr/0047-a-procedure-states-its-exceptions-resources-and-children.md): accepted
- [ADR-0048: One run drawn as a page, and findings exported with a cursor](adr/0048-one-run-drawn-as-a-page-and-findings-exported-with-a-cursor.md): accepted
- [ADR-0049: The site names the published release](adr/0049-the-site-names-the-published-release.md): accepted
- [ADR-0050: Adoption workflows preserve authority and evidence](adr/0050-adoption-workflows-preserve-authority-and-evidence.md): accepted
- [ADR-0051: A tool outside MCP is admitted, completed and aborted through an enforcement API](adr/0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md): accepted
- [ADR-0052: A change is gated on its pull request, and releases keep a rhythm](adr/0052-a-change-is-gated-on-its-pull-request.md): accepted
- [ADR-0053: A Python client of the enforcement API lives in this repository](adr/0053-a-python-client-of-the-enforcement-api-in-this-repository.md): accepted
- [ADR-0054: The enforcement receiver holds a lock beside its socket](adr/0054-the-enforcement-receiver-holds-a-lock-beside-its-socket.md): accepted
- [ADR-0055: A call is handed out only while the policy it was decided under stands](adr/0055-a-call-is-handed-out-only-while-its-policy-stands.md): accepted
- [ADR-0056: A coding runtime's hooks reach the plane through one bridge, by value](adr/0056-a-coding-runtimes-hooks-reach-the-plane-through-one-bridge.md): accepted
- [ADR-0057: An MCP client outside the Go SDK runs the guide on every pull request](adr/0057-an-external-mcp-client-runs-the-guide-on-every-pull-request.md): accepted
- [ADR-0058: A copy an import never read is doubt for the runs it claimed](adr/0058-a-copy-an-import-never-read-is-doubt-for-the-runs-it-claimed.md): accepted
