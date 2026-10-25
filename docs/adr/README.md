# Architecture decision records

A record states one decision already made and either the check that enforces it
or the change that brings one. Required for a change to authorization
semantics, a public contract, the layout rule, or release and licensing.

To add one: copy `0000-template.md` to the next free number, open the pull
request with `Status: proposed`, and set it to `accepted` when it merges.

| ADR | Decision |
| --- | --- |
| [0001](0001-language-and-toolchain.md) | Go, one compiler version pinned by the `go` directive |
| [0002](0002-wire-contracts-and-versioning.md) | Protobuf is the source of truth; generated Go is committed |
| [0003](0003-policy-model-and-external-pdp.md) | Structured predicates, deny-overrides, external PDP over AuthZEN |
| [0004](0004-evidence-and-privacy-defaults.md) | Metadata by default; content capture is opt-in |
| [0005](0005-canonical-action-digest.md) | One canonical digest identifies an action |
| [0006](0006-product-name-switch.md) | The name is a working name and can be switched |
| [0007](0007-repository-layout-and-dependency-rule.md) | The decision path imports no adapter, storage or server |
| [0008](0008-branching-and-release-policy.md) | Protected `main`, DCO, semver, releases built by CI |
| [0009](0009-open-core-boundary.md) | Everything here is Apache-2.0 and stays open; the site's fonts are under the SIL Open Font License |
| [0010](0010-digest-domain-separation.md) | The digest domain tag is fixed and carries no product name |
| [0011](0011-contract-corrections-before-publication.md) | The v1 contract is corrected once, before it is first published |
| [0012](0012-policy-kernel-semantics.md) | How the built-in policy kernel decides |
| [0013](0013-mcp-interception-approvals-and-modes.md) | The MCP gateway intercepts a call before it happens |
| [0014](0014-evidence-spool-and-sinks.md) | Evidence goes to a local spool first, and the spool decides what blocks |
| [0015](0015-documentation-structure-and-checks.md) | The documentation is a checked structure |
| [0016](0016-approval-providers-and-the-lost-hold.md) | An approver outside the plane answers, and a lost hold is closed |
| [0017](0017-an-external-decision-point-can-veto.md) | An external decision point can veto what the signed policy allows |
| [0018](0018-keys-and-bundles-on-disk.md) | A policy key and a signed bundle each have one format on disk |
| [0019](0019-an-operator-can-pause-calls.md) | An operator can pause calls, and a pause the plane cannot read blocks |
| [0020](0020-a-trail-and-counters-without-a-collector.md) | A plane's trail can land in a local file, and its counters in /metrics |
| [0021](0021-a-run-carries-what-it-took-in.md) | The plane keeps what each run took in, so a flow rule can fire |
| [0022](0022-scenarios-are-data.md) | A scenario is data a live plane is held to |
| [0023](0023-a-local-page-answers-through-the-directory.md) | A local page answers through the directory |
| [0024](0024-control-and-guardana-are-independent.md) | Guardana Control and Guardana are independent |
| [0025](0025-public-repository-merges-and-releases.md) | The admin pushes, maintainers merge and release, a release tag never moves |
| [0026](0026-first-value-and-external-extension-paths.md) | First value and readable evidence come before the supervisor's breadth |
| [0027](0027-expiry-at-hand-out-and-an-unreadable-lost-hold.md) | An approval's expiry holds until the call is handed out, and an unreadable lost hold is unknown |
| [0028](0028-a-stdio-upstream-gets-only-the-environment-it-is-given.md) | A stdio upstream gets only the environment it is given |
| [0029](0029-exact-fractions-in-the-canonical-form.md) | The canonical form accepts a fraction a double holds exactly, and a tool definition any finite number |
| [0030](0030-a-static-website-drawn-from-the-repository.md) | A static website drawn from the repository |
| [0031](0031-the-documentation-is-served-on-the-website.md) | The documentation is served on the website |
| [0032](0032-the-enforcement-mode-has-no-default.md) | The enforcement mode has no default |
| [0033](0033-a-demo-archive-a-release-user-runs-without-go.md) | A demo archive a release user runs without Go |
| [0034](0034-a-run-the-operator-opens-has-an-identity-of-its-own.md) | A run the operator opens has an identity of its own |
| [0035](0035-a-versioned-evidence-export-and-a-bounded-query.md) | A versioned evidence export and a bounded query |
| [0036](0036-policy-explain-reads-the-kernels-own-evaluation.md) | `policy explain` reads the kernel's own evaluation |
| [0037](0037-an-evidence-consumer-in-a-module-of-its-own.md) | An evidence consumer in a module of its own |
| [0038](0038-a-signed-freshness-statement-and-a-serial-floor.md) | A signed freshness statement and a serial floor that outlives the process |
| [0039](0039-many-channels-into-one-core.md) | Many channels into one core: what each may see, claim and do |
| [0040](0040-observations-a-record-a-log-and-one-importer.md) | Observations: a record, a source descriptor, a log and one importer |
| [0041](0041-coverage-per-declared-path.md) | Coverage per declared path |
| [0042](0042-an-answer-that-quotes-a-configured-credential-is-withheld.md) | An answer that quotes a configured credential is withheld |
| [0043](0043-a-refused-over-long-name-is-recorded-by-its-digest.md) | A refused over-long name is recorded by its digest |
| [0044](0044-coverage-judges-each-plane-and-joins-only-a-whole-export.md) | Coverage judges each plane and joins only a whole export |
| [0045](0045-one-run-is-supervised-against-its-procedure.md) | One run is supervised against its procedure |
| [0046](0046-a-finding-stops-one-run-through-a-signed-route.md) | A finding stops one run through a signed route |
| [0047](0047-a-procedure-states-its-exceptions-resources-and-children.md) | A procedure states its exceptions, resources and children |
| [0048](0048-one-run-drawn-as-a-page-and-findings-exported-with-a-cursor.md) | One run drawn as a page, and findings exported with a cursor |
| [0049](0049-the-site-names-the-published-release.md) | The site names the published release |
| [0050](0050-adoption-workflows-preserve-authority-and-evidence.md) | Adoption workflows preserve authority and evidence |
| [0051](0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md) | A tool outside MCP is admitted, completed and aborted through an enforcement API |
| [0052](0052-a-change-is-gated-on-its-pull-request.md) | A change is gated on its pull request, and releases keep a rhythm |
| [0053](0053-a-python-client-of-the-enforcement-api-in-this-repository.md) | A Python client of the enforcement API lives in this repository |
| [0054](0054-the-enforcement-receiver-holds-a-lock-beside-its-socket.md) | The enforcement receiver holds a lock beside its socket |
| [0055](0055-a-call-is-handed-out-only-while-its-policy-stands.md) | A call is handed out only while the policy it was decided under stands |
| [0056](0056-a-coding-runtimes-hooks-reach-the-plane-through-one-bridge.md) | A coding runtime's hooks reach the plane through one bridge, by value |
| [0057](0057-an-external-mcp-client-runs-the-guide-on-every-pull-request.md) | An MCP client outside the Go SDK runs the guide on every pull request |
| [0058](0058-a-copy-an-import-never-read-is-doubt-for-the-runs-it-claimed.md) | A copy an import never read is doubt for the runs it claimed |
| [0059](0059-a-tools-classification-is-one-type-checked-when-it-loads.md) | A tool's classification is one type, checked when it loads |
| [0060](0060-pkg-contract-exports-what-each-effect-class-requires.md) | `pkg/contract` exports what each effect class requires |
| [0061](0061-an-obligations-parameters-are-the-catalogues.md) | An obligation's parameters are the catalogue's |
