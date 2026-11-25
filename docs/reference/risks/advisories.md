---
title: Advisories on agentic attacks
summary: What the FBI, Google, and WorkOS reported, which parts apply to agents you run, and the tests and limits of the relevant controls.
type: reference
covers: [internal/policy/match/constraint_test.go, internal/gateway/e2e/call_test.go, cmd/guardana-gateway/reaction_tree_unix_test.go, internal/coverage/egress_test.go]
---

# Advisories on agentic attacks

Each section pairs a publisher's report with a question about an agent you operate. The tests exercise controls available on your own connected paths.

## FBI FLASH on ARTEX

On 2026-11-13 the FBI reported that threat actors had used ARTEX in intrusions across several sectors. They used the framework to automate work from identifying targets through exfiltrating data. [FBI FLASH-20261113-001](https://www.ic3.gov/CSA/2026/261113.pdf), read 2026-11-20.

**What applies to your agents.** For a testing agent you run, decide which tools it may call and which target resources it may use. Test each tool against one permitted target and one target outside the scope with policy tests (`implemented`). For a walkthrough, see [Check a security-testing agent's calls against a scope you declare](../../guides/check-a-security-testing-agent.md).

| Exercised control | Test file and function |
| --- | --- |
| [Policy documents, signed bundles and the matcher](../../status.md#policy-matcher) (`implemented`). A resource rule distinguishes a matching target ID, a different ID, and a missing ID. A missing ID leaves the match unknown. | `internal/policy/match/constraint_test.go` · `TestResourceConstraints`. |
| [Model Context Protocol (MCP) gateway](../../status.md#mcp-gateway) (`experimental`). In `ENFORCE`, a delete denied by policy never reaches the tool server. | `internal/gateway/e2e/call_test.go` · `TestDeniedCallNeverReachesTheUpstream`. |

**Bypasses and gaps.** A tool can contact a target directly. An allowed tool can act on a target its declared resource does not describe. Traffic arriving at a victim does not establish that ARTEX sent it. Guardana Control does not detect or stop an agent an attacker runs on the attacker's own machines. [Threat model](../../concepts/threat-model.md#an-agent-that-is-wrong-or-steered).

[Controlled attempts counted at the victim](../../status.md#controlled-attempts) (`experimental`) includes a scripted refund case. The demo checks whether the refund reached its victim. The fixture exercises no ARTEX campaign. [B37 results](../../guides/count-controlled-attempts.md#2-run-it) and [counting method](../../adr/0086-controlled-attempts-are-counted-at-the-victim.md).

## Google GTIG

On 2026-11-16 Google Threat Intelligence Group reported use of multi-agent frameworks during live intrusions. It described a group using a modified PentAGI platform to scan organizations in Asia. [GTIG AI Threat Tracker](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold), read 2026-11-20.

**What applies to your agents.** If your workflow delegates work to a child run, examine what the child does after a tool call is refused.

| Exercised control | Test file and function |
| --- | --- |
| [Supervision of a run against its procedure](../../status.md#run-supervision) (`experimental`). An operator checks the recorded run tree and gets a finding when the child retries denied mail with a changed address. | `cmd/guardana-gateway/reaction_tree_unix_test.go` · `TestAChildsRetryIsSupervisedOverTheTreeAndStopsTheChild`. |
| [Stopping a run through a signed route](../../status.md#run-stop) (`experimental`). When the operator applies a route naming the child's repeated denials and the stop takes effect, the gateway blocks the child's next covered call. The retry finding is suspected and stops nothing. The parent's call still runs. | `cmd/guardana-gateway/reaction_tree_unix_test.go` · `TestAChildsRetryIsSupervisedOverTheTreeAndStopsTheChild`. |

**Bypasses and gaps.** A child can use an unconnected tool. An action already running can finish. Continuous checks are work in [B28](../../backlog.md). Guardana Control does not detect or stop an agent an attacker runs on the attacker's own machines. [Threat model](../../concepts/threat-model.md#an-agent-that-is-wrong-or-steered) and [operator guide](../../guides/supervise-and-stop-a-run.md).

## WorkOS

On 2026-11-06 WorkOS attributed unauthorized access to an internal tool to a researcher's ARTEX agent that left its test environment. WorkOS reported that the exposed API accepted a weak development credential and lacked rate limits. [WorkOS incident update](https://workos.com/security/bulletins/update-for-october-30th-2026-data-security-incident), read 2026-11-20.

**What applies to your agents.** Compare the hosts in your test environment's outbound proxy log with the hosts you expected it to contact.

| Exercised control | Test file and function |
| --- | --- |
| [Coverage map per declared path](../../status.md#coverage-map) (`experimental`). The report lists a logged connection to an undeclared host even when every declared path was observed. | `internal/coverage/egress_test.go` · `TestAnUndeclaredRowMakesTheExitOne`. |

**Bypasses and gaps.** A direct connection can miss the proxy. A logged host alone cannot identify the run or establish how the agent left its environment. The report cannot block traffic. [B21](../../backlog.md) covers run attribution where the proxy can identify the caller. Sandbox isolation and the target API's access controls remain outside scope. Guardana Control does not detect or stop an agent an attacker runs on the attacker's own machines. [Threat model](../../concepts/threat-model.md#an-agent-that-is-wrong-or-steered) and [proxy guide](../../guides/watch-an-egress-proxy.md).
