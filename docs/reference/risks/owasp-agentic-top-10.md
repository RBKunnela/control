---
title: OWASP Top 10 for Agentic Applications
summary: The 2026 agentic risks, the tests that exercise Guardana Control's controls, the paths around them, and the remaining gaps.
type: reference
covers: [internal/core/decide_test.go, internal/gateway/e2e/**, internal/gateway/decisionpoint_test.go, adapters/mcp/list_test.go, cmd/guardana-gateway/reaction_tree_unix_test.go, examples/vulnerable-mcp-agent/attempts/**]
---

# OWASP Top 10 for Agentic Applications

OWASP published the 2026 edition on 2025-12-09. The identifiers and risk titles come from that edition. Guardana Control maps each risk to the behavior its tests exercise. [OWASP edition page](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) and [published report](https://genai.owasp.org/download/52117/?tmstv=1765059207), read 2026-11-20.

## Risks

The gateway examples use `ENFORCE`. In `OBSERVE`, the gateway records a policy denial and lets the call run. A gap means there is no exercised control for the behavior described. [Threat model][agent].

| Published risk | Exercised control | Test file and function | Known bypass and remaining gap |
| --- | --- | --- | --- |
| ASI01: Agent Goal Hijack | [Model Context Protocol (MCP) gateway][mcp] (`experimental`). A flow rule blocks outbound mail if the run previously read untrusted content and confidential data. This limits one way a steered agent can send data out. | `internal/gateway/e2e/flow_test.go` · `TestTheToxicFlowIsDeniedAcrossSessions`. [B37 mail cases][b37]. | Goal hijacking itself can go undetected. User prompts and tool descriptions fall outside the tracked flow, and a changed goal can lead to a harmful call that policy allows. [Threat model][agent]. |
| ASI02: Tool Misuse and Exploitation | [Model Context Protocol (MCP) gateway][mcp] (`experimental`). A delete denied by policy never reaches the tool server. | `internal/gateway/e2e/call_test.go` · `TestDeniedCallNeverReachesTheUpstream`. [B37 refund case][b37]. | An agent can bypass the gateway by reaching the server directly. It can also misuse a tool that policy allows. [Threat model][agent]. |
| ASI03: Identity and Privilege Abuse | [Decision kernel](../../status.md#decision-kernel) (`implemented`), exercised with delegation chains supplied by a kernel unit test. The kernel denies an expired chain, a cycle, or a child scope wider than its parent's. | `internal/core/decide_test.go` · `TestDelegationRefusalIsABuiltInDeny`. The MCP path is exercised separately in `internal/gateway/e2e/classes_test.go` · `TestEveryEffectClassUnderEveryAnswer`. | The live MCP listener uses its configured principal for every caller and supplies no delegation chain. In `ENFORCE`, a `SPAWN_OR_DELEGATE` call gets `REQUIRED_FIELD_ABSENT` before the delegation check. End-user authentication and enforcement of a caller's delegation chain remain gaps on this path, and no backlog task covers them. [MCP coverage](../mcp-coverage.md#what-the-gateway-cannot-do). |
| ASI04: Agentic Supply Chain Vulnerabilities | [Model Context Protocol (MCP) gateway][mcp] (`experimental`). A tool whose definition changes upstream at run time becomes unclassified until it is classified again. Its call is blocked. | `adapters/mcp/list_test.go` · `TestListChangedRefreshesTheManifest`. | An operator can pin a hostile definition, and server behavior can change behind an unchanged definition. [Threat model][server]. [Tool-definition change review](../../status.md#tool-definition-review) is `planned` in [B25](../../backlog.md). |
| ASI05: Unexpected Code Execution (RCE) | Gap. | No test exercises process containment. | The agent can run code directly, and an allowed tool can execute code on its host. [Host process events](../../status.md#host-process-events) are `planned` in [B35](../../backlog.md) for observation. Host isolation remains a gap. [Threat model][agent]. |
| ASI06: Memory & Context Poisoning | Gap. | No test exercises agent memory integrity. | Injected text in a tool result can reach the agent. No exercised check governs what enters persistent memory or what a later task retrieves. [Threat model][server]. |
| ASI07: Insecure Inter-Agent Communication | Gap. | No test exercises peer authentication or message integrity on an agent-to-agent channel. | Peers can communicate outside the plane. The [Agent-to-agent (A2A) adapter](../../status.md#a2a-adapter) is `planned`. [B16](../../backlog.md) includes adapter conformance. |
| ASI08: Cascading Failures | Gap. OWASP describes a fault that spreads and grows as other agents, tools, or workflows act on it. [ASI08, report p. 30](https://genai.owasp.org/download/52117/?tmstv=1765059207#page=31). | `internal/gateway/decisionpoint_test.go` · `TestSilenceBlocksEveryEffectClassUnderEnforce` checks one authorization at a time. An unanswered external veto blocks the call that needed it. | A wrong result can pass to another agent and trigger further allowed actions. The test exercises neither detection of that spread nor recovery of the affected workflow. [Decision-point limits](../../concepts/threat-model.md#a-decision-point-that-is-slow-wrong-or-hostile). |
| ASI09: Human-Agent Trust Exploitation | [Approval binding](../../status.md#approval-binding) (`implemented`). An approved transfer runs once. A repeated request cannot reuse the approval. | `internal/gateway/e2e/approval_test.go` · `TestPendingApprovalAndItsRetry`. [B37 changed-update case][b37]. | A person can still be persuaded to approve the original harmful transfer. [B38](../../backlog.md) covers showing the exact action to the approver. |
| ASI10: Rogue Agents | [Stopping a run through a signed route](../../status.md#run-stop) (`experimental`). After `supervise` reports a confirmed finding that a child retried a denied call with changed arguments, a signed route can stop later calls by that child. | `cmd/guardana-gateway/reaction_tree_unix_test.go` · `TestAChildsRetryIsSupervisedOverTheTreeAndStopsTheChild`. | The parent can still act. A call already running can finish, and the child can use a path outside the gateway. Continuous checks are work in [B28](../../backlog.md). [Threat model][agent]. |

## What B37 measured

[Controlled attempts counted at the victim](../../status.md#controlled-attempts) (`experimental`) compares the demo victims' journals under `ENFORCE` and `OBSERVE`. The results show which scripted effects reached the victims and the cost to legitimate work, including updates held for approval. A script chose the calls. [B37 results][b37] and [counting method](../../adr/0086-controlled-attempts-are-counted-at-the-victim.md).

[mcp]: ../../status.md#mcp-gateway
[agent]: ../../concepts/threat-model.md#an-agent-that-is-wrong-or-steered
[server]: ../../concepts/threat-model.md#a-hostile-or-compromised-mcp-server
[b37]: ../../guides/count-controlled-attempts.md#2-run-it
