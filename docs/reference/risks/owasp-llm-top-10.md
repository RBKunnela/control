---
title: OWASP Top 10 for LLM Applications
summary: The 2026 LLM risks, tests for effects on connected tools, and gaps in the model, its data, and the application that uses its output.
type: reference
covers: [internal/gateway/e2e/**, internal/gateway/rewrite_test.go, adapters/mcp/withhold_manifest_test.go, examples/vulnerable-mcp-agent/attempts/**]
---

# OWASP Top 10 for LLM Applications

OWASP's release record dates the 2026 edition to 2026-08-04. The download page is dated 2026-08-03. The identifiers and titles below follow the final list. [Release record](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/README.md), [download page](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/), and [edition PDF](https://genai.owasp.org/download/56857/?tmstv=1785822482), read 2026-11-20.

## Risks

Each test verifies a specific effect. For example, a mail server can receive no mail even after the run read untrusted content. The gateway enforcement examples use `ENFORCE`.

| Published risk | Exercised control | Test file and function | Known bypass and remaining gap |
| --- | --- | --- | --- |
| LLM01:2026 Prompt Injection | [Model Context Protocol (MCP) gateway][mcp] (`experimental`). A flow rule blocks outbound mail after the run reads untrusted content and confidential data. This limits one possible effect of an injection. | `internal/gateway/e2e/flow_test.go` · `TestTheToxicFlowIsDeniedAcrossSessions`. [B37 mail cases][b37]. | Injected instructions in a tool result can reach the model. Prompt-injection detection and actions outside the tracked flow remain gaps. [Threat model][server]. |
| LLM02:2026 Sensitive Information Disclosure | [Model Context Protocol (MCP) gateway][mcp] (`experimental`). After reading untrusted content and then confidential data, the run cannot send mail through the tested external mail tool. | `internal/gateway/e2e/flow_test.go` · `TestTheToxicFlowIsDeniedAcrossSessions`. [B37 case with order data in the mail][b37]. | A direct connection can bypass the mail tool. The model can also disclose data in its own reply. [Threat model][agent]. |
| LLM03:2026 Excessive Agency | [Approval binding](../../status.md#approval-binding) (`implemented`). The transfer waits for approval. Once approved, the retried call can run only once. | `internal/gateway/e2e/approval_test.go` · `TestPendingApprovalAndItsRetry`. [B37 changed-update case][b37]. | An overly broad allow rule can admit a harmful call. The operator chooses which actions require approval and which other paths the agent can reach. [Threat model][agent]. |
| LLM04:2026 Supply Chain | Gap. | No test verifies the provenance of a model, training dataset, or model adapter. | Replacing a model artifact can change its behavior without changing a routed tool call. The model is outside the plane. [Threat model][scope]. |
| LLM05:2026 Data and Model Poisoning | Gap. | No test checks training data or model weights for poisoning. | A poisoned model can give a harmful answer without calling a tool. The model and its training are outside the plane. [Threat model][scope]. |
| LLM06:2026 Unbounded Consumption | Gap. | No test enforces a token, inference, or spending budget. | Repeated inference can incur cost without an MCP call. [B42](../../backlog.md) covers usage and cost observations. A spending limit remains a gap. |
| LLM07:2026 Misinformation | Gap. | No test checks whether a model's answer is true. | False text from a tool can reach the model and be repeated to a reader. [Threat model][server]. |
| LLM08:2026 Hidden Context Exposure | [Withholding an answer that quotes a credential](../../status.md#credential-echo) (`experimental`). A tool definition that quotes a scanned credential is withheld from the tool list before it enters model context. | `adapters/mcp/withhold_manifest_test.go` · `TestADefinitionQuotingASecretIsNeverListed`. | A hostile server can disguise a credential. System prompts, private instructions, and secrets supplied by other routes are outside this check. [Threat model][server]. |
| LLM09:2026 Vector and Embedding Weaknesses | Gap. | No test checks vector-store access, embedding integrity, or isolation between users' search results. | An allowed search can retrieve another user's records or a poisoned result. The gateway cannot inspect the server's retrieval process. [Threat model][server]. |
| LLM10:2026 Improper Output Handling | [Model Context Protocol (MCP) gateway][mcp] (`experimental`), for two arguments of one configured transfer tool. OWASP includes validation before model output reaches a backend function. In the test, the server receives `amount` capped from `5000` to `1000` and the `ssn` field is removed. [OWASP mitigation 1, p. 56](https://genai.owasp.org/download/56857/?tmstv=1785822482#page=56) and [obligations](../obligations.md). | `internal/gateway/e2e/call_test.go` · `TestRewritingObligationReachesTheWire` checks the arguments received by the server. `internal/gateway/rewrite_test.go` · `TestRewriteRefusesWhatItCannotApply` checks malformed arguments, including a string in the numeric field. | The test client supplies the arguments. Other fields pass through, and the receiving application controls how it uses them. Safe handling of generated SQL, shell commands, or browser content remains a gap. [Threat model][server]. |

## What B37 measured

[Controlled attempts counted at the victim](../../status.md#controlled-attempts) (`experimental`) checks what the demo's order and mail tools received. The results include legitimate updates held for approval. The fixture uses scripted calls and measures no model output. [B37 results][b37] and [counting method](../../adr/0086-controlled-attempts-are-counted-at-the-victim.md).

[mcp]: ../../status.md#mcp-gateway
[agent]: ../../concepts/threat-model.md#an-agent-that-is-wrong-or-steered
[server]: ../../concepts/threat-model.md#a-hostile-or-compromised-mcp-server
[scope]: ../../concepts/threat-model.md#what-is-in-scope
[b37]: ../../guides/count-controlled-attempts.md#2-run-it
