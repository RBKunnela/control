---
title: Which tools check AI agent tool calls against policy?
summary: A comparison of where tool call policies run, how people approve calls, what gets recorded, and how each product is deployed.
type: explanation
covers: [adapters/mcp/**, adapters/enforce/**, internal/core/**, internal/policy/**, internal/gateway/**, internal/approvals/**, internal/evidence/**, internal/spool/**]
---

# Which tools check AI agent tool calls against policy?

Checked against the linked documentation on **2026-11-20**.

Microsoft's agent controls, Policy in Amazon Bedrock AgentCore, Hexgate
and Guardana Control's MCP gateway (`experimental`) can check an agent's
tool call against rules before it runs. The check can run at a gateway,
in the agent's process, or in a service the agent host calls.

| Question | Microsoft's agent controls | Policy in Amazon Bedrock AgentCore | Hexgate | Guardana Control |
| --- | --- | --- | --- | --- |
| Where does the check run? | The agent host sends the proposed call to a managed Azure service. The host applies the decision. [Microsoft overview][ms-overview] | The AWS policy engine checks the request at AgentCore Gateway before it reaches the tool. [AWS policy guide][aws-policy] | The SDK can check inside the agent process. Hexgate also supports remote checks on a self-hosted control plane or Hexgate Cloud. [Platform overview][hex-platform] | The MCP gateway ([`experimental`][guardana-gateway]) decides routed calls before they reach the server in every mode. In `OBSERVE`, it records the decision and forwards the call regardless of that decision, unless a pause or a call it cannot translate blocks it. Enforcing modes can block or hold a call. [Threat model][guardana-threat] Outside MCP, a tool can ask the enforcement API before acting. The client applies the answer, and Guardana Control cannot verify that it did. [Enforcement API receiver (`experimental`)][guardana-enforce] |
| What decides? | Rego rules under the Agent Control Specification. The rules can use input from classifiers or language models. [Microsoft overview][ms-overview] | Cedar rules and Dogwood, a language that supports Cedar rules and can check earlier steps in a session. [AWS authoring guide][aws-authoring] | YAML rules can run in Python or be compiled through Rego into WebAssembly. [Hexgate policy bundles][hex-bundles] | The decision kernel decides each call in a fixed order ([`implemented`][guardana-kernel]). The policy matcher evaluates rules from signed bundles containing `agent-policy/v1alpha1` policy documents ([`implemented`][guardana-matcher]). |
| Can a person approve a held call? | Yes. A denial can include an approval request. The host runs the review workflow and keeps the call blocked pending approval. [Microsoft overview][ms-overview] | A rule can require an earlier human approval on record. The examples show a tool call issued after approval. A workflow that holds and resumes the original call remains unverified. [AWS temporal policy examples][aws-temporal] · [AWS AgentCore FAQ][aws-faq] | Yes. The SDK waits for the application's approval handler, which can ask a person. [Hexgate approval guide][hex-approval] | An operator can approve by command or from a local page ([`experimental`](../status.md#approval-authority)). The approval binds to one exact call and one policy bundle and is used once when the caller retries that call ([`implemented`](../status.md#approval-binding)). |
| What gets recorded? | The service returns a receipt with the policies and versions used. The host records the receipt with the outcome. [Microsoft launch][ms-launch] | CloudWatch gets counts by default. With gateway tracing enabled, it also gets the allow or deny decision, the reason, and the policy IDs that decided it. [AWS policy observability][aws-logs] | The platform stores policy decisions, model usage and refusals of banned agents or users in ClickHouse. In local mode the events stay on the agent's machine. [Hexgate audit trail][hex-audit] | The gateway writes a local evidence log with the decision, policy version and a hash of the result when there is one ([`experimental`](../status.md#evidence-spool)). |
| How is it deployed? | Managed on Microsoft Azure. The calling agent can run on other clouds. [Microsoft launch][ms-launch] | Managed on AWS in supported regions. [AWS release announcement][aws-release] | Run the SDK locally, host the platform yourself, or use managed Hexgate Cloud. The cloud provider is not stated in the Hexgate Cloud docs. [Platform overview][hex-platform] · [Hexgate Cloud docs][hex-cloud] | Self-hosted using Linux or macOS archives or a gateway container image ([`experimental`](../status.md#releases)). Guardana Control offers no hosted service. [Open source, and what may be commercial](../status.md#open-source-and-what-may-be-commercial) |
| What is the licence? | The managed service licence is not stated in the Microsoft overview. [Microsoft overview][ms-overview] | The managed service licence is not stated in the AWS policy guide. [AWS policy guide][aws-policy] | The published code uses the MIT licence. A separate service licence is not stated in the Hexgate Cloud docs. [MIT licence][hex-licence] · [Hexgate Cloud docs][hex-cloud] | Open source ([Apache 2.0][guardana-licence]). |
| What is the release status? | Public preview, announced on 2026-11-18. [Microsoft launch][ms-launch] | Generally available since 2026-03-03. [AWS release announcement][aws-release] | Preview or general availability is not stated in the release notes or cloud documentation. [Hexgate releases][hex-releases] · [Hexgate Cloud docs][hex-cloud] | Alpha. [Implementation status][guardana-status] |

## Microsoft's agent controls

Agent controls is a managed Azure service for evaluating proposed agent
actions and content against policy. Microsoft's launch example shows an
agent host asking Azure for a decision before a tool call.
[Microsoft launch][ms-launch]

## Policy in Amazon Bedrock AgentCore

Policy in Amazon Bedrock AgentCore lets teams set rules for which tools
agents can use and with which inputs. AgentCore Gateway checks the policy
before forwarding the request. [AWS policy guide][aws-policy]

## Hexgate

Hexgate is a Python library with an optional platform for controlling
which tools an agent can use. The library can check calls inside a Python
agent before the tools run.
[Hexgate project docs][hex-project] · [Platform overview][hex-platform]

## Guardana Control

Guardana Control is an open-source AI agent supervision framework in
alpha. Its self-hosted MCP gateway checks routed tool calls against signed
policy in every mode (`experimental`). In `OBSERVE`, it records the policy
decision and forwards the call regardless of that decision, unless a pause or
a call it cannot translate blocks it. Enforcing modes can block a call or
hold it for approval. The project is not a security
boundary. [Implementation status][guardana-status] · [Threat model][guardana-threat]

## Choosing

Choose by where the check runs and who operates it.

- If your tool traffic goes through AgentCore Gateway, AWS can apply
  policy there. [AWS policy guide][aws-policy]
- If you want Azure to evaluate policy and can add a check to the agent
  host, Microsoft runs the service and the host applies the decision.
  [Microsoft overview][ms-overview]
- If you want rules checked inside a Python agent, Hexgate offers local
  evaluation. [Platform overview][hex-platform]
- If you want to run your own gateway in front of MCP servers, Guardana
  Control offers a self-hosted gateway (`experimental`).
  [MCP gateway][guardana-gateway]

[ms-overview]: https://learn.microsoft.com/en-us/azure/foundry/agent-controls/overview
[ms-launch]: https://commandline.microsoft.com/introducing-agent-controls-an-enterprise-control-plane-for-agent-behavior/
[aws-policy]: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html
[aws-authoring]: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-authoring-guide.html
[aws-temporal]: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/example-policies-temporal.html
[aws-faq]: https://aws.amazon.com/bedrock/agentcore/faqs/
[aws-logs]: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-policy-metrics.html
[aws-release]: https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available/
[hex-project]: https://github.com/HexamindOrganisation/hexgate
[hex-platform]: https://docs.hexgate.ai/platform/overview
[hex-cloud]: https://docs.hexgate.ai/platform/hosted
[hex-bundles]: https://docs.hexgate.ai/policy/wasm-bundles
[hex-approval]: https://docs.hexgate.ai/concepts/approval-required
[hex-audit]: https://docs.hexgate.ai/concepts/audit-trail
[hex-licence]: https://github.com/HexamindOrganisation/hexgate/blob/main/LICENSE
[hex-releases]: https://github.com/HexamindOrganisation/hexgate/releases
[guardana-status]: ../status.md
[guardana-gateway]: ../status.md#mcp-gateway
[guardana-enforce]: ../status.md#enforce-receiver
[guardana-kernel]: ../status.md#decision-kernel
[guardana-matcher]: ../status.md#policy-matcher
[guardana-threat]: threat-model.md
[guardana-licence]: ../../LICENSE

