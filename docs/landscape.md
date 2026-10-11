# Landscape: building blocks and standards

AgentGov is deliberately thin: it composes projects that already do one job well. This
page records which projects were considered, why the current ones were chosen, and the
standards the platform aligns with. Survey date: October 2026.

## Building blocks

| Need | Chosen | Why | Considered |
|---|---|---|---|
| Agent identity | **Keycloak** (Apache-2.0, CNCF incubating) | Per-agent confidential clients via the Admin REST API; RFC 8693 token exchange GA since 26.2; federated client authentication (Kubernetes / SPIFFE tokens) for secretless agents; experimental MCP authorization-server support | ZITADEL (AGPL-3.0 since v3, token exchange beta), Ory Hydra, SPIRE (complementary: workload identity on Kubernetes) |
| Policy decisions | **OPA** (Apache-2.0, CNCF graduated) | Largest install base; bundles, long polling, decision logs and status built in; the Agent Governance Toolkit can query it remotely, so one policy library serves gateway and in-process enforcement | Cedar (agent momentum: AWS AgentCore Policy, ToolHive; analyzable; needs glue at the gateway), Cerbos (AuthZEN) |
| MCP enforcement | **agentgateway** (Apache-2.0, Linux Foundation / Agentic AI Foundation) | Tracks the MCP spec (2026-07-28 support since 1.4.1); JWT auth; CEL; an MCP-aware external policy protocol (`ExtMcp`) that can rewrite and reject requests and results; A2A and LLM routes; OTel | Agent Router (formerly Envoy AI Gateway; Kubernetes only), IBM ContextForge, Docker MCP Gateway, microsoft/mcp-gateway (session-based routing, obsoleted by stateless MCP) |
| Personal data detection | **Presidio** (MIT) | Established analyzer with offsets for redaction; runs offline. Started at Microsoft, now maintained by the community-led Data Privacy Stack organisation (images on GHCR) | LLM Guard (archived July 2026), LlamaFirewall (stale), NeMo Guardrails (possible future addition for ML checks) |
| Telemetry | **OpenTelemetry Collector** | Vendor-neutral, speaks the GenAI semantic conventions that Agent 365 also uses | — |
| Trace UI (optional) | **Langfuse** (MIT core) | Understands GenAI spans out of the box and accepts OTLP directly; optional because self-hosting adds ClickHouse, Redis and S3-compatible storage | Arize Phoenix (ELv2, not OSI), Grafana Tempo/Loki (AGPL, semconv-agnostic) |
| Object storage for Langfuse (optional) | **SeaweedFS** (Apache-2.0) | Officially supported by Langfuse; its single-process `mini` mode suits the reference stack. In production, use a managed bucket | MinIO (AGPL-3.0; the community edition no longer ships images or security fixes), Garage (AGPL-3.0) |
| In-process enforcement (optional) | **Microsoft Agent Governance Toolkit** (MIT) | Framework adapters for Agent Framework, LangGraph, CrewAI, OpenAI Agents SDK, ADK, … | — |
| Harmful-content classifier (optional) | **IBM Granite Guardian** 4.1 (Apache-2.0) | Judges text against built-in risk criteria (harm, jailbreak, social bias, violence, unethical behaviour) and criteria you write; open weights under an OSI licence; GGUF builds run on a CPU with llama.cpp | Llama Guard and Prompt Guard (Llama licence, not OSI), ShieldGemma (Gemma terms), NeMo Guardrails (a framework around such models rather than a model) |

### What we did not reuse, and why

The Agent Governance Toolkit (AGT 5.0.0) also ships content detectors and an MCP scanner.
We evaluated them for the gateway path and wrote our own instead:

* Its credential redactor and response scanner have regular expressions with super-linear
  worst cases (about 6–9 seconds on 50 KB of crafted input); a gateway must not be slowed
  by its own input.
* Its tool-poisoning scanner missed the classic hidden `<IMPORTANT>` attack in our tests
  and is not thread-safe.
* Pulling the package into the gateway path adds about 40 dependencies for roughly a
  thousand lines of regular expressions.

AGT remains the recommended in-process layer; see [policies.md](policies.md#in-process-enforcement-with-the-agent-governance-toolkit).
Its ideas (invisible Unicode, hidden comments, fake control tags, exfiltration URLs,
definition fingerprints) informed our detectors, which are bounded and linear-time.

### Registry projects

No open-source project provides an agent inventory bound to runtime enforcement: owner and
sponsor, identity client, gateway route and policy, with approval, attestation, expiry and
deprovisioning. AGNTCY's Agent Directory (OASF records, signed, federated) has no owner or
lifecycle model; the official MCP Registry covers MCP servers only; Backstage provides
ownership and a UI but no enforcement. This gap is the reason AgentGov exists.

## Standards

* **MCP 2026-07-28.** Stateless: no sessions, no `initialize`, no GET stream; per-request
  `_meta`; `server/discover`; required `Mcp-Method` / `Mcp-Name` headers; multi
  round-trip requests; `ttlMs` / `cacheScope` on list results. Authorization: OAuth 2.1
  resource server, RFC 9728 protected-resource metadata, RFC 8707 resource indicators,
  no token passthrough. AgentGov decides on the parsed body (headers can be spoofed when
  a client falls back to an older revision) and marks per-agent tool lists `private`.
  [Changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
* **A2A v1.0.0.** Agents may carry an A2A agent card (`name`, `description`, `version`,
  `supportedInterfaces`, `capabilities`, `skills`, …), and those that serve A2A are called
  through agentgateway's A2A routes, which point their cards at the gateway; the
  governance processor decides each JSON-RPC request (`SendMessage`, `GetTask`, …) as
  agentgateway's external authorization ([agent to agent](agent-to-agent.md)).
  [Specification](https://a2a-protocol.org/latest/specification/)
* **OpenTelemetry GenAI semantic conventions.** `gen_ai.operation.name`
  (`invoke_agent`, `execute_tool`, `chat`, …), `gen_ai.agent.id/name`,
  `gen_ai.tool.name`, `gen_ai.usage.*`. Still at Development stability.
  [Agent spans](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md)
* **Agent identity.** IETF WIMSE `draft-ietf-wimse-aims` recommends one workload identity
  per agent with short-lived credentials, RFC 8693 for delegation, and treats static API
  keys as an anti-pattern. OpenID AuthZEN 1.0 is final; a COAZ MCP binding is in draft.
* **OWASP Top 10 for Agentic Applications (2026).** Controls in AgentGov map to:
  ASI01 Goal Hijack (indirect injection withheld), ASI02 Tool Misuse (grants, approvals),
  ASI03 Identity & Privilege Abuse (per-agent identity, least privilege, risk-based access),
  ASI04 Supply Chain (tool server review, definition pinning, poisoning detection),
  ASI07 Insecure Inter-Agent Communication (calls between agents only through the gateway,
  who may call whom, signed delegations), ASI08 Cascading Failures in part (loops refused,
  at most five agents in a chain), ASI10 Rogue Agents (kill switch, discovery, auto-block).
  ASI05, ASI06 and ASI09 need controls outside the call path (sandboxing, memory integrity,
  human-agent trust) and are on the roadmap or out of scope.
* **Regulation.** The EU AI Act as amended by the Digital Omnibus (Regulation (EU)
  2026/1744) postpones Annex III high-risk obligations to 2 December 2027; Article 12
  logging and Articles 19 / 26(6) retention (at least six months) are what the evidence
  ledger is designed to support. NIST AI RMF and ISO/IEC 42001 call for the same
  inventory, oversight and record-keeping evidence.
