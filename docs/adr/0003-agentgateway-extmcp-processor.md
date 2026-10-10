# ADR 0003: Enforce MCP traffic in agentgateway through an ExtMcp processor

Status: accepted (2026-10-09)

## Context

Tool-call governance needs to see arguments and results, rewrite them (redaction, list
filtering), refuse them, and park some calls for human approval. agentgateway offers
three hooks: CEL rules (`mcpAuthorization`, in-process, no external state), `extAuthz`
(HTTP-level allow/deny), and `mcpGuardrails` processors of kind `remote`, which speak the
`ExtMcp` gRPC protocol at the MCP method layer and may pass, mutate or reject both
requests and responses.

## Decision

Generate one agentgateway route per registered MCP server with `jwtAuth` (Keycloak) and an
`mcpGuardrails` remote processor (fail-closed) for `tools/call`, `tools/list`,
`resources/read` and `prompts/get`. The processor (this repository) inspects content,
queries OPA, handles approvals and records decisions. Per-agent tool-list filtering is
done in the processor, so the gateway configuration only changes when servers change.

## Consequences

* All policy logic stays in OPA; the gateway config is small and regenerated rarely.
* The processor is on the data path: it must be fast (bounded, linear-time scanning) and
  highly available (stateless, horizontally scalable); failures deny.
* agentgateway converts request-side rejections of tool calls into `isError` tool results
  carrying only the message text, so machine-readable details (such as approval ids) are
  also written into that text.
* The response message carries no request parameters; the processor returns the call
  context as metadata on the request side and agentgateway hands it back on the
  response side (`mcpGuardrails` CEL variable).
