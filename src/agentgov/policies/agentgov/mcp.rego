# Decisions for MCP traffic passing through agentgateway.
#
# The governance processor queries data.agentgov.mcp.decision for each tool
# call (phase "request"), each tool result (phase "response"), and
# data.agentgov.mcp.visible_tools when filtering a tools/list result.
#
# Input:
#   phase:      "request" | "response"
#   method:     MCP method, e.g. "tools/call"
#   agent:      {"agent_id", "client_id", "subject"}  (from the validated JWT)
#   resource:   {"server", "name"}
#   arguments:  tool arguments (request phase)
#   detections: {"categories": ["pii","secret"], "entities": [...],
#                "prompt_injection": bool, "injection_score": number}
#   tools:      [{"name", ...}]                       (tools/list filtering)
#   poisoned:   {"<tool>": [reasons]}                 (tools/list filtering)
#
# Organisation policies live in packages under agentgov.custom.* and may
# contribute to deny, require_approval and redact.
package agentgov.mcp

import data.agentgov.context as ctx

phase := object.get(input, "phase", "request")

detections := object.get(input, "detections", {})

categories contains c if some c in object.get(detections, "categories", [])

resource_id := sprintf("%s/%s", [input.resource.server, input.resource.name])

# ---------------------------------------------------------------------------
# Denials. Any denial wins over approvals and redaction.
# ---------------------------------------------------------------------------

deny contains "Caller is not a registered agent" if not ctx.agent

deny contains msg if {
	ctx.agent.status != "active"
	msg := sprintf("Agent %s is %s", [ctx.agent.name, ctx.agent.status])
}

deny contains msg if {
	not ctx.server
	msg := sprintf("Tool server %q is not registered", [input.resource.server])
}

deny contains msg if {
	ctx.server.status != "approved"
	msg := sprintf("Tool server %s is %s", [ctx.server.name, ctx.server.status])
}

# Least privilege: only tools granted by the agent's blueprint or its own grants.
deny contains msg if {
	phase == "request"
	ctx.agent.status == "active"
	not ctx.granted(input.resource.server, input.resource.name)
	msg := sprintf("%s is not granted to agent %s", [resource_id, ctx.agent.name])
}

# MCP "rug pull": the server changed the tool after it was approved.
deny contains msg if {
	phase == "request"
	ctx.tool.changed == true
	msg := sprintf("%s changed its definition since it was approved; an administrator must review it", [resource_id])
}

deny contains msg if {
	ctx.tool.poisoned == true
	msg := sprintf("%s is quarantined: its description contains hidden instructions", [resource_id])
}

deny contains "Arguments contain credentials; agents must not send secrets to tools" if {
	phase == "request"
	"secret" in categories
}

# Risk-based access, like Conditional Access for risky agents.
deny contains msg if {
	ctx.agent.risk_level == "critical"
	msg := sprintf("Agent %s is critical risk (score %d) and is blocked until investigated", [ctx.agent.name, ctx.agent.risk_score])
}

# Indirect prompt injection: withhold the result instead of passing it to the model.
deny contains "Tool result withheld: it contains instructions aimed at the agent (possible prompt injection)" if {
	phase == "response"
	detections.prompt_injection == true
}

deny contains msg if {
	some name
	some msg in data.agentgov.custom[name].deny
}

# ---------------------------------------------------------------------------
# Human approval.
# ---------------------------------------------------------------------------

require_approval contains msg if {
	phase == "request"
	ctx.annotations.destructiveHint == true
	not ctx.annotations.readOnlyHint == true
	msg := sprintf("%s is marked destructive by its server", [resource_id])
}

require_approval contains msg if {
	phase == "request"
	some name
	some msg in data.agentgov.custom[name].require_approval
}

# ---------------------------------------------------------------------------
# Redaction (data loss prevention). Categories: "secret", "pii".
# ---------------------------------------------------------------------------

redact contains "secret" if "secret" in categories

# Personal data in results is masked unless the agent is entitled to it.
redact contains "pii" if {
	phase == "response"
	"pii" in categories
	ctx.label("pii-access") != "true"
}

# Personal data must not leave for servers that have not been verified.
redact contains "pii" if {
	phase == "request"
	"pii" in categories
	ctx.server.trust_level != "verified"
}

redact contains category if {
	some name
	some category in data.agentgov.custom[name].redact
}

# ---------------------------------------------------------------------------
# Decision.
# ---------------------------------------------------------------------------

effect := "deny" if {
	count(deny) > 0
} else := "require_approval" if {
	count(require_approval) > 0
} else := "allow"

reasons := sort(deny) if {
	effect == "deny"
} else := sort(require_approval) if {
	effect == "require_approval"
} else := []

agent_summary := {
	"id": ctx.agent_id,
	"name": ctx.agent.name,
	"status": ctx.agent.status,
	"risk_level": ctx.agent.risk_level,
} if {
	ctx.agent
} else := null

decision := {
	"effect": effect,
	"allow": effect == "allow",
	"reasons": reasons,
	"redact": sort(redact),
	"agent": agent_summary,
}

# ---------------------------------------------------------------------------
# tools/list filtering: agents only see tools they may call.
# ---------------------------------------------------------------------------

visible_tools contains tool.name if {
	ctx.agent.status == "active"
	ctx.server.status == "approved"
	ctx.agent.risk_level != "critical"
	some tool in input.tools
	ctx.granted(input.resource.server, tool.name)
	not hidden(tool.name)
}

hidden(name) if ctx.server.tools[name].poisoned == true

hidden(name) if input.poisoned[name]

# One query for the processor: who is calling and which tools they may see.
list_view := {"agent": agent_summary, "visible": visible_tools}
