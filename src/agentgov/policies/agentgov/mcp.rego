# Decisions for MCP traffic passing through agentgateway.
#
# The governance processor queries data.agentgov.mcp.decision for each tool
# call (phase "request"), each tool result (phase "response"), and
# data.agentgov.mcp.list_view when filtering a tools/list result.
#
# Input:
#   phase:      "request" | "response"
#   method:     MCP method, e.g. "tools/call"
#   agent:      {"agent_id", "client_id", "subject"}  (from the validated JWT)
#   user:       the person the agent acts for, if any (see agentgov.context):
#               {"id", "username", "email", "groups", "roles", "via"}: via is
#               "delegation", "exchange" or "sign-in"
#   chain:      who handed the work down to the agent, when another agent did
#               (see agentgov.a2a): [{"type": "person" | "agent", "id", "name"}]
#   resource:   {"server", "name"}
#   arguments:  tool arguments (request phase)
#   detections: {"categories": ["pii","secret"], "entities": [...],
#                "prompt_injection": bool, "injection_score": number}
#   tools:      [{"name", ...}]                       (tools/list filtering)
#   poisoned:   {"<tool>": [reasons]}                 (tools/list filtering)
#
# Identity, lifecycle and the registry always apply. The controls an organisation
# can switch (data.registry.features) apply as their mode says: enforced, they
# deny, ask for approval or mask; monitored, they only say in "monitored" what
# they would have done, and the call goes through; off, they don't apply.
#
# Organisation policies live in packages under agentgov.custom.* and may
# contribute to deny (always applied), require_approval (applied as the approvals
# control is) and redact (applied as the data-protection control is).
package agentgov.mcp

import data.agentgov.context as ctx

phase := object.get(input, "phase", "request")

detections := object.get(input, "detections", {})

categories contains c if some c in object.get(detections, "categories", [])

resource_id := sprintf("%s/%s", [input.resource.server, input.resource.name])

# ---------------------------------------------------------------------------
# Always applied. Any denial wins over approvals and redaction.
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

deny contains msg if {
	some name
	some msg in data.agentgov.custom[name].deny
}

# ---------------------------------------------------------------------------
# Controls: what each one would do. They are applied below, as their modes say.
# ---------------------------------------------------------------------------

# Least privilege: only tools granted by the agent's blueprint, its own grants or an
# access package it holds.
violation contains {"control": "least-privilege", "effect": "deny", "message": msg} if {
	phase == "request"
	ctx.agent.status == "active"
	not ctx.granted(input.resource.server, input.resource.name)
	msg := sprintf("%s is not granted to agent %s", [resource_id, ctx.agent.name])
}

# Access packages: a tool only an expired package grants.
violation contains {"control": "access-packages", "effect": "deny", "message": msg} if {
	phase == "request"
	ctx.agent.status == "active"
	names := ctx.expired_tool_grants(input.resource.server, input.resource.name)
	count(names) > 0
	msg := sprintf("%s was granted to agent %s by access package %s, which has expired", [resource_id, ctx.agent.name, concat(", ", sort(names))])
}

# MCP "rug pull": the server changed the tool after it was approved.
violation contains {"control": "tool-integrity", "effect": "deny", "message": msg} if {
	phase == "request"
	ctx.tool.changed == true
	msg := sprintf("%s changed its definition since it was approved; an administrator must review it", [resource_id])
}

violation contains {"control": "tool-integrity", "effect": "deny", "message": msg} if {
	ctx.tool.poisoned == true
	msg := sprintf("%s is quarantined: its description contains hidden instructions", [resource_id])
}

violation contains {
	"control": "data-protection",
	"effect": "deny",
	"message": "Arguments contain credentials; agents must not send secrets to tools",
} if {
	phase == "request"
	"secret" in categories
}

# Who the agent acts for, as its blueprint says.
violation contains {"control": "acting-for-people", "effect": "deny", "message": msg} if {
	phase == "request"
	ctx.agent.status == "active"
	some msg in ctx.person_refusals
}

# Risk-based access, like Conditional Access for risky agents.
violation contains {"control": "risk-based-access", "effect": "deny", "message": msg} if {
	ctx.agent.risk_level == "critical"
	msg := sprintf("Agent %s is critical risk (score %d) and is blocked until investigated", [ctx.agent.name, ctx.agent.risk_score])
}

# Indirect prompt injection: withhold the result instead of passing it to the model.
violation contains {
	"control": "prompt-injection",
	"effect": "deny",
	"message": "Tool result withheld: it contains instructions aimed at the agent (possible prompt injection)",
} if {
	phase == "response"
	detections.prompt_injection == true
}

# Human approval.
violation contains {"control": "approvals", "effect": "require_approval", "message": msg} if {
	phase == "request"
	ctx.annotations.destructiveHint == true
	not ctx.annotations.readOnlyHint == true
	msg := sprintf("%s is marked destructive by its server", [resource_id])
}

violation contains {"control": "approvals", "effect": "require_approval", "message": msg} if {
	phase == "request"
	some name
	some msg in data.agentgov.custom[name].require_approval
}

deny contains v.message if {
	some v in violation
	v.effect == "deny"
	ctx.enforced(v.control)
}

require_approval contains v.message if {
	some v in violation
	v.effect == "require_approval"
	ctx.enforced(v.control)
}

# ---------------------------------------------------------------------------
# Redaction (data loss prevention), the data-protection control.
# Categories: "secret", "pii".
# ---------------------------------------------------------------------------

to_mask contains "secret" if "secret" in categories

# Personal data in results is masked unless the agent is entitled to it.
to_mask contains "pii" if {
	phase == "response"
	"pii" in categories
	ctx.label("pii-access") != "true"
}

# Personal data must not leave for servers that have not been verified.
to_mask contains "pii" if {
	phase == "request"
	"pii" in categories
	ctx.server.trust_level != "verified"
}

to_mask contains category if {
	some name
	some category in data.agentgov.custom[name].redact
}

redact contains category if {
	ctx.enforced("data-protection")
	some category in to_mask
}

# ---------------------------------------------------------------------------
# What monitored controls would have done. The call goes through.
# ---------------------------------------------------------------------------

monitored contains sprintf("%s: %s", [v.control, v.message]) if {
	some v in violation
	ctx.monitored(v.control)
}

monitored contains sprintf("data-protection: would mask %s", [category]) if {
	ctx.monitored("data-protection")
	some category in to_mask
	category in categories
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
	"monitored": sort(monitored),
	"agent": agent_summary,
}

# ---------------------------------------------------------------------------
# tools/list filtering: agents only see tools they may call.
# ---------------------------------------------------------------------------

visible_tools contains tool.name if {
	ctx.agent.status == "active"
	ctx.server.status == "approved"
	not refused_for_risk
	not refused_for_person
	some tool in input.tools
	may_see(tool.name)
	not quarantined(tool.name)
}

refused_for_risk if {
	ctx.enforced("risk-based-access")
	ctx.agent.risk_level == "critical"
}

# The agent may call no tool for this person (or without one).
refused_for_person if {
	ctx.enforced("acting-for-people")
	count(ctx.person_refusals) > 0
}

# Monitored or off, least privilege hides nothing: agents may call every tool. Nor do
# expired access packages, unless they are enforced.
may_see(name) if ctx.granted_in_force(input.resource.server, name)

may_see(name) if {
	ctx.granted(input.resource.server, name)
	not ctx.enforced("access-packages")
}

may_see(_) if not ctx.enforced("least-privilege")

quarantined(name) if {
	ctx.enforced("tool-integrity")
	poisoned(name)
}

poisoned(name) if ctx.server.tools[name].poisoned == true

poisoned(name) if input.poisoned[name]

# One query for the processor: who is calling and which tools they may see.
list_view := {"agent": agent_summary, "visible": visible_tools}
