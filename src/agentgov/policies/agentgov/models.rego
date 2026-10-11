# Decisions for model calls passing through agentgateway (/llm/<provider>).
#
# The governance processor queries data.agentgov.models.decision for each prompt
# (phase "request") and each answer (phase "response").
#
# Input:
#   kind:       "model"
#   phase:      "request" | "response"
#   agent:      {"agent_id", "client_id"}      (from the validated JWT)
#   user:       the person the agent acts for, if any (see agentgov.context)
#   chain:      who handed the work down to the agent, when another agent did
#               (see agentgov.a2a): [{"type": "person" | "agent", "id", "name"}]
#   provider:   the model provider's name in the registry
#   model:      the model the agent asked for
#   detections: {"categories": ["pii","secret"], "entities": [...],
#                "prompt_injection": bool, "injection_score": number,
#                "jailbreak": bool, "jailbreak_score": number}
#               (prompt_injection: in the tool results the conversation holds;
#               jailbreak: in its latest message from the user role)
#   tool_calls: true when the conversation holds tool calls or tool results
#
# Identity, lifecycle and the registry always apply; the controls apply as their
# features say (see agentgov.mcp). Organisation policies under agentgov.custom.*
# take part through deny (always) and redact (as data-protection); they can tell
# model calls from tool calls by input.kind == "model".
package agentgov.models

import data.agentgov.context as ctx

phase := object.get(input, "phase", "request")

detections := object.get(input, "detections", {})

categories contains c if some c in object.get(detections, "categories", [])

provider := data.registry.model_providers[input.provider]

model_id := sprintf("%s/%s", [input.provider, object.get(input, "model", "")])

# ---------------------------------------------------------------------------
# Always applied.
# ---------------------------------------------------------------------------

deny contains "Caller is not a registered agent" if not ctx.agent

deny contains msg if {
	ctx.agent.status != "active"
	msg := sprintf("Agent %s is %s", [ctx.agent.name, ctx.agent.status])
}

deny contains msg if {
	not provider
	msg := sprintf("Model provider %q is not registered", [input.provider])
}

deny contains msg if {
	provider.status != "approved"
	msg := sprintf("Model provider %s is %s", [provider.name, provider.status])
}

deny contains msg if {
	some name
	some msg in data.agentgov.custom[name].deny
}

# ---------------------------------------------------------------------------
# Controls.
# ---------------------------------------------------------------------------

# Granted by the agent's blueprint, its own model access, or an access package it holds.
model_granted if ctx.model_granted(input.provider, object.get(input, "model", ""))

violation contains {"control": "least-privilege", "message": msg} if {
	phase == "request"
	ctx.agent.status == "active"
	not model_granted
	msg := sprintf("Model %s is not granted to agent %s", [model_id, ctx.agent.name])
}

# Access packages: a model only an expired package grants.
violation contains {"control": "access-packages", "message": msg} if {
	phase == "request"
	ctx.agent.status == "active"
	names := ctx.expired_model_grants(input.provider, object.get(input, "model", ""))
	count(names) > 0
	msg := sprintf("Model %s was granted to agent %s by access package %s, which has expired", [model_id, ctx.agent.name, concat(", ", sort(names))])
}

violation contains {
	"control": "data-protection",
	"message": "The prompt contains credentials; they must not be sent to a model provider",
} if {
	phase == "request"
	"secret" in categories
}

# An answer is withheld rather than masked: answers can arrive as a stream.
violation contains {
	"control": "data-protection",
	"message": "The model's answer contained credentials and was withheld",
} if {
	phase == "response"
	"secret" in categories
}

# Masking rewrites the conversation as text, which would drop its tool calls.
violation contains {"control": "data-protection", "message": msg} if {
	phase == "request"
	input.tool_calls == true
	some category in to_mask
	category in categories
	msg := sprintf("Personal data in this conversation must be masked before it goes to %s, but masking would break its tool calls", [input.provider])
}

violation contains {
	"control": "prompt-injection",
	"message": "A tool result in the conversation contains instructions aimed at the agent (possible prompt injection)",
} if {
	phase == "request"
	detections.prompt_injection == true
}

violation contains {
	"control": "jailbreak-detection",
	"message": "The prompt looks like a jailbreak: it tries to set aside the model's instructions or safety rules",
} if {
	phase == "request"
	detections.jailbreak == true
}

violation contains {"control": "acting-for-people", "message": msg} if {
	phase == "request"
	ctx.agent.status == "active"
	some msg in ctx.person_refusals
}

violation contains {"control": "risk-based-access", "message": msg} if {
	ctx.agent.risk_level == "critical"
	msg := sprintf("Agent %s is critical risk (score %d) and is blocked until investigated", [ctx.agent.name, ctx.agent.risk_score])
}

violation contains {"control": "token-budgets", "message": msg} if {
	phase == "request"
	ctx.agent.over_budget == true
	msg := sprintf("Agent %s has used its daily budget of %d tokens", [ctx.agent.name, ctx.agent.daily_token_budget])
}

deny contains v.message if {
	some v in violation
	ctx.enforced(v.control)
}

# ---------------------------------------------------------------------------
# Masking personal data in prompts, the data-protection control.
# ---------------------------------------------------------------------------

# Personal data must not leave for providers that have not been verified.
to_mask contains "pii" if {
	phase == "request"
	"pii" in categories
	provider.trust_level != "verified"
}

to_mask contains category if {
	phase == "request"
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

effect := "deny" if count(deny) > 0

else := "allow"

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
	"reasons": sort(deny),
	"redact": sort(redact),
	"monitored": sort(monitored),
	"agent": agent_summary,
}
