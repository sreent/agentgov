# Decisions for Copilot Studio agents' tool calls.
#
# With threat detection connected, Copilot Studio asks AgentGov before each tool
# call an agent makes (generative orchestration only). The control plane
# queries data.agentgov.copilotstudio.decision and answers "block" or "allow".
#
# Input:
#   platform:   "copilot-studio"
#   agent:      {"id": registry agent id (absent when AgentGov doesn't know the
#                agent), "platform_id", "environment_id", "tenant_id", "published"}
#   user:       {"id"}                  (the Entra object ID of the agent's user)
#   tool:       {"id", "type", "name", "connector"}  (connector: e.g.
#                "shared_office365", absent for tools that aren't connectors)
#   arguments:  the tool's input values
#   detections: {"categories": ["secret"], "entities": [...],
#                "prompt_injection": bool, "injection_score": number}
#               (from the arguments and the earlier tool results in the plan)
#
# Organisation policies in agentgov.custom.* contribute to deny here as well;
# they can tell these calls apart by input.platform.
package agentgov.copilotstudio

import data.agentgov.context as ctx

registry := data.registry

agent := registry.agents[input.agent.id]

detections := object.get(input, "detections", {})

categories contains c if some c in object.get(detections, "categories", [])

allowlist := object.get(registry, "connector_allowlist", {"active": false, "approved": {}})

# The kill switch: an agent blocked in AgentGov makes no more tool calls.
deny contains msg if {
	agent.status == "blocked"
	msg := sprintf("Agent %s is blocked in AgentGov", [agent.name])
}

deny contains msg if {
	some name
	some msg in data.agentgov.custom[name].deny
}

# The controls an organisation can switch apply as their modes say (see agentgov.mcp).

# The connector allowlist, once it lists a connector: refused, or recorded, as its mode
# says (for this agent, if an exception or its label sets it).
violation contains {"control": "connector-allowlist", "message": msg} if {
	allowlist.active == true
	connector := input.tool.connector
	not allowlist.approved[connector]
	msg := sprintf("Connector %s is not on AgentGov's connector allowlist", [connector])
}

# Risk-based access, as for agents behind the gateway.
violation contains {"control": "risk-based-access", "message": msg} if {
	agent.risk_level == "critical"
	msg := sprintf("Agent %s is critical risk (score %d) and is blocked until investigated", [agent.name, agent.risk_score])
}

violation contains {
	"control": "data-protection",
	"message": "Arguments contain credentials; agents must not send secrets to tools",
} if {
	"secret" in categories
}

# Indirect prompt injection: an earlier tool result tried to give the agent orders.
violation contains {
	"control": "prompt-injection",
	"message": "An earlier tool result contained instructions aimed at the agent (possible prompt injection)",
} if {
	detections.prompt_injection == true
}

deny contains v.message if {
	some v in violation
	ctx.enforced(v.control)
}

monitored contains sprintf("%s: %s", [v.control, v.message]) if {
	some v in violation
	ctx.monitored(v.control)
}

effect := "deny" if {
	count(deny) > 0
} else := "allow"

decision := {
	"effect": effect,
	"allow": effect == "allow",
	"reasons": sort(deny),
	"monitored": sort(monitored),
}
