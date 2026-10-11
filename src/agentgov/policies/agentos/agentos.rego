# In-process enforcement for agents that use the Microsoft Agent Governance
# Toolkit (AGT). AGT 5.0.0 framework adapters configured with
#
#   PolicyEvaluator.add_backend(OPABackend(mode="remote", package="agentos"))
#
# query POST /v1/data/agentos/allow with
#
#   {"agent_id": "<agent name>", "action_type": "tool_call",
#    "tool_name": "<tool>" | "<server>/<tool>", "tool_args": {...}}
#
# and treat only a literal `true` as permission, so this package exposes a
# plain boolean. Plain tool names are in-process functions and are matched
# against grants for the pseudo-server "local".
#
# The agent identity here is self-declared by the agent process. Use the
# gateway (verified tokens) as the enforcement point for anything that must
# hold against a misbehaving agent.
package agentos

import data.agentgov.context as ctx

default allow := false

agent := a if {
	some a in data.registry.agents
	a.name == input.agent_id
} else := data.registry.agents[input.agent_id]

server := s if {
	contains(input.tool_name, "/")
	s := split(input.tool_name, "/")[0]
} else := "local"

tool := t if {
	contains(input.tool_name, "/")
	parts := split(input.tool_name, "/")
	t := concat("/", array.slice(parts, 1, count(parts)))
} else := input.tool_name

granted if {
	some grant in agent.grants
	ctx.matches(grant.server, server)
	some pattern in grant.tools
	ctx.matches(pattern, tool)
}

# The least-privilege and risk-based access controls apply here only when they
# are enforced: the toolkit can't record what a monitored control would do.
allow if {
	input.action_type == "tool_call"
	agent.status == "active"
	not refused_for_risk
	permitted
}

refused_for_risk if {
	ctx.enforced("risk-based-access")
	agent.risk_level == "critical"
}

permitted if granted

permitted if not ctx.enforced("least-privilege")
