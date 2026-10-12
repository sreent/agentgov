# Identity assertions (ID-JAG) for MCP servers outside the gateway: whether AgentGov gives
# an agent, acting for a person or on its own, an assertion it trades at the server's
# authorization server for an access token (agentgov.identity.assertions). The server is
# outside the gateway, so this is the only check AgentGov makes on the agent's access to
# it: the calls it then makes go straight to the server.
#
# Input:
#   agent:    {"agent_id", "client_id"}  (from the token AgentGov checked)
#   user:     the person the agent acts for, if any (see agentgov.context)
#   resource: {"server": <tool server name>}
#   scope:    the scopes asked for, if any
#
# Identity, lifecycle and the registry always apply. The controls an organisation can
# switch apply as their mode says, as they do to tool calls: least privilege (the agent
# needs a grant on the server), access packages, acting for people and risk-based access.
package agentgov.idjag

import data.agentgov.context as ctx

server_name := input.resource.server

deny contains "Caller is not a registered agent" if not ctx.agent

deny contains msg if {
	ctx.agent.status != "active"
	msg := sprintf("Agent %s is %s", [ctx.agent.name, ctx.agent.status])
}

deny contains msg if {
	not ctx.server
	msg := sprintf("Tool server %q is not registered", [server_name])
}

deny contains msg if {
	ctx.server.status != "approved"
	msg := sprintf("Tool server %s is %s", [ctx.server.name, ctx.server.status])
}

# A grant on the server: some tool of it.
grants_server(grants) if {
	some grant in grants
	ctx.matches(grant.server, server_name)
	count(grant.tools) > 0
}

granted if grants_server(ctx.agent.grants)

granted if {
	some p in ctx.packages
	grants_server(object.get(p, "grants", []))
}

granted_in_force if grants_server(ctx.agent.grants)

granted_in_force if {
	some p in ctx.packages
	not ctx.expired(p)
	grants_server(object.get(p, "grants", []))
}

violation contains {"control": "least-privilege", "effect": "deny", "message": msg} if {
	ctx.agent.status == "active"
	not granted
	msg := sprintf("No tool of %s is granted to agent %s", [server_name, ctx.agent.name])
}

violation contains {"control": "access-packages", "effect": "deny", "message": msg} if {
	ctx.agent.status == "active"
	granted
	not granted_in_force
	names := {p.name |
		some p in ctx.packages
		ctx.expired(p)
		grants_server(object.get(p, "grants", []))
	}
	msg := sprintf("%s was granted to agent %s by access package %s, which has expired", [server_name, ctx.agent.name, concat(", ", sort(names))])
}

violation contains {"control": "acting-for-people", "effect": "deny", "message": msg} if {
	ctx.agent.status == "active"
	some msg in ctx.person_refusals
}

violation contains {"control": "risk-based-access", "effect": "deny", "message": msg} if {
	ctx.agent.risk_level == "critical"
	msg := sprintf("Agent %s is critical risk (score %d) and is blocked until investigated", [ctx.agent.name, ctx.agent.risk_score])
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

agent_summary := {
	"id": ctx.agent_id,
	"name": ctx.agent.name,
	"client_id": object.get(ctx.agent, "client_id", null),
} if {
	ctx.agent
} else := null

decision := {
	"effect": effect,
	"allow": effect == "allow",
	"reasons": sort(deny),
	"monitored": sort(monitored),
	"agent": agent_summary,
}
