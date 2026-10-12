package agentgov.idjag_test

import data.agentgov.idjag
import data.agentgov.mcp_test

# The MCP tests' registry, with a wiki outside the gateway, and an agent that acts only for
# people in support.
registry := object.union(mcp_test.registry, {
	"agents": object.union(mcp_test.registry.agents, {"agt_people": {
		"id": "agt_people",
		"name": "helper",
		"client_id": "agent-helper",
		"status": "active",
		"risk_level": "low",
		"risk_score": 0,
		"labels": {},
		"grants": [{"server": "wiki", "tools": ["search"]}],
		"acts_for": "people",
		"people_groups": ["support"],
	}}),
	"clients": object.union(mcp_test.registry.clients, {"agent-helper": "agt_people"}),
	"toolservers": object.union(mcp_test.registry.toolservers, {"wiki": {"name": "wiki", "status": "approved", "gateway": false, "tools": {}}}),
})

ask(client, server, user) := d if {
	d := idjag.decision with input as {"agent": {"client_id": client}, "resource": {"server": server}, "user": user}
		with data.registry as registry
}

sam := {"id": "u-sam", "username": "sam", "groups": ["/support"], "via": "exchange"}

dana := {"id": "u-dana", "username": "dana", "groups": ["/developers"], "via": "sign-in"}

test_an_agent_granted_a_tool_of_the_server_gets_one if {
	d := ask("agent-helper", "wiki", sam)
	d.allow
	d.agent.name == "helper"
	d.reasons == []
}

test_a_grant_on_any_server_counts if {
	ask("agent-analyst", "wiki", null).allow
}

test_an_agent_without_a_grant_on_the_server_doesnt if {
	d := ask("agent-support-bot", "wiki", null)
	not d.allow
	d.reasons == ["No tool of wiki is granted to agent support-bot"]
}

test_only_for_the_people_its_blueprint_allows if {
	d := ask("agent-helper", "wiki", dana)
	not d.allow
	contains(d.reasons[0], "acts only for people in support")
	alone := ask("agent-helper", "wiki", null)
	not alone.allow
	contains(alone.reasons[0], "acts only for people")
}

test_blocked_agents_and_servers_and_unknown_callers if {
	not ask("agent-rogue", "crm", null).allow
	not ask("agent-analyst", "shady", null).allow
	d := ask("agent-nobody", "wiki", null)
	not d.allow
	"Caller is not a registered agent" in d.reasons
	unknown := ask("agent-analyst", "nowhere", null)
	"Tool server \"nowhere\" is not registered" in unknown.reasons
}

test_critical_risk if {
	not ask("agent-risky", "crm", null).allow
}

test_monitored_controls_say_what_they_would_have_done if {
	d := idjag.decision with input as {"agent": {"client_id": "agent-support-bot"}, "resource": {"server": "wiki"}}
		with data.registry as object.union(registry, {"features": {"least-privilege": "monitor"}})
	d.allow
	d.monitored == ["least-privilege: No tool of wiki is granted to agent support-bot"]
}

test_an_expired_package_is_no_grant if {
	held := object.union(registry, {"agents": {"agt_support": object.union(registry.agents.agt_support, {"packages": [{
		"name": "wiki-reader",
		"expires_at": "2020-01-01T00:00:00Z",
		"grants": [{"server": "wiki", "tools": ["search"]}],
	}]})}})
	d := idjag.decision with input as {"agent": {"client_id": "agent-support-bot"}, "resource": {"server": "wiki"}}
		with data.registry as held
	not d.allow
	d.reasons == ["wiki was granted to agent support-bot by access package wiki-reader, which has expired"]
}
