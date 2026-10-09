package agentos_test

import data.agentos

registry := {"agents": {
	"agt_a": {
		"id": "agt_a",
		"name": "sales-bot",
		"status": "active",
		"risk_level": "low",
		"grants": [{"server": "local", "tools": ["search_*"]}, {"server": "crm", "tools": ["lookup_customer"]}],
	},
	"agt_b": {"id": "agt_b", "name": "old-bot", "status": "blocked", "risk_level": "low", "grants": [{"server": "*", "tools": ["*"]}]},
}}

req(agent, tool) := {"agent_id": agent, "action_type": "tool_call", "tool_name": tool, "tool_args": {}}

test_local_tool_granted if {
	agentos.allow with input as req("sales-bot", "search_docs") with data.registry as registry
}

test_server_tool_granted if {
	agentos.allow with input as req("sales-bot", "crm/lookup_customer") with data.registry as registry
}

test_agent_id_also_accepted if {
	agentos.allow with input as req("agt_a", "search_docs") with data.registry as registry
}

test_ungranted_tool_denied if {
	not agentos.allow with input as req("sales-bot", "crm/delete_customer") with data.registry as registry
}

test_blocked_agent_denied if {
	not agentos.allow with input as req("old-bot", "anything") with data.registry as registry
}

test_unknown_agent_denied if {
	not agentos.allow with input as req("stranger", "search_docs") with data.registry as registry
}

test_result_is_boolean if {
	r := agentos.allow with input as req("stranger", "search_docs") with data.registry as registry
	r == false
}
