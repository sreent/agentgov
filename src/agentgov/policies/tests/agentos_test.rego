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

test_least_privilege_not_enforced_allows_ungranted_tools if {
	reg := object.union(registry, {"features": {"least-privilege": "monitor"}})
	agentos.allow with input as req("sales-bot", "crm/delete_customer") with data.registry as reg
}

test_blocked_agents_stay_denied_whatever_the_modes if {
	reg := object.union(registry, {"features": {"least-privilege": "off", "risk-based-access": "off"}})
	not agentos.allow with input as req("old-bot", "anything") with data.registry as reg
}

held := {"agents": {"agt_c": {
	"id": "agt_c",
	"name": "kb-bot",
	"status": "active",
	"risk_level": "low",
	"grants": [],
	"packages": [
		{"name": "now", "grants": [{"server": "crm", "tools": ["update_*"]}], "expires_at": "2099-01-01T00:00:00Z"},
		{"name": "gone", "grants": [{"server": "crm", "tools": ["export_*"]}], "expires_at": "2000-01-01T00:00:00Z"},
	],
}}}

with_mode(mode) := object.union(held, {"features": {"access-packages": mode}})

test_access_packages_grant_in_process if {
	agentos.allow with input as req("kb-bot", "crm/update_customer") with data.registry as held
	not agentos.allow with input as req("kb-bot", "crm/export_all") with data.registry as with_mode("enforce")
	agentos.allow with input as req("kb-bot", "crm/export_all") with data.registry as with_mode("monitor")
	not agentos.allow with input as req("kb-bot", "crm/update_customer") with data.registry as with_mode("off")
}
