package agentgov.access_packages_test

import data.agentgov.a2a
import data.agentgov.mcp
import data.agentgov.models

# kb-bot holds two access packages: crm-write, until 2099, and crm-export, which expired
# in 2000. Its own grants let it look customers up, and nothing more.
kb := {
	"id": "agt_kb",
	"name": "kb-bot",
	"client_id": "agent-kb-bot",
	"status": "active",
	"risk_level": "low",
	"risk_score": 0,
	"labels": {},
	"a2a": false,
	"grants": [{"server": "crm", "tools": ["lookup_customer"]}],
	"model_access": [],
	"agent_access": [],
	"packages": [
		{
			"name": "crm-write",
			"grants": [{"server": "crm", "tools": ["update_customer"]}],
			"model_access": [{"provider": "openai", "models": ["gpt-4.1"]}],
			"agent_access": ["billing-agent"],
			"expires_at": "2099-01-01T00:00:00Z",
		},
		{
			"name": "crm-export",
			"grants": [{"server": "crm", "tools": ["export_*", "update_customer"]}],
			"model_access": [{"provider": "openai", "models": ["o3"]}],
			"agent_access": ["finance-agent"],
			"expires_at": "2000-01-01T00:00:00Z",
		},
	],
}

target(id, name) := {
	"id": id,
	"name": name,
	"client_id": sprintf("agent-%s", [name]),
	"status": "active",
	"risk_level": "low",
	"risk_score": 0,
	"labels": {},
	"a2a": true,
	"agent_access": [],
	"acts_for": "either",
	"people_groups": [],
}

registry := {
	"agents": {
		"agt_kb": kb,
		"agt_billing": target("agt_billing", "billing-agent"),
		"agt_finance": target("agt_finance", "finance-agent"),
	},
	"clients": {"agent-kb-bot": "agt_kb"},
	"agent_names": {"kb-bot": "agt_kb", "billing-agent": "agt_billing", "finance-agent": "agt_finance"},
	"toolservers": {"crm": {"name": "crm", "status": "approved", "trust_level": "verified", "tools": {}}},
	"model_providers": {"openai": {"name": "openai", "kind": "openai", "status": "approved", "trust_level": "verified"}},
}

with_mode(mode) := object.union(registry, {"features": {"access-packages": mode}})

tool(name) := {
	"phase": "request",
	"method": "tools/call",
	"agent": {"client_id": "agent-kb-bot"},
	"resource": {"server": "crm", "name": name},
	"arguments": {},
	"detections": {"categories": []},
}

prompt(model) := {
	"kind": "model",
	"phase": "request",
	"agent": {"client_id": "agent-kb-bot"},
	"provider": "openai",
	"model": model,
	"detections": {"categories": []},
	"tool_calls": false,
}

message(to) := {
	"kind": "a2a",
	"method": "SendMessage",
	"agent": {"client_id": "agent-kb-bot"},
	"target": to,
	"chain": [],
	"detections": {"categories": []},
}

test_a_package_in_force_grants_tools_models_and_agents if {
	d := mcp.decision with input as tool("update_customer") with data.registry as registry
	d.effect == "allow"
	d.monitored == []
	m := models.decision with input as prompt("gpt-4.1") with data.registry as registry
	m.effect == "allow"
	m.monitored == []
	a := a2a.decision with input as message("billing-agent") with data.registry as registry
	a.effect == "allow"
	a.monitored == []
}

# Also granted by a package in force: the expired one doesn't matter.
test_an_expired_package_is_ignored_where_another_grant_covers_it if {
	d := mcp.decision with input as tool("update_customer") with data.registry as with_mode("enforce")
	d.effect == "allow"
}

test_enforced_an_expired_package_grants_nothing if {
	d := mcp.decision with input as tool("export_all") with data.registry as with_mode("enforce")
	d.effect == "deny"
	d.reasons == ["crm/export_all was granted to agent kb-bot by access package crm-export, which has expired"]
	m := models.decision with input as prompt("o3") with data.registry as with_mode("enforce")
	m.effect == "deny"
	a := a2a.decision with input as message("finance-agent") with data.registry as with_mode("enforce")
	a.effect == "deny"
}

test_monitored_an_expired_package_still_grants_and_says_so if {
	d := mcp.decision with input as tool("export_all") with data.registry as with_mode("monitor")
	d.effect == "allow"
	d.monitored == ["access-packages: crm/export_all was granted to agent kb-bot by access package crm-export, which has expired"]
	m := models.decision with input as prompt("o3") with data.registry as with_mode("monitor")
	m.effect == "allow"
	count(m.monitored) == 1
	a := a2a.decision with input as message("finance-agent") with data.registry as with_mode("monitor")
	a.effect == "allow"
	count(a.monitored) == 1
}

test_off_packages_grant_nothing if {
	d := mcp.decision with input as tool("update_customer") with data.registry as with_mode("off")
	d.effect == "deny"
	d.reasons == ["crm/update_customer is not granted to agent kb-bot"]
	m := models.decision with input as prompt("gpt-4.1") with data.registry as with_mode("off")
	m.effect == "deny"
}

test_tools_lists_show_what_packages_grant if {
	inp := object.union(tool("x"), {"method": "tools/list", "tools": [
		{"name": "lookup_customer"},
		{"name": "update_customer"},
		{"name": "export_all"},
		{"name": "delete_customer"},
	]})
	enforced := mcp.list_view with input as inp with data.registry as with_mode("enforce")
	enforced.visible == {"lookup_customer", "update_customer"}
	monitored := mcp.list_view with input as inp with data.registry as with_mode("monitor")
	monitored.visible == {"export_all", "lookup_customer", "update_customer"}
}
