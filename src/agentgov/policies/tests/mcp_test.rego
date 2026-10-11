package agentgov.mcp_test

import data.agentgov.mcp

registry := {
	"agents": {
		"agt_support": {
			"id": "agt_support",
			"name": "support-bot",
			"client_id": "agent-support-bot",
			"status": "active",
			"risk_level": "low",
			"risk_score": 10,
			"labels": {},
			"grants": [{"server": "crm", "tools": ["lookup_*", "update_customer", "delete_customer"]}],
		},
		"agt_analyst": {
			"id": "agt_analyst",
			"name": "analyst",
			"client_id": "agent-analyst",
			"status": "active",
			"risk_level": "low",
			"risk_score": 5,
			"labels": {"pii-access": "true"},
			"grants": [{"server": "*", "tools": ["*"]}],
		},
		"agt_blocked": {
			"id": "agt_blocked",
			"name": "rogue",
			"client_id": "agent-rogue",
			"status": "blocked",
			"risk_level": "high",
			"risk_score": 60,
			"labels": {},
			"grants": [{"server": "crm", "tools": ["*"]}],
		},
		"agt_risky": {
			"id": "agt_risky",
			"name": "risky",
			"client_id": "agent-risky",
			"status": "active",
			"risk_level": "critical",
			"risk_score": 90,
			"labels": {},
			"grants": [{"server": "crm", "tools": ["*"]}],
		},
	},
	"clients": {
		"agent-support-bot": "agt_support",
		"agent-analyst": "agt_analyst",
		"agent-rogue": "agt_blocked",
		"agent-risky": "agt_risky",
	},
	"toolservers": {
		"crm": {
			"name": "crm",
			"status": "approved",
			"trust_level": "verified",
			"data_classification": "confidential",
			"tools": {
				"lookup_customer": {"annotations": {"readOnlyHint": true}},
				"update_customer": {"annotations": {"destructiveHint": false}},
				"delete_customer": {"annotations": {"destructiveHint": true}},
				"lookup_orders": {"changed": true},
				"lookup_notes": {"poisoned": true},
			},
		},
		"web": {"name": "web", "status": "approved", "trust_level": "unverified", "tools": {}},
		"shady": {"name": "shady", "status": "blocked", "trust_level": "unverified", "tools": {}},
	},
}

call(client, server, tool) := {
	"phase": "request",
	"method": "tools/call",
	"agent": {"client_id": client},
	"resource": {"server": server, "name": tool},
	"arguments": {},
	"detections": {"categories": []},
}

test_granted_tool_is_allowed if {
	d := mcp.decision with input as call("agent-support-bot", "crm", "lookup_customer")
		with data.registry as registry
	d.effect == "allow"
	d.allow
	d.agent.name == "support-bot"
}

test_agent_id_claim_resolves_agent if {
	inp := object.union(call("ignored", "crm", "lookup_customer"), {"agent": {"agent_id": "agt_support"}})
	d := mcp.decision with input as inp with data.registry as registry
	d.effect == "allow"
}

test_unknown_agent_is_denied if {
	d := mcp.decision with input as call("agent-nobody", "crm", "lookup_customer")
		with data.registry as registry
	d.effect == "deny"
	"Caller is not a registered agent" in d.reasons
	d.agent == null
}

test_blocked_agent_is_denied if {
	d := mcp.decision with input as call("agent-rogue", "crm", "lookup_customer")
		with data.registry as registry
	d.effect == "deny"
	"Agent rogue is blocked" in d.reasons
}

test_ungranted_tool_is_denied if {
	d := mcp.decision with input as call("agent-support-bot", "crm", "export_all")
		with data.registry as registry
	d.effect == "deny"
	"crm/export_all is not granted to agent support-bot" in d.reasons
}

test_unregistered_server_is_denied if {
	d := mcp.decision with input as call("agent-analyst", "nowhere", "x")
		with data.registry as registry
	"Tool server \"nowhere\" is not registered" in d.reasons
}

test_blocked_server_is_denied if {
	d := mcp.decision with input as call("agent-analyst", "shady", "x") with data.registry as registry
	"Tool server shady is blocked" in d.reasons
}

test_changed_tool_is_denied if {
	d := mcp.decision with input as call("agent-support-bot", "crm", "lookup_orders")
		with data.registry as registry
	d.effect == "deny"
	contains(concat(" ", d.reasons), "changed its definition")
}

test_poisoned_tool_is_denied if {
	d := mcp.decision with input as call("agent-support-bot", "crm", "lookup_notes")
		with data.registry as registry
	contains(concat(" ", d.reasons), "quarantined")
}

test_secrets_in_arguments_are_denied if {
	inp := object.union(call("agent-support-bot", "crm", "update_customer"), {"detections": {"categories": ["secret"]}})
	d := mcp.decision with input as inp with data.registry as registry
	d.effect == "deny"
	"Arguments contain credentials; agents must not send secrets to tools" in d.reasons
}

test_critical_risk_agent_is_denied if {
	d := mcp.decision with input as call("agent-risky", "crm", "lookup_customer")
		with data.registry as registry
	d.effect == "deny"
	contains(concat(" ", d.reasons), "critical risk")
}

test_destructive_tool_requires_approval if {
	d := mcp.decision with input as call("agent-support-bot", "crm", "delete_customer")
		with data.registry as registry
	d.effect == "require_approval"
	not d.allow
	"crm/delete_customer is marked destructive by its server" in d.reasons
}

test_denial_beats_approval if {
	inp := object.union(call("agent-support-bot", "crm", "delete_customer"), {"detections": {"categories": ["secret"]}})
	d := mcp.decision with input as inp with data.registry as registry
	d.effect == "deny"
}

test_pii_in_results_is_redacted if {
	inp := object.union(call("agent-support-bot", "crm", "lookup_customer"), {"phase": "response", "detections": {"categories": ["pii"]}})
	d := mcp.decision with input as inp with data.registry as registry
	d.effect == "allow"
	d.redact == ["pii"]
}

test_pii_access_label_skips_redaction if {
	inp := object.union(call("agent-analyst", "crm", "lookup_customer"), {"phase": "response", "detections": {"categories": ["pii"]}})
	d := mcp.decision with input as inp with data.registry as registry
	d.redact == []
}

test_pii_to_unverified_server_is_redacted if {
	inp := object.union(call("agent-analyst", "web", "search"), {"detections": {"categories": ["pii"]}})
	d := mcp.decision with input as inp with data.registry as registry
	d.effect == "allow"
	d.redact == ["pii"]
}

test_secrets_in_results_are_redacted if {
	inp := object.union(call("agent-analyst", "crm", "lookup_customer"), {"phase": "response", "detections": {"categories": ["secret"]}})
	d := mcp.decision with input as inp with data.registry as registry
	d.effect == "allow"
	d.redact == ["secret"]
}

test_prompt_injection_in_results_is_withheld if {
	inp := object.union(call("agent-support-bot", "crm", "lookup_customer"), {"phase": "response", "detections": {"categories": [], "prompt_injection": true}})
	d := mcp.decision with input as inp with data.registry as registry
	d.effect == "deny"
	contains(concat(" ", d.reasons), "prompt injection")
}

test_tool_list_is_filtered if {
	inp := {
		"phase": "response",
		"method": "tools/list",
		"agent": {"client_id": "agent-support-bot"},
		"resource": {"server": "crm"},
		"tools": [
			{"name": "lookup_customer"}, {"name": "update_customer"}, {"name": "export_all"},
			{"name": "lookup_notes"}, {"name": "lookup_fresh"},
		],
		"poisoned": {"lookup_fresh": ["hidden instructions"]},
	}
	v := mcp.visible_tools with input as inp with data.registry as registry
	v == {"lookup_customer", "update_customer"}
}

test_list_view_reports_caller if {
	inp := {"agent": {"client_id": "agent-support-bot"}, "resource": {"server": "crm"}, "tools": [{"name": "lookup_customer"}]}
	v := mcp.list_view with input as inp with data.registry as registry
	v.agent.name == "support-bot"
	v.visible == {"lookup_customer"}
}

test_list_view_unknown_caller if {
	inp := {"agent": {"client_id": "nobody"}, "resource": {"server": "crm"}, "tools": [{"name": "lookup_customer"}]}
	v := mcp.list_view with input as inp with data.registry as registry
	v.agent == null
	count(v.visible) == 0
}

test_blocked_agent_sees_no_tools if {
	inp := {"agent": {"client_id": "agent-rogue"}, "resource": {"server": "crm"}, "tools": [{"name": "lookup_customer"}]}
	v := mcp.visible_tools with input as inp with data.registry as registry
	count(v) == 0
}

test_custom_policies_contribute if {
	custom := {"finance": {"deny": {"No payments on weekends"}, "redact": {"pii"}}}
	d := mcp.decision with input as call("agent-support-bot", "crm", "lookup_customer")
		with data.registry as registry
		with data.agentgov.custom as custom
	d.effect == "deny"
	d.reasons == ["No payments on weekends"]
	d.redact == ["pii"]
}

test_custom_approval_only_on_requests if {
	custom := {"finance": {"require_approval": {"Large refund"}}}
	inp := object.union(call("agent-support-bot", "crm", "lookup_customer"), {"phase": "response"})
	d := mcp.decision with input as inp with data.registry as registry with data.agentgov.custom as custom
	d.effect == "allow"
}

# ---------------------------------------------------------------------------
# Feature modes: monitored controls only record; controls that are off don't apply.
# ---------------------------------------------------------------------------

with_modes(modes) := object.union(registry, {"features": modes})

test_monitored_least_privilege_records_instead_of_denying if {
	d := mcp.decision with input as call("agent-support-bot", "crm", "export_all")
		with data.registry as with_modes({"least-privilege": "monitor"})
	d.effect == "allow"
	d.monitored == ["least-privilege: crm/export_all is not granted to agent support-bot"]
}

test_least_privilege_off_neither_denies_nor_records if {
	d := mcp.decision with input as call("agent-support-bot", "crm", "export_all")
		with data.registry as with_modes({"least-privilege": "off"})
	d.effect == "allow"
	d.monitored == []
}

test_monitored_approval_lets_destructive_calls_through if {
	d := mcp.decision with input as call("agent-support-bot", "crm", "delete_customer")
		with data.registry as with_modes({"approvals": "monitor"})
	d.effect == "allow"
	d.monitored == ["approvals: crm/delete_customer is marked destructive by its server"]
}

test_monitored_data_protection_neither_denies_nor_masks if {
	inp := object.union(call("agent-support-bot", "crm", "update_customer"), {"detections": {"categories": ["secret"]}})
	d := mcp.decision with input as inp with data.registry as with_modes({"data-protection": "monitor"})
	d.effect == "allow"
	d.redact == []
	d.monitored == [
		"data-protection: Arguments contain credentials; agents must not send secrets to tools",
		"data-protection: would mask secret",
	]
}

test_data_protection_off_masks_nothing if {
	inp := object.union(call("agent-support-bot", "crm", "lookup_customer"), {"phase": "response", "detections": {"categories": ["pii"]}})
	d := mcp.decision with input as inp with data.registry as with_modes({"data-protection": "off"})
	d.redact == []
	d.monitored == []
}

test_monitored_tool_integrity_lets_changed_tools_through if {
	d := mcp.decision with input as call("agent-support-bot", "crm", "lookup_orders")
		with data.registry as with_modes({"tool-integrity": "monitor"})
	d.effect == "allow"
	count(d.monitored) == 1
}

test_monitored_risk_lets_critical_agents_through if {
	d := mcp.decision with input as call("agent-risky", "crm", "lookup_customer")
		with data.registry as with_modes({"risk-based-access": "monitor"})
	d.effect == "allow"
	contains(d.monitored[0], "critical risk")
}

test_monitored_prompt_injection_passes_results if {
	inp := object.union(call("agent-support-bot", "crm", "lookup_customer"), {"phase": "response", "detections": {"categories": [], "prompt_injection": true}})
	d := mcp.decision with input as inp with data.registry as with_modes({"prompt-injection": "monitor"})
	d.effect == "allow"
	contains(d.monitored[0], "prompt-injection: Tool result withheld")
}

test_identity_and_lifecycle_apply_in_every_mode if {
	modes := {k: "off" | some k in ["least-privilege", "approvals", "data-protection", "prompt-injection", "tool-integrity", "risk-based-access"]}
	d := mcp.decision with input as call("agent-rogue", "crm", "lookup_customer")
		with data.registry as with_modes(modes)
	d.effect == "deny"
	"Agent rogue is blocked" in d.reasons
}

test_custom_denials_apply_whatever_the_modes if {
	custom := {"finance": {"deny": {"No payments on weekends"}, "require_approval": {"Large refund"}}}
	d := mcp.decision with input as call("agent-support-bot", "crm", "lookup_customer")
		with data.registry as with_modes({"approvals": "off"})
		with data.agentgov.custom as custom
	d.effect == "deny"
	d.reasons == ["No payments on weekends"]
}

test_custom_approvals_follow_the_approvals_control if {
	custom := {"finance": {"require_approval": {"Large refund"}}}
	d := mcp.decision with input as call("agent-support-bot", "crm", "lookup_customer")
		with data.registry as with_modes({"approvals": "monitor"})
		with data.agentgov.custom as custom
	d.effect == "allow"
	d.monitored == ["approvals: Large refund"]
}

tool_list := {
	"phase": "response",
	"method": "tools/list",
	"agent": {"client_id": "agent-support-bot"},
	"resource": {"server": "crm"},
	"tools": [{"name": "lookup_customer"}, {"name": "export_all"}, {"name": "lookup_notes"}],
	"poisoned": {},
}

test_monitored_least_privilege_shows_every_tool if {
	v := mcp.visible_tools with input as tool_list with data.registry as with_modes({"least-privilege": "monitor"})
	v == {"lookup_customer", "export_all"}
}

test_monitored_tool_integrity_shows_quarantined_tools if {
	v := mcp.visible_tools with input as tool_list with data.registry as with_modes({"tool-integrity": "monitor"})
	v == {"lookup_customer", "lookup_notes"}
}

test_monitored_risk_shows_critical_agents_their_tools if {
	inp := object.union(tool_list, {"agent": {"client_id": "agent-risky"}})
	v := mcp.visible_tools with input as inp with data.registry as with_modes({"risk-based-access": "monitor"})
	v == {"lookup_customer", "export_all"}
}
