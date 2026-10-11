package agentgov.copilotstudio_test

import data.agentgov.copilotstudio

registry := {
	"agents": {
		"agt_sales": {"id": "agt_sales", "name": "sales-helper", "status": "discovered", "risk_level": "medium", "risk_score": 45},
		"agt_hr": {"id": "agt_hr", "name": "hr-faq", "status": "blocked", "risk_level": "high", "risk_score": 55},
		"agt_it": {"id": "agt_it", "name": "it-helpdesk", "status": "active", "risk_level": "critical", "risk_score": 80},
	},
	"connector_allowlist": {"active": true, "approved": {"shared_office365": true}},
}

call(agent_id, tool) := {
	"platform": "copilot-studio",
	"agent": {"id": agent_id, "platform_id": "bot-1", "environment_id": "env-1", "published": true},
	"tool": tool,
	"arguments": {"to": "customer@contoso.com"},
}

email := {"id": "tool-1", "type": "ConnectorTool", "name": "Send email", "connector": "shared_office365"}

sql := {"id": "tool-2", "type": "ConnectorTool", "name": "Run query", "connector": "shared_sql"}

topic := {"id": "tool-3", "type": "TopicTool", "name": "Escalate"}

test_an_ordinary_call_is_allowed if {
	d := copilotstudio.decision with input as call("agt_sales", email) with data.registry as registry
	d.effect == "allow"
	d.reasons == []
}

test_a_blocked_agent_is_refused if {
	d := copilotstudio.decision with input as call("agt_hr", email) with data.registry as registry
	d.effect == "deny"
	"Agent hr-faq is blocked in AgentGov" in d.reasons
}

test_a_critical_risk_agent_is_refused if {
	d := copilotstudio.decision with input as call("agt_it", email) with data.registry as registry
	d.reasons == ["Agent it-helpdesk is critical risk (score 80) and is blocked until investigated"]
}

test_unapproved_connectors_are_refused if {
	d := copilotstudio.decision with input as call("agt_sales", sql) with data.registry as registry
	d.reasons == ["Connector shared_sql is not on AgentGov's connector allowlist"]
}

test_tools_that_are_not_connectors_pass_the_allowlist if {
	d := copilotstudio.decision with input as call("agt_sales", topic) with data.registry as registry
	d.effect == "allow"
}

test_without_an_allowlist_any_connector_goes if {
	reg := object.union(registry, {"connector_allowlist": {"active": false, "approved": {}}})
	d := copilotstudio.decision with input as call("agt_sales", sql) with data.registry as reg
	d.effect == "allow"
}

test_unknown_agents_are_allowed if {
	unknown := object.remove(call("agt_sales", email), ["agent"])
	d := copilotstudio.decision with input as object.union(unknown, {"agent": {"platform_id": "bot-9"}})
		with data.registry as registry
	d.effect == "allow"
}

test_credentials_in_arguments_are_refused if {
	inp := object.union(call("agt_sales", email), {"detections": {"categories": ["secret"]}})
	d := copilotstudio.decision with input as inp with data.registry as registry
	d.reasons == ["Arguments contain credentials; agents must not send secrets to tools"]
}

test_injected_instructions_in_earlier_results_are_refused if {
	inp := object.union(call("agt_sales", email), {"detections": {"prompt_injection": true}})
	d := copilotstudio.decision with input as inp with data.registry as registry
	d.effect == "deny"
}

test_policies_see_the_agent if {
	a := data.agentgov.context.agent with input as call("agt_sales", email) with data.registry as registry
	a.name == "sales-helper"
}

test_only_copilot_studio_calls_name_the_agent_by_its_registry_id if {
	inp := object.remove(call("agt_sales", email), ["platform"])
	not data.agentgov.context.agent with input as inp with data.registry as registry
}

test_organisation_policies_apply if {
	d := copilotstudio.decision with input as call("agt_sales", email)
		with data.registry as registry
		with data.agentgov.custom.freeze.deny as {"Change freeze until Monday"}
	d.reasons == ["Change freeze until Monday"]
}

test_monitored_controls_only_record if {
	reg := object.union(registry, {"features": {"data-protection": "monitor", "risk-based-access": "monitor"}})
	inp := object.union(call("agt_it", email), {"detections": {"categories": ["secret"]}})
	d := copilotstudio.decision with input as inp with data.registry as reg
	d.effect == "allow"
	count(d.monitored) == 2
}

test_controls_that_are_off_do_not_apply if {
	reg := object.union(registry, {"features": {"prompt-injection": "off"}})
	inp := object.union(call("agt_sales", email), {"detections": {"prompt_injection": true}})
	d := copilotstudio.decision with input as inp with data.registry as reg
	d.effect == "allow"
	d.monitored == []
}
