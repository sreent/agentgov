package agentgov.authzen_test

import data.agentgov.a2a_test
import data.agentgov.authzen
import data.agentgov.mcp_test
import data.agentgov.models_test

ask(req, registry) := e if {
	e := authzen.evaluation with input as req with data.registry as registry
}

tool_call(subject, tool) := {
	"subject": subject,
	"action": {"name": "tools/call"},
	"resource": {"type": "tool", "id": tool},
	"context": {"detections": {"categories": []}},
}

test_an_agent_may_call_a_granted_tool if {
	e := ask(tool_call({"type": "agent", "id": "agent-support-bot"}, "crm/lookup_customer"), mcp_test.registry)
	e.decision
	e.context.reason == "allowed"
	e.context.agentgov.agent.name == "support-bot"
	e.context.obligations == []
}

test_the_agent_by_its_agentgov_id_too if {
	e := ask(tool_call({"type": "agent", "id": "agt_support"}, "crm/lookup_customer"), mcp_test.registry)
	e.decision
}

test_a_tool_it_wasnt_granted_is_denied_with_why if {
	e := ask(tool_call({"type": "agent", "id": "agent-support-bot"}, "crm/export_all"), mcp_test.registry)
	not e.decision
	e.context.reason == "denied"
	"crm/export_all is not granted to agent support-bot" in e.context.reasons
}

test_a_person_with_the_agent_acting_for_them if {
	req := object.union(
		tool_call({"type": "user", "id": "u-1", "properties": {"username": "sam", "groups": ["/support"]}}, "crm/lookup_customer"),
		{"context": {"agent": "agent-support-bot", "detections": {"categories": []}}},
	)
	e := ask(req, mcp_test.registry)
	e.decision
	e.context.agentgov.agent.name == "support-bot"
}

test_tools_split_by_their_properties if {
	req := object.union(
		tool_call({"type": "agent", "id": "agent-support-bot"}, "ignored"),
		{"resource": {"type": "tool", "id": "x", "properties": {"server": "crm", "name": "lookup_customer"}}},
	)
	ask(req, mcp_test.registry).decision
}

test_destructive_tools_need_approval if {
	e := ask(tool_call({"type": "agent", "id": "agent-support-bot"}, "crm/delete_customer"), mcp_test.registry)
	not e.decision
	e.context.reason == "approval_required"
}

# Personal data must not leave for a server that isn't verified: masked, as an obligation.
test_personal_data_comes_back_as_an_obligation_to_mask_it if {
	req := object.union(
		tool_call({"type": "agent", "id": "agent-analyst"}, "web/search"),
		{"context": {"detections": {"categories": ["pii"]}}},
	)
	e := ask(req, mcp_test.registry)
	e.decision
	[obligation] := e.context.obligations
	obligation.type == "custom"
	obligation.properties == {"vendor": "agentgov", "action": "redact", "categories": ["pii"]}
}

test_models if {
	req := {
		"subject": {"type": "agent", "id": "agt_support"},
		"action": {"name": "chat"},
		"resource": {"type": "model", "id": "openai/gpt-4o-mini"},
		"context": {"detections": {"categories": []}},
	}
	e := ask(req, models_test.registry)
	e.decision
	denied := ask(object.union(req, {"resource": {"type": "model", "id": "openai/o1"}}), models_test.registry)
	not denied.decision
}

test_agents if {
	req := {
		"subject": {"type": "agent", "id": "agent-frontdesk"},
		"action": {"name": "SendMessage"},
		"resource": {"type": "agent", "id": "billing-agent"},
		"context": {"detections": {"categories": []}},
	}
	e := ask(req, a2a_test.registry)
	e.decision
	e.context.agentgov.target.name == "billing-agent"
	denied := ask(object.union(req, {"resource": {"type": "agent", "id": "payroll"}}), a2a_test.registry)
	not denied.decision
}

test_what_agentgov_doesnt_decide_is_denied if {
	req := {"subject": {"type": "agent", "id": "agent-support-bot"}, "action": {"name": "read"}, "resource": {"type": "document", "id": "d-1"}}
	e := ask(req, mcp_test.registry)
	not e.decision
	contains(e.context.reasons[0], "not document")
}
