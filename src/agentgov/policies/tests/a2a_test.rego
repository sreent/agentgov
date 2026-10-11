package agentgov.a2a_test

import data.agentgov.a2a

registry := {
	"agents": {
		"agt_desk": {
			"id": "agt_desk",
			"name": "frontdesk",
			"client_id": "agent-frontdesk",
			"status": "active",
			"risk_level": "low",
			"risk_score": 10,
			"labels": {},
			"a2a": false,
			"agent_access": ["billing-*", "kb"],
		},
		"agt_billing": {
			"id": "agt_billing",
			"name": "billing-agent",
			"client_id": "agent-billing-agent",
			"status": "active",
			"risk_level": "low",
			"risk_score": 5,
			"labels": {},
			"a2a": true,
			"agent_access": ["kb", "frontdesk"],
			"acts_for": "either",
			"people_groups": [],
		},
		"agt_kb": {
			"id": "agt_kb",
			"name": "kb",
			"client_id": "agent-kb",
			"status": "active",
			"risk_level": "low",
			"risk_score": 5,
			"labels": {},
			"a2a": true,
			"agent_access": [],
			"acts_for": "people",
			"people_groups": ["support"],
		},
		"agt_payroll": {
			"id": "agt_payroll",
			"name": "payroll",
			"client_id": "agent-payroll",
			"status": "active",
			"risk_level": "low",
			"risk_score": 5,
			"labels": {},
			"a2a": true,
			"agent_access": [],
			"acts_for": "itself",
		},
		"agt_blocked": {
			"id": "agt_blocked",
			"name": "billing-old",
			"client_id": "agent-billing-old",
			"status": "blocked",
			"risk_level": "low",
			"risk_score": 5,
			"labels": {},
			"a2a": true,
			"agent_access": [],
		},
		"agt_risky": {
			"id": "agt_risky",
			"name": "billing-risky",
			"client_id": "agent-billing-risky",
			"status": "active",
			"risk_level": "critical",
			"risk_score": 95,
			"labels": {},
			"a2a": true,
			"agent_access": [],
		},
		"agt_plain": {
			"id": "agt_plain",
			"name": "billing-plain",
			"client_id": "agent-billing-plain",
			"status": "active",
			"risk_level": "low",
			"risk_score": 5,
			"labels": {},
			"a2a": false,
			"agent_access": [],
		},
	},
	"clients": {
		"agent-frontdesk": "agt_desk",
		"agent-billing-agent": "agt_billing",
		"agent-kb": "agt_kb",
	},
	"agent_names": {
		"frontdesk": "agt_desk",
		"billing-agent": "agt_billing",
		"kb": "agt_kb",
		"payroll": "agt_payroll",
		"billing-old": "agt_blocked",
		"billing-risky": "agt_risky",
		"billing-plain": "agt_plain",
	},
}

sam := {"id": "u-1", "username": "sam", "groups": ["/support"]}

desk := {"type": "agent", "id": "agt_desk", "name": "frontdesk"}

person := {"type": "person", "id": "u-1", "name": "sam"}

call(client, target) := {
	"kind": "a2a",
	"method": "SendMessage",
	"agent": {"client_id": client},
	"target": target,
	"chain": [],
	"detections": {"categories": []},
}

decide(inp) := d if {
	d := a2a.decision with input as inp with data.registry as registry
}

test_granted_call_allowed if {
	d := decide(call("agent-frontdesk", "billing-agent"))
	d.effect == "allow"
	d.agent.name == "frontdesk"
	d.target.name == "billing-agent"
}

test_ungranted_call_denied if {
	d := decide(call("agent-billing-agent", "payroll"))
	d.effect == "deny"
	"Agent billing-agent may not call agent payroll" in d.reasons
}

test_least_privilege_monitored_lets_it_through if {
	d := a2a.decision with input as call("agent-billing-agent", "payroll")
		with data.registry as object.union(registry, {"features": {"least-privilege": "monitor"}})
	d.effect == "allow"
	"least-privilege: Agent billing-agent may not call agent payroll" in d.monitored
}

test_unknown_and_inactive_agents if {
	"Caller is not a registered agent" in decide(call("agent-nobody", "billing-agent")).reasons
	"Agent \"ghost\" is not registered" in decide(call("agent-frontdesk", "ghost")).reasons
	"Agent billing-old is blocked" in decide(call("agent-frontdesk", "billing-old")).reasons
	"Agent billing-plain doesn't serve A2A" in decide(call("agent-frontdesk", "billing-plain")).reasons
}

test_no_agent_calls_itself if {
	d := decide(call("agent-billing-agent", "billing-agent"))
	"Agent billing-agent can't call itself" in d.reasons
}

test_loops_are_refused if {
	# frontdesk asked billing-agent, which now calls frontdesk back.
	inp := object.union(call("agent-billing-agent", "frontdesk"), {"chain": [person, desk]})
	reg := object.union(registry, {"agents": {"agt_desk": {"a2a": true}}})
	d := a2a.decision with input as inp with data.registry as reg
	"Agent frontdesk is already in this chain (sam > frontdesk > billing-agent > frontdesk)" in d.reasons
}

test_long_chains_are_refused if {
	hops := [{"type": "agent", "id": sprintf("agt_%d", [i]), "name": sprintf("hop-%d", [i])} | some i in numbers.range(1, 4)]
	inp := object.union(call("agent-billing-agent", "kb"), {"chain": hops, "user": sam})
	d := decide(inp)
	d.effect == "deny"
	some reason in d.reasons
	startswith(reason, "The chain would hold 6 agents, more than 5")
}

test_three_agents_are_fine if {
	inp := object.union(call("agent-billing-agent", "kb"), {"chain": [person, desk], "user": sam})
	decide(inp).effect == "allow"
}

test_the_called_agent_acts_for_the_person_as_its_blueprint_says if {
	# kb acts only for people, in support.
	"Agent kb acts only for people, and this call is on no one's behalf" in decide(call("agent-frontdesk", "kb")).reasons
	outsider := {"id": "u-2", "username": "olga", "groups": ["/finance"]}
	d := decide(object.union(call("agent-frontdesk", "kb"), {"user": outsider}))
	"Agent kb acts only for people in support, and olga is in none of them" in d.reasons
	decide(object.union(call("agent-frontdesk", "kb"), {"user": sam})).effect == "allow"

	# payroll acts only on its own.
	reg := object.union(registry, {"agents": {"agt_desk": {"agent_access": ["payroll"]}}})
	p := a2a.decision with input as object.union(call("agent-frontdesk", "payroll"), {"user": sam}) with data.registry as reg
	"Agent payroll acts only on its own behalf, and this call is on behalf of sam" in p.reasons
}

test_credentials_in_messages_are_refused if {
	inp := object.union(call("agent-frontdesk", "billing-agent"), {"detections": {"categories": ["secret"]}})
	"The message contains credentials; agents must not send secrets to other agents" in decide(inp).reasons
}

test_critical_risk_on_either_side if {
	d := decide(call("agent-frontdesk", "billing-risky"))
	"Agent billing-risky is critical risk (score 95): no agent may call it until it is investigated" in d.reasons
}

test_organisation_policies_can_ask_for_approval if {
	d := a2a.decision with input as call("agent-frontdesk", "billing-agent")
		with data.registry as registry
		with data.agentgov.custom.a2a_review.require_approval as {"calls to billing need a person"}
	d.effect == "require_approval"
	d.reasons == ["calls to billing need a person"]
}

# ---------------------------------------------------------------------------
# Answers (phase "response").
# ---------------------------------------------------------------------------

answer(client, target, detections) := {
	"kind": "a2a",
	"phase": "response",
	"method": "answer",
	"agent": {"client_id": client},
	"target": target,
	"detections": detections,
}

test_a_clean_answer_passes if {
	d := decide(answer("agent-frontdesk", "billing-agent", {"categories": []}))
	d.effect == "allow"
	d.redact == []
}

test_instructions_in_an_answer_withhold_it if {
	d := decide(answer("agent-frontdesk", "billing-agent", {"categories": [], "prompt_injection": true}))
	d.effect == "deny"
	"Answer from agent billing-agent withheld: it contains instructions aimed at the agent (possible prompt injection)" in d.reasons
}

test_credentials_and_personal_data_in_answers_are_masked if {
	d := decide(answer("agent-frontdesk", "billing-agent", {"categories": ["secret", "pii"]}))
	d.effect == "allow"
	d.redact == ["pii", "secret"]

	# An agent that may have personal data gets it.
	reg := object.union(registry, {"agents": {"agt_desk": {"labels": {"pii-access": "true"}}}})
	entitled := a2a.decision with input as answer("agent-frontdesk", "billing-agent", {"categories": ["secret", "pii"]})
		with data.registry as reg
	entitled.redact == ["secret"]
}

test_monitored_answers_pass_and_say_what_would_have_been_done if {
	reg := object.union(registry, {"features": {"prompt-injection": "monitor", "data-protection": "monitor"}})
	d := a2a.decision with input as answer("agent-frontdesk", "billing-agent", {"categories": ["secret"], "prompt_injection": true})
		with data.registry as reg
	d.effect == "allow"
	d.redact == []
	"data-protection: would mask secret" in d.monitored
	some m in d.monitored
	startswith(m, "prompt-injection: Answer from agent billing-agent withheld")
}

test_what_a_call_is_checked_for_doesnt_hold_up_its_answer if {
	# billing-agent may not call payroll, nor send credentials; payroll's answer to a
	# call that went through is checked for what answers are checked for.
	d := decide(answer("agent-billing-agent", "payroll", {"categories": []}))
	d.effect == "allow"

	# But a caller blocked meanwhile gets nothing more.
	reg := object.union(registry, {"agents": {"agt_desk": {"status": "blocked"}}})
	blocked := a2a.decision with input as answer("agent-frontdesk", "billing-agent", {"categories": []})
		with data.registry as reg
	"Agent frontdesk is blocked" in blocked.reasons
}
