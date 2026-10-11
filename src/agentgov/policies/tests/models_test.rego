package agentgov.models_test

import data.agentgov.models

registry := {
	"agents": {
		"agt_support": {
			"id": "agt_support",
			"name": "support-bot",
			"status": "active",
			"risk_level": "low",
			"risk_score": 10,
			"labels": {},
			"grants": [],
			"model_access": [{"provider": "openai", "models": ["gpt-4o-mini", "gpt-4.1*"]}],
			"daily_token_budget": 100000,
			"over_budget": false,
		},
		"agt_spender": {
			"id": "agt_spender",
			"name": "spender",
			"status": "active",
			"risk_level": "low",
			"risk_score": 5,
			"labels": {},
			"grants": [],
			"model_access": [{"provider": "openai", "models": ["*"]}],
			"daily_token_budget": 1000,
			"over_budget": true,
		},
		"agt_risky": {
			"id": "agt_risky",
			"name": "risky",
			"status": "active",
			"risk_level": "critical",
			"risk_score": 90,
			"labels": {},
			"grants": [],
			"model_access": [{"provider": "openai", "models": ["*"]}],
		},
		"agt_blocked": {
			"id": "agt_blocked",
			"name": "rogue",
			"status": "blocked",
			"risk_level": "low",
			"risk_score": 0,
			"labels": {},
			"grants": [],
			"model_access": [{"provider": "openai", "models": ["*"]}],
		},
	},
	"clients": {"agent-support-bot": "agt_support"},
	"toolservers": {},
	"model_providers": {
		"openai": {"name": "openai", "kind": "openai", "status": "approved", "trust_level": "unverified"},
		"azure": {"name": "azure", "kind": "openai-compatible", "status": "approved", "trust_level": "verified"},
		"old": {"name": "old", "kind": "openai", "status": "blocked", "trust_level": "unverified"},
	},
}

prompt(agent_id, provider, model) := {
	"kind": "model",
	"phase": "request",
	"agent": {"agent_id": agent_id},
	"provider": provider,
	"model": model,
	"detections": {"categories": []},
	"tool_calls": false,
}

with_modes(modes) := object.union(registry, {"features": modes})

test_granted_model_is_allowed if {
	d := models.decision with input as prompt("agt_support", "openai", "gpt-4.1-mini")
		with data.registry as registry
	d.effect == "allow"
	d.agent.name == "support-bot"
}

test_the_client_id_identifies_the_agent_too if {
	inp := object.union(prompt("", "openai", "gpt-4o-mini"), {"agent": {"client_id": "agent-support-bot"}})
	d := models.decision with input as inp with data.registry as registry
	d.effect == "allow"
}

test_ungranted_model_is_denied if {
	d := models.decision with input as prompt("agt_support", "openai", "o3")
		with data.registry as registry
	d.reasons == ["Model openai/o3 is not granted to agent support-bot"]
}

test_ungranted_provider_is_denied if {
	d := models.decision with input as prompt("agt_support", "azure", "gpt-4o-mini")
		with data.registry as registry
	d.effect == "deny"
}

test_unknown_and_blocked_providers_are_denied if {
	unknown := models.decision with input as prompt("agt_spender", "nowhere", "x")
		with data.registry as registry
	"Model provider \"nowhere\" is not registered" in unknown.reasons
	blocked := models.decision with input as prompt("agt_spender", "old", "x")
		with data.registry as registry
	"Model provider old is blocked" in blocked.reasons
}

test_unknown_and_blocked_agents_are_denied if {
	unknown := models.decision with input as prompt("agt_nobody", "openai", "x")
		with data.registry as registry
	unknown.reasons == ["Caller is not a registered agent"]
	unknown.agent == null
	blocked := models.decision with input as prompt("agt_blocked", "openai", "x")
		with data.registry as registry
	"Agent rogue is blocked" in blocked.reasons
}

test_credentials_in_prompts_are_denied if {
	inp := object.union(prompt("agt_support", "openai", "gpt-4o-mini"), {"detections": {"categories": ["secret"]}})
	d := models.decision with input as inp with data.registry as registry
	d.reasons == ["The prompt contains credentials; they must not be sent to a model provider"]
}

test_credentials_in_answers_are_withheld if {
	inp := object.union(prompt("agt_support", "openai", "gpt-4o-mini"), {"phase": "response", "detections": {"categories": ["secret"]}})
	d := models.decision with input as inp with data.registry as registry
	d.reasons == ["The model's answer contained credentials and was withheld"]
}

test_personal_data_is_masked_for_unverified_providers if {
	inp := object.union(prompt("agt_support", "openai", "gpt-4o-mini"), {"detections": {"categories": ["pii"]}})
	d := models.decision with input as inp with data.registry as registry
	d.effect == "allow"
	d.redact == ["pii"]
}

test_personal_data_may_go_to_verified_providers if {
	inp := object.union(prompt("agt_spender", "azure", "gpt-4o"), {"detections": {"categories": ["pii"]}})
	reg := object.union(registry, {"agents": {"agt_spender": {"over_budget": false, "model_access": [{"provider": "azure", "models": ["*"]}]}}})
	d := models.decision with input as inp with data.registry as reg
	d.effect == "allow"
	d.redact == []
}

test_masking_that_would_break_tool_calls_is_refused if {
	inp := object.union(prompt("agt_support", "openai", "gpt-4o-mini"), {"detections": {"categories": ["pii"]}, "tool_calls": true})
	d := models.decision with input as inp with data.registry as registry
	d.effect == "deny"
	contains(d.reasons[0], "masking would break its tool calls")
}

test_injected_tool_results_in_the_conversation_are_refused if {
	inp := object.union(prompt("agt_support", "openai", "gpt-4o-mini"), {"detections": {"categories": [], "prompt_injection": true}})
	d := models.decision with input as inp with data.registry as registry
	d.effect == "deny"
	contains(d.reasons[0], "possible prompt injection")
}

test_jailbreaks_are_refused_when_enforced if {
	inp := object.union(prompt("agt_support", "openai", "gpt-4o-mini"), {"detections": {"categories": [], "jailbreak": true}})
	d := models.decision with input as inp with data.registry as with_modes({"jailbreak-detection": "enforce"})
	d.effect == "deny"
	contains(d.reasons[0], "looks like a jailbreak")
}

test_monitored_jailbreaks_are_only_recorded if {
	inp := object.union(prompt("agt_support", "openai", "gpt-4o-mini"), {"detections": {"categories": [], "jailbreak": true}})
	d := models.decision with input as inp with data.registry as with_modes({"jailbreak-detection": "monitor"})
	d.effect == "allow"
	count(d.monitored) == 1
	startswith(d.monitored[0], "jailbreak-detection: ")
	off := models.decision with input as inp with data.registry as with_modes({"jailbreak-detection": "off"})
	off.monitored == []
}

test_critical_risk_agents_are_refused if {
	d := models.decision with input as prompt("agt_risky", "openai", "gpt-4o")
		with data.registry as registry
	contains(d.reasons[0], "critical risk")
}

test_agents_over_budget_are_refused if {
	d := models.decision with input as prompt("agt_spender", "openai", "gpt-4o")
		with data.registry as registry
	d.reasons == ["Agent spender has used its daily budget of 1000 tokens"]
}

test_budgets_only_apply_to_prompts if {
	inp := object.union(prompt("agt_spender", "openai", "gpt-4o"), {"phase": "response"})
	d := models.decision with input as inp with data.registry as registry
	d.effect == "allow"
}

test_monitored_budgets_and_grants_only_record if {
	modes := {"token-budgets": "monitor", "least-privilege": "monitor"}
	over := models.decision with input as prompt("agt_spender", "openai", "gpt-4o")
		with data.registry as with_modes(modes)
	over.effect == "allow"
	over.monitored == ["token-budgets: Agent spender has used its daily budget of 1000 tokens"]
	ungranted := models.decision with input as prompt("agt_support", "openai", "o3")
		with data.registry as with_modes(modes)
	ungranted.effect == "allow"
	ungranted.monitored == ["least-privilege: Model openai/o3 is not granted to agent support-bot"]
}

test_monitored_data_protection_neither_masks_nor_refuses if {
	inp := object.union(prompt("agt_support", "openai", "gpt-4o-mini"), {"detections": {"categories": ["pii"]}, "tool_calls": true})
	d := models.decision with input as inp with data.registry as with_modes({"data-protection": "monitor"})
	d.effect == "allow"
	d.redact == []
	count(d.monitored) == 2
}

test_controls_that_are_off_do_not_apply if {
	modes := {"token-budgets": "off", "data-protection": "off"}
	inp := object.union(prompt("agt_spender", "openai", "gpt-4o"), {"detections": {"categories": ["secret"]}})
	d := models.decision with input as inp with data.registry as with_modes(modes)
	d.effect == "allow"
	d.monitored == []
}

test_custom_policies_take_part if {
	custom := {"eu": {"deny": {"EU agents use EU providers"}, "redact": {"pii"}}}
	d := models.decision with input as prompt("agt_support", "openai", "gpt-4o-mini")
		with data.registry as registry
		with data.agentgov.custom as custom
	d.reasons == ["EU agents use EU providers"]
	d.redact == ["pii"]
}

test_model_calls_follow_who_the_agent_acts_for if {
	reg := object.union(registry, {"agents": {"agt_support": {"acts_for": "people", "people_groups": ["support"]}}})
	alone := models.decision with input as prompt("agt_support", "openai", "gpt-4o-mini") with data.registry as reg
	alone.reasons == ["Agent support-bot acts only for people, and this call is on no one's behalf"]
	bob := {"id": "u-bob", "username": "bob", "groups": ["sales"], "via": "delegation"}
	d := models.decision with input as object.union(prompt("agt_support", "openai", "gpt-4o-mini"), {"user": bob})
		with data.registry as reg
	d.reasons == ["Agent support-bot acts only for people in support, and bob is in none of them"]
	carol := {"id": "u-carol", "email": "carol@example.com", "groups": ["/support"], "via": "exchange"}
	ok := models.decision with input as object.union(prompt("agt_support", "openai", "gpt-4o-mini"), {"user": carol})
		with data.registry as reg
	ok.effect == "allow"
}
