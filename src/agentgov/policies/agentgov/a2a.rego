# Decisions for calls between agents passing through agentgateway (/a2a/<agent>).
#
# The governance processor queries data.agentgov.a2a.decision for each call an agent
# makes to another over A2A (agentgateway's external authorization), and for each answer
# the called agent sends back (agentgateway's external processing; phase "response").
#
# Input:
#   kind:       "a2a"
#   phase:      "request" (the call; the default) | "response" (an answer, or an event
#               of a streamed one)
#   method:     the A2A operation: "SendMessage", "SendStreamingMessage", "GetTask",
#               "CancelTask"..., or "GetAgentCard" for the agent's card; "answer" for
#               an answer
#   agent:      {"agent_id", "client_id"}      (the caller, from the validated JWT)
#   target:     the called agent's name in the registry
#   user:       the person the call is for, if any (see agentgov.context): the caller's
#               token's person, or the person who started the chain
#   chain:      who handed the call to the caller, in order: [{"type": "person" |
#               "agent", "id", "name"}], from the delegation the gateway gave the
#               caller; empty when the caller acts on its own
#   detections: {"categories": ["pii","secret"], "entities": [...]} in the message or
#               the answer, and for an answer "prompt_injection": bool
#
# Identity, lifecycle, the registry and the chain's limits always apply: no agent calls
# itself or an agent already in its chain, and a chain holds at most max_depth agents.
# The controls apply as their features say (see agentgov.mcp). Organisation policies
# under agentgov.custom.* take part through deny (always), require_approval (on calls, as
# the approvals control is) and redact (in answers, as data-protection is); they tell
# agents' calls from others by input.kind == "a2a", answers by input.phase == "response",
# and can read input.chain.
package agentgov.a2a

import data.agentgov.context as ctx

phase := object.get(input, "phase", "request")

# Agents in one chain, the caller and the called agent included.
max_depth := 5

detections := object.get(input, "detections", {})

categories contains c if some c in object.get(detections, "categories", [])

target_id := data.registry.agent_names[input.target]

target := data.registry.agents[target_id]

chain := object.get(input, "chain", [])

chain_agents := [c | some c in chain; c.type == "agent"]

depth := count(chain_agents) + 2

path := concat(" > ", array.concat([c.name | some c in chain], [ctx.agent.name, input.target]))

# ---------------------------------------------------------------------------
# Always applied.
# ---------------------------------------------------------------------------

deny contains "Caller is not a registered agent" if not ctx.agent

deny contains msg if {
	ctx.agent.status != "active"
	msg := sprintf("Agent %s is %s", [ctx.agent.name, ctx.agent.status])
}

deny contains msg if {
	not target
	msg := sprintf("Agent %q is not registered", [input.target])
}

deny contains msg if {
	target.status != "active"
	msg := sprintf("Agent %s is %s", [target.name, target.status])
}

deny contains msg if {
	target
	not target.a2a
	msg := sprintf("Agent %s doesn't serve A2A", [target.name])
}

deny contains msg if {
	target_id == ctx.agent_id
	msg := sprintf("Agent %s can't call itself", [target.name])
}

# A loop: the call would come back to an agent that is already waiting on it.
deny contains msg if {
	some c in chain_agents
	c.id == target_id
	msg := sprintf("Agent %s is already in this chain (%s)", [target.name, path])
}

deny contains msg if {
	depth > max_depth
	msg := sprintf("The chain would hold %d agents, more than %d (%s)", [depth, max_depth, path])
}

deny contains msg if {
	some name
	some msg in data.agentgov.custom[name].deny
}

# ---------------------------------------------------------------------------
# Controls.
# ---------------------------------------------------------------------------

# Granted by the agent's blueprint, its own agent access, or an access package it holds.
granted if ctx.agent_granted(input.target)

violation contains {"control": "least-privilege", "effect": "deny", "message": msg} if {
	phase == "request"
	ctx.agent.status == "active"
	target
	not granted
	msg := sprintf("Agent %s may not call agent %s", [ctx.agent.name, input.target])
}

# Access packages: an agent only an expired package lets it call.
violation contains {"control": "access-packages", "effect": "deny", "message": msg} if {
	phase == "request"
	ctx.agent.status == "active"
	target
	names := ctx.expired_agent_grants(input.target)
	count(names) > 0
	msg := sprintf("Agent %s was let call agent %s by access package %s, which has expired", [ctx.agent.name, input.target, concat(", ", sort(names))])
}

violation contains {
	"control": "data-protection",
	"effect": "deny",
	"message": "The message contains credentials; agents must not send secrets to other agents",
} if {
	phase == "request"
	"secret" in categories
}

# The caller acts for the person as its blueprint allows; so must the agent it hands
# the call to, which acts for that person from then on.
violation contains {"control": "acting-for-people", "effect": "deny", "message": msg} if {
	phase == "request"
	ctx.agent.status == "active"
	some msg in ctx.person_refusals
}

violation contains {"control": "acting-for-people", "effect": "deny", "message": msg} if {
	phase == "request"
	some msg in target_person_refusals
}

violation contains {"control": "risk-based-access", "effect": "deny", "message": msg} if {
	ctx.agent.risk_level == "critical"
	msg := sprintf("Agent %s is critical risk (score %d) and is blocked until investigated", [ctx.agent.name, ctx.agent.risk_score])
}

violation contains {"control": "risk-based-access", "effect": "deny", "message": msg} if {
	target.risk_level == "critical"
	msg := sprintf("Agent %s is critical risk (score %d): no agent may call it until it is investigated", [target.name, target.risk_score])
}

violation contains {"control": "approvals", "effect": "require_approval", "message": msg} if {
	phase == "request"
	some name
	some msg in data.agentgov.custom[name].require_approval
}

# An answer that carries instructions aimed at the agent reading it is withheld, as a
# tool result that carries them is.
violation contains {"control": "prompt-injection", "effect": "deny", "message": msg} if {
	phase == "response"
	detections.prompt_injection == true
	msg := sprintf("Answer from agent %s withheld: it contains instructions aimed at the agent (possible prompt injection)", [input.target])
}

deny contains v.message if {
	some v in violation
	v.effect == "deny"
	ctx.enforced(v.control)
}

require_approval contains v.message if {
	some v in violation
	v.effect == "require_approval"
	ctx.enforced(v.control)
}

# ---------------------------------------------------------------------------
# Whom the called agent may act for, as its blueprint says.
# ---------------------------------------------------------------------------

target_acts_for := object.get(target, "acts_for", "either")

target_groups := object.get(target, "people_groups", [])

target_person_refusals contains msg if {
	target_acts_for == "people"
	not ctx.user
	msg := sprintf("Agent %s acts only for people, and this call is on no one's behalf", [target.name])
}

target_person_refusals contains msg if {
	target_acts_for == "itself"
	ctx.user
	msg := sprintf("Agent %s acts only on its own behalf, and this call is on behalf of %s", [target.name, ctx.user_name])
}

target_person_refusals contains msg if {
	ctx.user
	count(target_groups) > 0
	not in_target_groups
	msg := sprintf("Agent %s acts only for people in %s, and %s is in none of them", [target.name, concat(", ", target_groups), ctx.user_name])
}

in_target_groups if {
	some group in target_groups
	ctx.member_of(group)
}

# ---------------------------------------------------------------------------
# Masking in answers (data loss prevention), the data-protection control:
# credentials, and personal data unless the agent reading it may have it.
# ---------------------------------------------------------------------------

to_mask contains "secret" if {
	phase == "response"
	"secret" in categories
}

to_mask contains "pii" if {
	phase == "response"
	"pii" in categories
	ctx.label("pii-access") != "true"
}

to_mask contains category if {
	phase == "response"
	some name
	some category in data.agentgov.custom[name].redact
}

redact contains category if {
	ctx.enforced("data-protection")
	some category in to_mask
}

# ---------------------------------------------------------------------------
# What monitored controls would have done. The call goes through.
# ---------------------------------------------------------------------------

monitored contains sprintf("%s: %s", [v.control, v.message]) if {
	some v in violation
	ctx.monitored(v.control)
}

monitored contains sprintf("data-protection: would mask %s", [category]) if {
	ctx.monitored("data-protection")
	some category in to_mask
	category in categories
}

# ---------------------------------------------------------------------------
# Decision.
# ---------------------------------------------------------------------------

effect := "deny" if {
	count(deny) > 0
} else := "require_approval" if {
	count(require_approval) > 0
} else := "allow"

reasons := sort(deny) if {
	effect == "deny"
} else := sort(require_approval) if {
	effect == "require_approval"
} else := []

agent_summary := {
	"id": ctx.agent_id,
	"name": ctx.agent.name,
	"status": ctx.agent.status,
	"risk_level": ctx.agent.risk_level,
} if {
	ctx.agent
} else := null

target_summary := {
	"id": target_id,
	"name": target.name,
	"status": target.status,
} if {
	target
} else := null

decision := {
	"effect": effect,
	"allow": effect == "allow",
	"reasons": reasons,
	"redact": sort(redact),
	"monitored": sort(monitored),
	"agent": agent_summary,
	"target": target_summary,
}
