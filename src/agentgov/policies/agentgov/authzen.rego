# AgentGov's decisions as an AuthZEN decision point (OpenID AuthZEN Authorization API
# 1.0, https://openid.net/specs/authorization-api-1_0.html).
#
# The control plane answers AuthZEN evaluations (POST /access/v1/evaluation) with
# data.agentgov.authzen.evaluation, so that an enforcement point that speaks AuthZEN, and
# not AgentGov's own input, can ask the same policies. The request names who (subject),
# what (action) and what on (resource); AgentGov's decision for that call comes back as
# AuthZEN's: true or false, with why in the context.
#
# Input (an AuthZEN evaluation request):
#   subject:  {"type": "agent", "id": <agent ID or client ID>}
#             or {"type": "user", "id": <person>, "properties": {username, email, groups,
#             roles}}, with the agent acting for them in context.agent
#   action:   {"name": "tools/call" | "chat" | "SendMessage" | ...}
#   resource: {"type": "tool", "id": "<server>/<tool>"} | {"type": "model", "id":
#             "<provider>/<model>"} | {"type": "agent", "id": "<agent called>"}
#   context:  agent: the agent acting for the subject (its ID, client ID, or {"agent_id",
#             "client_id"}); user: the person an agent subject acts for; chain: who handed
#             the work down; detections: what was found in the call; agentgov: more of
#             AgentGov's own input, merged in (see agentgov.mcp, agentgov.models,
#             agentgov.a2a)
#
# Output (an AuthZEN evaluation response):
#   decision: true when AgentGov allows the call
#   context:  reason ("allowed" | "denied" | "approval_required"), reasons, monitored,
#             obligations (a custom one, vendor agentgov, to mask the personal data
#             categories listed: an enforcement point that can't must deny), and agentgov
#             (AgentGov's own decision: effect, and the agent and target it knows)
package agentgov.authzen

subject := object.get(input, "subject", {})

action := object.get(input, "action", {})

resource := object.get(input, "resource", {})

context := object.get(input, "context", {})

properties(x) := object.get(x, "properties", {})

# The agent: the subject, or the agent acting for the person who is.
agent_ref(x) := x if is_object(x)

agent_ref(x) := {"agent_id": x} if {
	is_string(x)
	data.registry.agents[x]
}

agent_ref(x) := {"client_id": x} if {
	is_string(x)
	not data.registry.agents[x]
}

agent := agent_ref(subject.id) if subject.type == "agent"

agent := agent_ref(context.agent) if {
	subject.type != "agent"
	context.agent
}

agent := {} if {
	subject.type != "agent"
	not context.agent
}

person := object.union({"id": subject.id}, properties(subject)) if subject.type == "user"

person := context.user if {
	subject.type != "user"
	is_object(context.user)
}

with_person := {"user": person} if person

with_person := {} if not person

# (A built-in's argument is evaluated outside "not": hence a default, never undefined.)
chain := object.get(context, "chain", null)

with_chain := {"chain": chain} if is_array(chain)

with_chain := {} if not is_array(chain)

# "<a>/<b>" as its two parts; properties name them too.
split_id(key_a, key_b) := [a, b] if {
	a := properties(resource)[key_a]
	b := properties(resource)[key_b]
} else := [a, b] if {
	[a, b] := split(resource.id, "/")
} else := [resource.id, ""]

common := object.union_n([
	{
		"phase": "request",
		"agent": agent,
		"detections": object.get(context, "detections", {"categories": []}),
	},
	with_person,
	with_chain,
])

mcp_input := object.union_n([
	common,
	{
		"method": object.get(action, "name", "tools/call"),
		"resource": {"server": parts[0], "name": parts[1]},
		"arguments": {},
	},
	object.get(context, "agentgov", {}),
]) if {
	resource.type == "tool"
	parts := split_id("server", "name")
}

model_input := object.union_n([
	common,
	{"kind": "model", "provider": parts[0], "model": parts[1]},
	object.get(context, "agentgov", {}),
]) if {
	resource.type == "model"
	parts := split_id("provider", "model")
}

a2a_input := object.union_n([
	common,
	{"kind": "a2a", "method": object.get(action, "name", "SendMessage"), "target": resource.id},
	object.get(context, "agentgov", {}),
]) if resource.type == "agent"

decision := d if {
	resource.type == "tool"
	d := data.agentgov.mcp.decision with input as mcp_input
}

decision := d if {
	resource.type == "model"
	d := data.agentgov.models.decision with input as model_input
}

decision := d if {
	resource.type == "agent"
	d := data.agentgov.a2a.decision with input as a2a_input
}

reason := {"allow": "allowed", "deny": "denied", "require_approval": "approval_required"}

obligations := [{
	"id": "agentgov-redact",
	"type": "custom",
	"properties": {"vendor": "agentgov", "action": "redact", "categories": decision.redact},
}] if {
	decision.effect == "allow"
	count(decision.redact) > 0
} else := []

evaluation := {
	"decision": decision.effect == "allow",
	"context": {
		"reason": reason[decision.effect],
		"reasons": decision.reasons,
		"monitored": decision.monitored,
		"obligations": obligations,
		"agentgov": {
			"effect": decision.effect,
			"agent": decision.agent,
			"target": object.get(decision, "target", null),
		},
	},
} if decision

evaluation := {
	"decision": false,
	"context": {
		"reason": "denied",
		"reasons": [sprintf(
			"AgentGov decides calls to tools, models and agents (resource type tool, model or agent), not %v",
			[object.get(resource, "type", "nothing")],
		)],
		"monitored": [],
		"obligations": [],
	},
} if not decision
