# Shared context for AgentGov policies: who is calling, what they are calling,
# and what they are allowed to call. Registry state arrives in OPA through the
# control plane's bundle under data.registry.
package agentgov.context

registry := data.registry

# How strictly each feature applies (agentgov.registry.features). Controls are
# "off", "monitor" or "enforce"; a bundle without modes, or a test, enforces them.
features := object.get(registry, "features", {})

mode(key) := object.get(features, key, "enforce")

enforced(key) if mode(key) == "enforce"

monitored(key) if mode(key) == "monitor"

# The calling agent, resolved from claims the gateway has already validated
# (the agent_id claim first, then the OAuth client id).
agent_id := id if {
	id := input.agent.agent_id
	registry.agents[id]
} else := id if {
	id := registry.clients[input.agent.client_id]
} else := id if {
	# Copilot Studio's tool calls: the control plane has already matched the agent.
	input.platform == "copilot-studio"
	id := input.agent.id
	registry.agents[id]
}

agent := registry.agents[agent_id]

server := registry.toolservers[input.resource.server]

# Catalog entry for the tool being called; empty when the catalog has not been
# synchronised yet.
tool := object.get(object.get(server, "tools", {}), input.resource.name, {})

annotations := object.get(tool, "annotations", {})

# glob match in which "*" spans every character, including "." and "/".
matches(pattern, value) if glob.match(pattern, ["\u0000"], value)

# True when one of the agent's grants (blueprint + agent-specific) covers the tool.
granted(server_name, tool_name) if {
	some grant in agent.grants
	matches(grant.server, server_name)
	some pattern in grant.tools
	matches(pattern, tool_name)
}

label(name) := value if {
	value := agent.labels[name]
} else := ""

# The person the agent acts for, when it acts for one, from the token it got for them
# (agentgov.identity.people): {"id", "username", "email", "groups", "roles", "via"},
# where via is "delegation" (the person delegated to the agent) or "exchange". Undefined
# while the agent acts on its own.
user := input.user if input.user.id

user_name := object.get(user, "username", object.get(user, "email", user.id))

# Whether the person is in a group, named with or without its path's leading "/"
# (Keycloak's group claims hold "/support" or "support", as their mapper says).
member_of(group) if {
	some g in object.get(user, "groups", [])
	trim_prefix(g, "/") == trim_prefix(group, "/")
}

# Who the agent may act for, as its blueprint says (acting-for-people): "people",
# "itself" or "either", and the groups the people must be in (none: anyone).
acts_for := object.get(agent, "acts_for", "either")

people_groups := object.get(agent, "people_groups", [])

in_people_groups if count(people_groups) == 0

in_people_groups if {
	some group in people_groups
	member_of(group)
}

person_refusals contains msg if {
	acts_for == "people"
	not user
	msg := sprintf("Agent %s acts only for people, and this call is on no one's behalf", [agent.name])
}

person_refusals contains msg if {
	acts_for == "itself"
	user
	msg := sprintf("Agent %s acts only on its own behalf, and this call is on behalf of %s", [agent.name, user_name])
}

person_refusals contains msg if {
	user
	not in_people_groups
	msg := sprintf("Agent %s acts only for people in %s, and %s is in none of them", [agent.name, concat(", ", people_groups), user_name])
}
