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
