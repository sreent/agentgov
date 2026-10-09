# Example organisation policy. Custom policies live in agentgov.custom.<name>
# and may add to deny, require_approval and redact. They see the same input
# as the built-in library and can use its context helpers.
package agentgov.custom.prod_verified_only

import data.agentgov.context as ctx

deny contains msg if {
	input.phase == "request"
	ctx.agent.environment == "prod"
	ctx.server.trust_level != "verified"
	msg := sprintf("Production agents may only use verified tool servers (%s is %s)", [ctx.server.name, ctx.server.trust_level])
}
