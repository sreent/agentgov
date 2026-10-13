"""Open Policy Agent integration: bundle distribution, Rego validation, decisions."""

# In the input of a what-if question from the policies page: OPA doesn't log its answer as
# a decision (agentgov.opa.bundle), and the ledger doesn't record it.
WHAT_IF = "agentgov_what_if"
