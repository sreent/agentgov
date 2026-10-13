# The demo

The whole stack on Docker Compose, and a demo agent that goes through every control in
turn. You need Docker with Compose v2, Python 3.11 or later, and about 4 GB of free memory
([requirements](requirements.md)).

```bash
git clone https://github.com/sreent/ai-agent-governance-platform.git
cd ai-agent-governance-platform
docker compose -f deploy/compose/docker-compose.yml up -d --build --wait

python -m venv .venv && . .venv/bin/activate
pip install -e ".[demo]"
export AGENTGOV_TOKEN=dev-admin-token
agentgov apply -f examples/manifests      # blueprints, the CRM tool server, a model, agents, a policy, an identity issuer, the SOC's destinations and its hand-off level, teams and an access package
python examples/agents/demo_agent.py
```

The stack listens on this machine only, with tokens and passwords everybody knows: it is
for evaluation ([running it locally](deploy/local.md)).

The demo registers a new agent and drives a real MCP client and model calls through
the gateway. It shows each control in turn:

1. **Registration**: the agent is requested, approved and given its own identity.
2. **Least privilege**: the agent only sees the tools its blueprint grants.
3. **Data loss prevention**: personal data in tool results is masked.
4. **Credentials never leave**: a secret in tool arguments is blocked.
5. **Indirect prompt injection**: a poisoned tool result is withheld.
6. **Ungranted tools** are refused even when called directly.
7. **Monitor mode**: with least privilege monitored, the same call goes through and the
   ledger records what would have stopped it; enforced again, it is refused. Monitored
   for the customer-support blueprint's agents only (an
   [exception](features.md#exceptions)), it goes through again; without the
   exception, it is refused.
8. **Human in the loop**: a destructive tool waits for an approver; once approved, the
   agent's retry goes through.
9. **Access packages**: alice, the agent's sponsor, asks for the crm-export package for it;
   she can't approve her own request, an administrator does, and the agent can export
   customers until the package is revoked (or would expire, a week later).
10. **Model calls**: the agent calls a model through the gateway with its own token,
    never the provider's key. Personal data in the prompt is masked, an ungranted model
    is refused, credentials are kept out of prompts and answers, and once the agent's
    metered tokens reach its daily budget, its calls are refused. A jailbreak attempt
    goes through but is recorded: jailbreak detection starts in monitor mode.
11. **Acting for people**: sam signs in to the demo chat app, and the agent exchanges
    sam's token for one of its own: it acts for sam as its blueprint allows, only for
    people in the groups the blueprint names, and sam approves what it wants to do for
    them.
12. **Agent to agent**: the agent hands sam's question to a billing agent over A2A,
    through the gateway. The billing agent learns who asked and for whom, whatever the
    caller claims, and its own call to the CRM carries the chain `sam > agent >
    billing-agent` into policy and the ledger. A made-up delegation is refused, and so
    is the call once the blueprint no longer grants it. The billing agent may read
    customers' contact details, and the agent that asked may not: the gateway masks them
    in the answer. With masking in messages enforced, an email in what the agent asks
    reaches the billing agent whole, as it may have personal data. A call straight to the
    billing agent's own URL, around the gateway, is refused by the billing agent itself:
    it checks the delegation the gateway gives with each call, and AgentGov's test shows
    it.
13. **Kill switch**: blocking the agent takes effect everywhere within a second (with the
    chart's two control-plane replicas, whichever one took the block).
14. **Own identities**: an agent with no client secret at all authenticates with its
    service account token from a stand-in Kubernetes cluster, and calls a tool; blocking
    the cluster's issuer stops Keycloak taking its tokens.
15. **Shadow AI**: telemetry from an unregistered agent adds it as unmanaged.
16. **Developer tools**: the MCP servers approved for developers are served as an MCP
    registry for GitHub Copilot, and a developer's laptop
    ([examples/developer-machine](../examples/developer-machine)) reports its MCP servers:
    those that aren't approved, or skip the gateway, raise issues.
17. **Security operations**: the SOC's stand-in SIEM has the ledger as OCSF events, its
    Splunk the decisions and issues that matter, and its Slack and Teams the alerts;
    its SOAR's `secops` key is refused a block at the `inform` level, and blocks the
    shadow agent once the level is `contain`.
18. **Issues**: the agent's issues went to its owner, the cx-platform team, in its own
    Slack channel, and the issues no team owns to the AI governance team's Teams channel;
    alice, in cx-platform, sees them in AgentGov and acknowledges one.
19. **Management rules**: a rule that deletes agents blocked for 30 days matches the demo
    agent, blocked in step 13. Enforced, it tells the agent's owner and sponsor first, with
    the date. alice, its sponsor, can't accept the risk; an administrator accepts it until
    a later date, and the rule leaves the agent be.
20. **Evidence**: every decision is in a ledger whose hash chain verifies. An
    administrator keeps a checkpoint of it, which a time-stamping authority signs (the
    sink stands in for one) and OpenSSL verifies, and which goes into a transparency log
    (the stack's own Rekor), whose proof is checked offline; then the EU AI Act report and
    the evidence pack.
21. **Deeper detection**: a customer's notes ask the agent, in plain words, to wire money.
    The rules see data and let the result through; a classifier (the mock model stands in
    for IBM Granite Guardian) flags it in the background, and once the classifier is
    enforced, the same result is withheld ([detection](detection.md)).
22. **AuthZEN**: another enforcement point asks AgentGov's policies, in the standard way,
    whether the billing agent may call two tools: one it was granted, and one it wasn't
    ([AuthZEN](policies.md#authzen)).
23. **Developers sign in at the gateway**: an MCP client that calls a tool server on the
    gateway without a token is told where to sign in. dana, a developer, signs in to the
    coding-assistant agent in a browser, as an MCP client has developers do, and calls the
    CRM with dana's own token: the ledger names dana and the agent. sam, who isn't a
    developer, is refused ([developer tools](developer-tools.md#signing-in-at-the-gateway)).
24. **Servers outside the gateway**: dana's MCP client gets an identity assertion (ID-JAG)
    from AgentGov for the wiki, a server with an authorization server of its own, which it
    would trade there for an access token; sam's is refused, and both are in the ledger
    ([acting for people](acting-for-people.md#mcp-servers-outside-the-gateway)).
25. **Signing out everywhere**: alice signs in to AgentGov, then signs out at Keycloak
    itself; Keycloak tells AgentGov, and her AgentGov session ends at once
    ([administration](administration.md#signing-out-everywhere)).
26. **Is it working?**: the governance processor has told the control plane what it can
    reach, OPA and Presidio, so least privilege and data protection can do what their
    modes say ([features](features.md#is-it-working)); and what it does when OPA
    can't decide, and what the monitor-first starting point would change
    ([when something is down](features.md#when-something-is-down),
    [starting points](features.md#starting-points)).

Then look around:

* Admin UI: <http://localhost:8000/ui>. Choose *Sign in with single sign-on* and use
  `admin` (administrator), `alice` (approver, and the demo agent's sponsor), `sofia`
  (security operations) or `audrey` (auditor), all with the password `dev-password`; or
  paste the API token `dev-admin-token`
* What the security team's tools got: <http://localhost:9300/received> (the demo sink)
* API reference: <http://localhost:8000/docs>
* CLI: `agentgov agents list`, `agentgov issues`, `agentgov approvals list`,
  `agentgov ledger verify`. The CLI can do everything the UI can
  ([Administration](administration.md) maps one to the other)
* Keycloak: <http://localhost:8180> (`admin` / `admin`), realm `agentgov`, which has one
  client per agent

[Running it locally](deploy/local.md) has every endpoint and demo user, and the optional
Langfuse for exploring traces.
