# Agents on other platforms

Agents built on a cloud's or a SaaS vendor's agent platform don't call tools through
AgentGov's gateway, so AgentGov can't sit in front of them. It can read what their platform
reports about them, as it does for [Microsoft 365 and Copilot Studio](platforms.md): each
agent becomes a registry agent, its risky settings become findings, and both stay in the
same registry, risk scores and evidence ledger as every other agent.

**AgentGov reads these platforms; it doesn't change them.** Blocking or deleting one of
their agents in AgentGov records the decision in the registry and the ledger, but the agent
keeps running: stop it in its platform's console as well.

| Platform | What AgentGov reads | Set up |
|---|---|---|
| AWS | Amazon Bedrock agents, AgentCore harnesses and AgentCore agent runtimes | [AWS](#aws) |

Each platform is read where its settings are set, when the control plane starts and every
hour after that (`AGENTGOV_PLATFORM_SYNC_INTERVAL_SECONDS`; `0` reads only on demand). Admins
can read one at any time with **Sync now** on the Platforms page or `agentgov platforms sync
aws`. Each has a switch on the [Features](features.md) page (on by default) that stops it
being read, even where it could be.

## What AgentGov does with each agent

Each agent the platform reports becomes a registry agent with the source `platform:<platform>`
(`platform:aws`), its platform's name for what it is (an Amazon Bedrock agent), and a card on
its page with what the platform reports: its settings, its tools and a link to it in the
platform's console. It starts as `discovered`, with an "agent to review" finding: adopt it to
give it an owner, sponsors and periodic attestation, like any other agent. AgentGov issues
these agents no gateway credentials and doesn't apply blueprints to them, because they never
call the gateway.

AgentGov reads each platform in parts (an AWS account's region). Agents gone from a part
it read in full stay in the registry, marked as gone, so their history is kept: delete them
when you no longer need the record. A part that can't be read (its region refuses, say) is
named on the Platforms page; its agents are left as the last sync saw them, and their findings
stay open, marked unverified, until it can be read again.

AgentGov never copies secrets: of an agent's environment variables, it keeps only their
names. Its instructions (a system prompt) go through the same [instruction
checks](instructions.md) as every agent's.

## Checks

AgentGov raises a finding for each risky setting it finds. A finding resolves itself once two
syncs in a row find the setting fixed. Open findings count towards the agent's risk score, so
a risky agent also gets a high-risk alert; dismissing one (an accepted risk) takes it out of
the score.

| Finding | Risk points | Raised when |
|---|---|---|
| `platform.no_authentication` | 25 | anyone who can reach the agent can use it |
| `platform.plain_secret` | 20 | its settings hold what looks like a secret in plain text, rather than a reference to a secret store |
| `platform.weak_authentication` | 15 | it checks callers' tokens, but takes a token for any audience or client |
| `platform.broad_identity` | 15 | it runs as a broad or default identity rather than one of its own |
| `platform.risky_tool` | 15 | its tools run code or work a computer, so a prompt injection acts too |
| `platform.shared_with_everyone` | 10 | everyone in the organisation may use it |
| `platform.no_guardrail` | 10 | nothing filters what it is asked or what it answers |

Each platform's section below says which of them it checks, and how.

## AWS

AgentGov reads, in each region and account you name:

* **Amazon Bedrock agents** (Agents for Amazon Bedrock, which AWS now calls Agents Classic
  and keeps in maintenance): each agent's working draft, with its model, guardrail, the role
  it runs as, its action groups (its tools), knowledge bases and aliases, and its instructions.
* **AgentCore harnesses**, AWS's managed agents: their model, tools and the tools they may
  use, system prompt, the runtime behind them, how they check callers, and the names of their
  environment variables.
* **AgentCore agent runtimes**, agents and MCP servers you deploy yourself: their protocol,
  how they check callers, their resource policy, outbound network, the role they run as and
  their container. A runtime behind a harness is shown as the harness.

AgentCore gateways, AWS's Agent Registry and Amazon Quick's agents aren't read yet.

| Check | Raised when |
|---|---|
| `platform.no_guardrail` | a Bedrock agent has no guardrail |
| `platform.risky_tool` | an agent has computer use, a shell or a text editor (high), or a code interpreter or a browser (medium) |
| `platform.weak_authentication` | a harness or runtime checks callers' tokens without allowed audiences or clients, so a token issued to another application gets in |
| `platform.no_authentication` | a runtime that checks AWS credentials has a resource policy that lets any AWS principal in, with no condition |
| `platform.plain_secret` | an environment variable whose name says it holds a secret (a password, token or key) has a value that isn't a reference to Secrets Manager or Parameter Store |

### Setting it up

1. Give AgentGov AWS credentials that may read the agents. In each account, a role (or user)
   with this policy:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "bedrock:ListAgents", "bedrock:GetAgent", "bedrock:ListAgentActionGroups",
           "bedrock:GetAgentActionGroup", "bedrock:ListAgentKnowledgeBases",
           "bedrock:ListAgentAliases",
           "bedrock-agentcore:ListHarnesses", "bedrock-agentcore:GetHarness",
           "bedrock-agentcore:ListAgentRuntimes", "bedrock-agentcore:GetAgentRuntime",
           "bedrock-agentcore:GetResourcePolicy"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

   AWS's `ReadOnlyAccess` covers the Bedrock agent actions but AgentCore has no read-only
   managed policy, so use this one. An agent encrypted with a key of yours also needs
   `kms:Decrypt` on that key; without it, AgentGov records the agent from what the list
   shows and says what it couldn't read.
2. Give the control plane the credentials, from wherever AWS's SDKs find them:
   `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`; on EKS, IAM roles for service accounts or
   Pod Identity on its service account ([AWS](deploy/aws.md)); or an EC2 instance's role.
   AgentGov doesn't read profiles or SSO from `~/.aws`: to try it on your machine, export a
   profile's credentials with `aws configure export-credentials --format env`.
3. Name the regions to read, and any other accounts' roles to assume with those credentials:

   ```bash
   AGENTGOV_AWS_REGIONS=us-east-1,eu-west-1
   AGENTGOV_AWS_ROLE_ARNS=arn:aws:iam::444455556666:role/agentgov-reader
   AGENTGOV_AWS_EXTERNAL_ID=...   # if those roles' trust policies ask for one
   ```

AgentGov signs its requests itself (Signature Version 4), without the AWS SDK. A region that
doesn't offer Bedrock agents or AgentCore is skipped; one that refuses is named on the
Platforms page.

## Doing it from the CLI or the API

| Task | Admin UI | CLI | API |
|---|---|---|---|
| See each platform and its last sync | Platforms > Other platforms | `agentgov platforms status` | `GET /v1/platforms` |
| Read a platform now | Platforms > Other platforms > **Sync now** | `agentgov platforms sync aws` | `POST /v1/platforms/aws/sync` |
| List one platform's agents | Platforms > *n agents* | `agentgov agents list --source platform:aws` | `GET /v1/agents?source=platform:aws` |
| What the platform reports about one agent | Agent page | `agentgov agents get REF` | `platforms` in `GET /v1/agents/{ref}` |

Auditors and approvers can see everything here; reading a platform on demand needs an admin.
