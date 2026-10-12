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
| Google Cloud | Agent Runtime agents (formerly Vertex AI Agent Engine) | [Google Cloud](#google-cloud) |
| Salesforce | Agentforce agents, with their topics and actions | [Salesforce](#salesforce) |
| Databricks | Agents on Model Serving, Agent Bricks agents and Genie agents | [Databricks](#databricks) |

Each platform is read where its settings are set, when the control plane starts and every
hour after that (`AGENTGOV_PLATFORM_SYNC_INTERVAL_SECONDS`; `0` reads only on demand). Admins
can read one at any time with **Sync now** on the Platforms page or `agentgov platforms sync
<platform>` (`aws`, `google-cloud`, `salesforce` or `databricks`). Each has a switch on the
[Features](features.md) page (on by default) that stops it being read, even where it could be.

## What AgentGov does with each agent

Each agent the platform reports becomes a registry agent with the source `platform:<platform>`
(`platform:aws`), its platform's name for what it is (an Amazon Bedrock agent), and a card on
its page with what the platform reports: its settings and its tools. It starts as
`discovered`, with an "agent to review" finding: adopt it to give it an owner, sponsors and
periodic attestation, like any other agent. AgentGov issues these agents no gateway
credentials and doesn't apply blueprints to them, because they never call the gateway.

AgentGov reads each platform in parts (an AWS account's region, a Google Cloud project's
region, a Salesforce org, a Databricks workspace's agents on Model Serving). Agents gone from a
part it read in full stay in the registry, marked as gone, so their history is kept: delete
them when you no longer need the record. A part that can't be read (its region refuses, say) is
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
| `platform.broad_identity` | 15 | it runs as, or calls its platform with, an identity that may do far more than its job: a default or shared one, or one with broad permissions |
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
* **AgentCore gateways**, the MCP servers AgentCore runs in front of tools: how they check
  callers, their resource policy, policy engine, interceptors and web ACL, the role they run
  as, the instructions they give agents, and their targets (their tools) with how the
  gateway signs in to each. Like the runtimes that serve MCP, they are listed with the
  agents, so their risky settings count the same way. Of a target's URL only the host is
  kept, and nothing of its parameters or credentials.

AWS's Agent Registry and Amazon Quick's agents aren't read yet.

| Check | Raised when |
|---|---|
| `platform.no_guardrail` | a Bedrock agent has no guardrail |
| `platform.risky_tool` | an agent has computer use, a shell or a text editor (high), or a code interpreter or a browser (medium) |
| `platform.weak_authentication` | a harness, runtime or gateway checks callers' tokens without allowed audiences or clients, so a token issued to another application gets in |
| `platform.no_authentication` | a gateway has no inbound authorization (high: anyone who can reach it may call its tools), or a runtime or gateway that checks AWS credentials has a resource policy that lets any AWS principal in, with no condition |
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
           "bedrock-agentcore:ListGateways", "bedrock-agentcore:GetGateway",
           "bedrock-agentcore:ListGatewayTargets", "bedrock-agentcore:GetGatewayTarget",
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
   shows and says what it couldn't read. A policy without the gateway actions leaves the
   agents read, and the Platforms page says the gateways couldn't be.
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

## Google Cloud

AgentGov reads the **Agent Runtime agents** (Agent Runtime was Vertex AI Agent Engine; its API
calls them reasoning engines) in each project and region you name: the identity each runs as,
how it reaches networks, the names of its environment variables and of those it takes from
Secret Manager, its encryption key, memory bank and container, and who may use it, from its
IAM policy.

Gemini Enterprise's agents and Agent Platform's managed agents aren't read: Google's APIs list
them only to the person who created them, so they can't give AgentGov an organisation's. An
agent built with the ADK and added to Gemini Enterprise runs on Agent Runtime, where AgentGov
reads it. Agent Registry, which also lists agents on Cloud Run and GKE, isn't read yet.

| Check | Raised when |
|---|---|
| `platform.no_authentication` | its IAM policy grants a role to `allUsers` or `allAuthenticatedUsers` |
| `platform.shared_with_everyone` | its IAM policy grants a role to a whole domain |
| `platform.broad_identity` | it runs as a default service account, Compute Engine's or App Engine's, which Google makes an editor of the project (high), or as the project's Agent Runtime service agent, which every agent without an identity of its own shares (medium) |
| `platform.plain_secret` | an environment variable whose name says it holds a secret has a plain value rather than one from Secret Manager, or `GOOGLE_APPLICATION_CREDENTIALS` is set (a service account key shipped with the agent) |

An agent whose IAM policy AgentGov may not read is shown as such, and its findings about who
may use it are left as they were.

### Setting it up

1. Give AgentGov's identity a role that may read the agents, in each project. Make one with
   only what it needs:

   ```bash
   gcloud iam roles create agentgovAgentReader --project=PROJECT \
     --title="AgentGov agent reader" \
     --permissions=aiplatform.reasoningEngines.list,aiplatform.reasoningEngines.getIamPolicy,resourcemanager.projects.get
   gcloud projects add-iam-policy-binding PROJECT \
     --role=projects/PROJECT/roles/agentgovAgentReader --member=serviceAccount:READER
   ```

   Create it once in your organisation (`--organization`) instead to grant it in several
   projects. Google's Vertex AI Viewer role (`roles/aiplatform.viewer`) can read them too, but
   it reads much more of the project than AgentGov needs.
2. Give the control plane Google credentials, from where Google's libraries find them: on GKE,
   Workload Identity ([Google Cloud](deploy/gcp.md#agents-built-on-google-cloud)) or a VM's
   service account; elsewhere, the file `GOOGLE_APPLICATION_CREDENTIALS` names: a workload
   identity federation configuration, which trades the identity AgentGov runs with (on AWS,
   Azure or any OpenID Connect provider) for Google's without a key, or a service account key,
   which many organisations don't allow. To try it on your machine as yourself, sign in with
   `gcloud auth application-default login`.
3. Name the projects to read, and the regions their agents are in (`us` and `eu` for the
   multi-regions):

   ```bash
   AGENTGOV_GOOGLE_CLOUD_PROJECTS=contoso-agents,contoso-labs
   AGENTGOV_GOOGLE_CLOUD_REGIONS=us-central1,europe-west4
   ```

AgentGov gets its tokens itself, without Google's client libraries.

## Salesforce

AgentGov reads the **Agentforce agents** in your org: service agents, which talk to customers,
and employee agents, which people use inside Salesforce. For each, the version in use, its
topics with their instructions and their actions (its tools), the user a service agent runs
as and what that user may do, and who has an employee agent.

Einstein Bots aren't read: they aren't agents. Nor, yet, are the channels a service agent is
deployed on, so whether a channel lets people in without signing in isn't checked.

| Check | Raised when |
|---|---|
| `platform.broad_identity` | a service agent's user may modify or view all data, manage users, author Apex or modify metadata (high), or customize the application (medium) |
| `platform.shared_with_everyone` | an employee agent is given, through permission sets or profiles, to nine in ten or more of the org's active people |

Its topics' instructions go through the instruction checks, and its actions that reach outside
Salesforce (external services, MCP tools, APIs, integration procedures, Slack) are marked
among its tools. AgentGov uses the newest API version the org offers (60.0 or later); what an
org's release doesn't have yet is left out, and the agent's card says what wasn't read.

### Setting it up

1. Make an integration user for AgentGov, with a permission set that gives it **API Enabled**,
   **View Setup and Configuration** and, to count who has each employee agent, **View All
   Users**. Salesforce's own Salesforce Integration user licence fits.
2. Make an External Client App for AgentGov (Setup > External Client App Manager), with OAuth
   on and the `api` scope, and either:
   * the **client credentials flow** on, running as the integration user: AgentGov signs in
     with the app's consumer key and secret; or
   * the **JWT bearer flow**: upload a certificate to the app, pre-authorize the integration
     user, and give AgentGov the certificate's private key.
3. Name the org and the app:

   ```bash
   AGENTGOV_SALESFORCE_URL=https://contoso.my.salesforce.com   # Setup > My Domain
   AGENTGOV_SALESFORCE_CLIENT_ID=3MVG9...                      # the consumer key
   AGENTGOV_SALESFORCE_CLIENT_SECRET=...                       # the client credentials flow
   # or, for the JWT bearer flow:
   AGENTGOV_SALESFORCE_USERNAME=agentgov@contoso.com
   AGENTGOV_SALESFORCE_PRIVATE_KEY_FILE=/etc/agentgov/salesforce.key
   ```

## Databricks

AgentGov reads, in each workspace you name:

* **Agents on Model Serving**: serving endpoints whose task is an agent's, with what they
  serve, who may query them, whether their requests and answers are kept in inference tables,
  and the names of their environment variables. An endpoint that serves a **Knowledge
  Assistant** or a **Supervisor Agent** (Agent Bricks, whose APIs are in Beta) is shown as
  one, with its instructions and, for a supervisor, its subagents and tools.
* **Agent Bricks agents**: the Databricks Apps the Agent Bricks CLI deploys agents as (named
  `agent-bricks-…`), with who may use them, the service principal they run as and the
  resources it holds (their tools), and the scopes they act for their users with.
* **Genie agents** (Genie spaces), with who may ask them questions, the tables they answer
  from, and their instructions.

MCP services in Unity Catalog aren't read yet.

| Check | Raised when |
|---|---|
| `platform.shared_with_everyone` | the workspace's `users` group, or the account's `account users`, may use the agent |
| `platform.plain_secret` | an environment variable whose name says it holds a secret has its value in the agent's configuration, rather than from a secret scope (`{{secrets/scope/key}}`, or an app's `valueFrom`) |
| `platform.risky_tool` | a Supervisor Agent: every one can run the code its model writes (in a sandbox without internet access, reading the tables and volumes it is given) |
| `platform.broad_identity` | an agent on Model Serving calls Databricks with a fixed credential (`DATABRICKS_TOKEN` or `DATABRICKS_CLIENT_SECRET`), or an Agent Bricks agent's service principal may change, not only use, a resource (`CAN_MANAGE`, `IS_OWNER`, `MODIFY`, a secret scope's `WRITE` or `MANAGE`) |

Genie agents', Knowledge Assistants' and Supervisor Agents' instructions go through the
instruction checks. An agent whose permissions
AgentGov may not read is shown as such, and its findings about who may use it are left as
they were.

### Setting it up

1. Make a service principal for AgentGov in your Databricks account, give it an OAuth secret,
   and add it to each workspace to read. Databricks has no role that may read every endpoint,
   app and Genie space without changing them, so make it a workspace admin; a service
   principal that isn't sees only what it has been given.
2. Name the workspaces, and give AgentGov the service principal's credentials:

   ```bash
   AGENTGOV_DATABRICKS_HOSTS=https://dbc-1234.cloud.databricks.com,https://adb-5678.azuredatabricks.net
   AGENTGOV_DATABRICKS_CLIENT_ID=...       # the service principal's application ID
   AGENTGOV_DATABRICKS_CLIENT_SECRET=...   # its OAuth secret
   AGENTGOV_DATABRICKS_READ=serving,apps,genie   # leave out what you don't want read
   ```

   A personal access token (`AGENTGOV_DATABRICKS_TOKEN`) works too, for one workspace or
   several where it is valid, but Databricks recommends OAuth.

## Doing it from the CLI or the API

| Task | Admin UI | CLI | API |
|---|---|---|---|
| See each platform and its last sync | Platforms > Other platforms | `agentgov platforms status` | `GET /v1/platforms` |
| Read a platform now | Platforms > Other platforms > **Sync now** | `agentgov platforms sync google-cloud` | `POST /v1/platforms/google-cloud/sync` |
| List one platform's agents | Platforms > *n agents* | `agentgov agents list --source platform:google-cloud` | `GET /v1/agents?source=platform:google-cloud` |
| What the platform reports about one agent | Agent page | `agentgov agents get REF` | `platforms` in `GET /v1/agents/{ref}` |

Auditors and approvers can see everything here; reading a platform on demand needs an admin.
