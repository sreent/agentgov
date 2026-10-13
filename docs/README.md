# AgentGov documentation

## Get started

* [README](../README.md): what AgentGov is, how it works, and where to start
* [The demo](demo.md): the whole stack, and a demo agent that goes through every control
* [Run AgentGov on your machine](deploy/local.md): Docker Compose, Kubernetes with kind, or
  the control plane alone
* [Requirements](requirements.md): versions, resources, network, and accounts for the
  optional connections

## Deploy and run

* [Deploying AgentGov](deploy/README.md): choosing where, and a checklist before others
  rely on it
* [One server](deploy/server.md): Docker Compose on a Linux server, with HTTPS, for
  production without Kubernetes
* [Kubernetes](deploy/kubernetes.md): the Helm chart on any cluster, its values, upgrades,
  and checking the published image's signature
* [Google Cloud](deploy/gcp.md), [Azure](deploy/azure.md) and [AWS](deploy/aws.md): GKE,
  AKS and EKS with each cloud's database, secrets, load balancer and certificates
* [Configuration](configuration.md): every setting, where to set it, and which the
  deployment sets for you
* [Running in production](production.md): several control-plane replicas, people working
  at once, mutual TLS between the components, with certificates from SPIRE if you like, and
  signed policy bundles
* [Backing up and restoring](backup.md): what to back up, restoring, and a restored
  database's missing ledger entries noticed and recorded
* [Features](features.md): which parts of AgentGov you use, and how strictly
* [Administration](administration.md): signing in, roles, and every task in the admin UI,
  the CLI and the API
* [Glossary](glossary.md): the words AgentGov uses for each thing, and what the API calls
  them

## Govern agents

* [Policies](policies.md): the Rego library, blueprints, organisation policies and
  what-if
* [Model calls](models.md): model providers, which agents may call which models, usage,
  cost and token budgets
* [Developer tools](developer-tools.md): an MCP registry for GitHub Copilot and VS Code,
  and the MCP servers developers set up on their machines
* [Acting for people](acting-for-people.md): agents that act for a person, whom each may
  act for, and approvals sent to the person
* [Agents' own identities](agent-identity.md): Kubernetes service accounts, SPIFFE IDs and
  Microsoft Entra Agent ID instead of client secrets, through Keycloak or straight at the
  gateway
* [Agent to agent](agent-to-agent.md): calls between agents over A2A, their answers, and
  the chain of delegation
* [Agent instructions](instructions.md): checking agents' system prompts for harmful or
  malicious content
* [Detection](detection.md): what the gateway's rules catch, and a classifier's second
  opinion on tool results, people's prompts and agents' answers
* [Access packages](access-packages.md): tools, models and agents an agent holds for a
  while once approved, with reminders, renewals and reviews
* [Issues](issues.md): issues sent to the people responsible for each agent (its owner,
  its sponsors, its team), escalated until someone takes them on
* [Tickets in service desks](tickets.md): issues as tickets in ServiceNow, Jira Service
  Management or Freshservice, kept in step with them both ways
* [Management rules](management-rules.md): what to do about agents that meet some
  conditions for long enough (inactive, ownerless, long blocked), after telling their people
* [Evidence](evidence.md): ledger checkpoints time-stamped by an authority, retention and
  archives, and compliance reports and an evidence pack for assessors
* [Security operations](secops.md): the ledger to SIEMs as OCSF events, alerts in Teams and
  Slack, and how much the security team's tools may do

## Microsoft 365 and Copilot Studio

* [Agents on Microsoft 365 and Copilot Studio](platforms.md): the agent catalog, the
  Copilot Studio inventory, the connector allowlist, and acting as the signed-in admin
* [Agents on other platforms](other-platforms.md): agents built on AWS, Google Cloud,
  Salesforce, Databricks and Microsoft Foundry, read into the registry with their risky
  settings as issues
* [Connecting AgentGov to Microsoft's services](microsoft-connections.md): Entra Agent ID,
  the Purview audit log, Defender alerts, Entra access packages, connector policies and
  Copilot Studio threat detection
* [Agent 365 baseline](baseline-agent365.md): what Microsoft Agent 365 does, and how
  AgentGov compares

## Design

* [Architecture](architecture.md): the parts, the path of each call, trust boundaries,
  failure modes and scaling
* [Landscape and standards](landscape.md): why each project was chosen, and the standards
  AgentGov follows
* [Architecture decision records](adr)
* [Roadmap](roadmap.md)

## Contributing

* [CONTRIBUTING](../CONTRIBUTING.md): the development setup, the checks, and how to add a
  feature or a migration
* [SECURITY](../SECURITY.md): reporting a vulnerability, and deploying safely
