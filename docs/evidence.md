# Evidence: retention, time-stamps and compliance reports

Everything AgentGov decides or is told to do goes into its ledger, a hash chain that
anyone can verify ([architecture](architecture.md#evidence-ledger)). This page is about
keeping that evidence for as long as it is needed, proving it existed unchanged, and
handing it to the people who assess compliance:

* **Checkpoints** keep the chain's head every day, and a **time-stamping authority** signs
  each one with its own time (RFC 3161), so that nobody, AgentGov's administrators
  included, can rewrite the history before it unnoticed.
* **Retention**: the ledger keeps every entry, or keeps them for a period and then
  archives them, checked link by link, before they leave the database. Operational records
  whose history is in the ledger go after a period of their own.
* **Compliance reports** say what AgentGov does towards the EU AI Act, ISO/IEC 42001 and
  the NIST AI RMF, how far that is set up, and the evidence. An **evidence pack** bundles
  them with the ledger for the period, so that an assessor can check it without AgentGov.

## Checkpoints and time-stamps

Every `AGENTGOV_LEDGER_CHECKPOINT_HOURS` (24), while the chain grows, the control plane
keeps its head (the last entry's sequence number and hash) as a checkpoint; administrators
make one at any time. With `AGENTGOV_LEDGER_TSA_URL` set, a time-stamping authority signs
each checkpoint's statement:

```text
agentgov ledger checkpoint seq=1042 hash=9f2c…e1
```

The authority's answer proves that the chain up to that entry existed, as it is, at the
time it gives. AgentGov keeps the answer whole, and checks that it covers the hash it sent,
with its nonce. Anyone can verify it with OpenSSL, against the authority's certificate,
without AgentGov:

```bash
agentgov ledger proof 1042 -o proof/
openssl ts -verify -data proof/checkpoint-1042.txt -in proof/checkpoint-1042.tsr \
  -CAfile the-authority-ca.pem
```

| Authority | URL | Verify with |
|---|---|---|
| FreeTSA | `https://freetsa.org/tsr` | its `cacert.pem`, and `-untrusted tsa.crt` |
| DigiCert | `http://timestamp.digicert.com` | the system's CA bundle, such as `/etc/ssl/certs/ca-certificates.crt` |
| Sectigo | `http://timestamp.sectigo.com` | the system's CA bundle (it asks for 15 seconds between requests) |

Your organisation's own authority works too. A refused or failed request is kept on the
checkpoint and tried again each hour; until then, the checkpoint vouches only for itself.
The control plane needs to reach the authority over the network
([requirements](requirements.md)).

## Retention

| Setting | Default | What it does |
|---|---|---|
| `AGENTGOV_LEDGER_RETENTION_DAYS` | 0 | Days the ledger keeps entries in the database. 0 keeps them all; otherwise at least 183 (six months) |
| `AGENTGOV_LEDGER_ARCHIVE_DIR` | none | Where entries past that go first, as gzipped JSON Lines (needed with the setting above) |
| `AGENTGOV_DATA_RETENTION_DAYS` | 0 | Days the operational records are kept: 0 keeps them; otherwise at least 30 |

**The ledger.** Each hour, the entries older than the retention period are written to an
archive, `ledger-<first>-<last>.jsonl.gz`, and checked as they are written: each must
link to the one before it and match its hash, or nothing is archived and an issue for the
default team says why. Only then does a checkpoint record the archive and its SHA-256, and
the entries leave the database; the chain there goes on from that checkpoint, and an entry
`ledger.archived` names the archive. Entries that an active destination hasn't been sent
yet stay, while security operations are on ([security operations](secops.md)).

The minimum of 183 days follows the EU AI Act, which asks providers and deployers of
high-risk AI systems to keep the logs under their control for at least six months
(Articles 19 and 26(6)), unless other law asks for longer. The archives are evidence: back
the volume up, or copy the archives to storage that can't be rewritten (object lock,
immutable blobs).

```bash
agentgov ledger verify --file ledger-000000000001-000000050000.jsonl.gz \
  --file ledger-000000050001-000000100000.jsonl.gz
```

checks archives offline, in order: each entry, and that each archive goes on from the one
before. `--follows HASH` names the hash the first must follow, such as a checkpoint's.
Exports (`agentgov ledger export`) check the same way.

**Operational records.** With `AGENTGOV_DATA_RETENTION_DAYS`, the records whose history
is in the ledger go once older than that: agents' daily activity and model usage, risk
signals, notifications sent, decided approval requests (with the arguments they held),
resolved and dismissed findings, ended access assignments, and developers' MCP servers not
reported since. An entry `retention.pruned` counts what went.

## Compliance reports

A report takes a framework and a period, and says, control by control, what the framework
asks, what AgentGov does towards it, how far that is set up in this deployment, and the
evidence: counts from the registry and the ledger over the period, with where to look.

| Status | Means |
|---|---|
| In place | AgentGov does this here, and the evidence is there |
| Partly | Set up in part: say, a control monitored rather than enforced, or agents without an owner. The report says what is missing |
| Not set up | The features that would do it are off |
| Needs attention | Something is wrong: a broken chain, a failing destination |
| Outside AgentGov | The framework asks it of the organisation: AgentGov records what bears on it |

A report doesn't say that an organisation complies. That depends on its AI systems, its
processes and its people, and is for its assessors to judge; the report and the evidence
pack are for them.

**EU AI Act** (Regulation (EU) 2024/1689, as amended by Regulation (EU) 2026/1744, under
which the obligations for high-risk AI systems apply from 2 December 2027 for Annex III
systems and 2 August 2028 for Annex I systems):

| Article | What AgentGov does |
|---|---|
| 4 AI literacy | Outside AgentGov; its issues, approvals and previews put the people responsible in the loop |
| 9 Risk management | Risk tiers, risk scores, posture findings and risk-based blocking |
| 12 Record-keeping | The ledger: every decision and action, hash-chained, checkpointed and time-stamped |
| 14 Human oversight | Approvals for destructive actions, the kill switch, monitor modes |
| 15 Accuracy, robustness and cybersecurity | The controls at the gateway, enforced or monitored |
| 19, 26(6) Keeping the logs | Retention of at least six months, archives that verify offline |
| 26(2) Oversight by competent people | Owners, sponsors, teams and roles |
| 26(5) Monitoring the operation | Posture checks, findings, issues, management rules |
| 72 Post-market monitoring | Monitoring in production, including calls between agents |
| 73 Serious incidents | Findings and the hand-off to the security team; reporting to authorities is the organisation's |

**ISO/IEC 42001:2023, Annex A**: A.3.2 AI roles and responsibilities; A.4.2 Resource
documentation; A.4.4 Tooling resources; A.5.2 AI system impact assessment process (outside
AgentGov); A.6.2.5 AI system deployment; A.6.2.6 AI system operation and monitoring;
A.6.2.8 AI system recording of event logs; A.8.4 Communication of incidents; A.9.2
Processes for responsible use of AI systems; A.9.4 Intended use of the AI system; A.10.3
Suppliers.

**NIST AI RMF 1.0**: GOVERN 1.5 (ongoing monitoring and periodic review), GOVERN 1.6
(inventory), GOVERN 2.1 (roles and responsibilities), MAP 4.1 (third-party risks), MEASURE
2.4 (monitored in production), MEASURE 2.7 (security and resilience), MEASURE 3.1
(emergent risks), MANAGE 2.4 (supersede, disengage, deactivate), MANAGE 4.1
(post-deployment monitoring), MANAGE 4.3 (incidents communicated).

## The evidence pack

A zip for the last N days:

| File | What it is |
|---|---|
| `reports/*.json`, `report.md` | The three frameworks' reports, as data and as a document |
| `ledger.jsonl` | The ledger's entries in the period, as AgentGov wrote them: `agentgov ledger verify --file ledger.jsonl` checks them |
| `checkpoints.json`, `checkpoints/*.txt`, `*.tsr` | The checkpoints, their archives, and each time-stamp with its statement, for `openssl ts -verify` |
| `inventory.json` | The agents, with their owners, sponsors, teams, status, risk and attestations |
| `manifests.yaml` | The registry as code: blueprints, tool servers, policies, rules, packages, features |
| `features.json` | Which features are on, and how strictly |

## Where

| Where | How |
|---|---|
| Admin UI | **Ledger** → *Entries*: **Verify chain**, *Checkpoints and retention* (**Make a checkpoint**, each time-stamp to download); **Ledger** → *Compliance*: a framework and a period, and **Evidence pack** |
| CLI | `agentgov ledger checkpoints`, `checkpoint`, `proof SEQ`, `retention [--run]`, `verify [--file F ...]`; `agentgov evidence report [--framework F] [--days N] [--json]`, `agentgov evidence pack [--days N] [-o FILE]` |
| API | `GET`/`POST /v1/ledger/checkpoints`, `GET /v1/ledger/checkpoints/{seq}/timestamp`, `GET /v1/ledger/retention`, `POST /v1/ledger/retention/run`; `GET /v1/evidence/frameworks`, `GET /v1/evidence/report?framework=&days=`, `GET /v1/evidence/pack?days=` |
| Helm chart | `controlPlane.ledgerArchive` (a volume for the archives, and the retention), `controlPlane.env.AGENTGOV_LEDGER_TSA_URL` ([Kubernetes](deploy/kubernetes.md)) |

Everyone who reads AgentGov (administrators, approvers, the security team, auditors) sees
the reports and downloads the pack; administrators make checkpoints and run retention.

## Compared with Microsoft

Microsoft Purview keeps audit records for 180 days with Audit (Standard) and a year with
Audit (Premium), and up to ten years with an add-on licence. Compliance Manager has
assessment templates for the EU AI Act, ISO/IEC 42001 and the NIST AI RMF, and Agent 365
includes agents in them ([baseline](baseline-agent365.md)). AgentGov keeps its own
evidence for as long as you choose, in archives you hold, time-stamped by an authority
outside it, and reports on it for the same three frameworks.

## In the demo

The demo's control plane has the sink as its time-stamping authority
(`examples/secops/sink`, with OpenSSL). In step 20 of `python examples/agents/demo_agent.py`,
an administrator makes a checkpoint, the authority time-stamps it, and OpenSSL verifies
the time-stamp; then the EU AI Act report and the evidence pack for the day.

## In the ledger

| Entry | When |
|---|---|
| `ledger.archived` | Entries were archived, then removed: the range, the archive and its SHA-256 |
| `retention.pruned` | Operational records past their retention were removed: how many of each |
