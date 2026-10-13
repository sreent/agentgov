# Tickets in service desks

Where work runs through a service desk, an issue that lives only in AgentGov and people's
inboxes is easy to lose. AgentGov opens a ticket for each [issue](issues.md) in your service
desk (ServiceNow, Jira Service Management or Freshservice), keeps it in step with the issue,
and reads back what happens to it there. A service desk is a destination, set up like a
SIEM or a chat ([security operations](secops.md)), and its credential is a file the control
plane reads, never in AgentGov's database.

## What happens

| In AgentGov | In the desk |
|---|---|
| An issue goes to someone, from the desk's minimum severity up (high by default) | A ticket opens, assigned to the issue's team's group, or the desk's own |
| Nobody takes it on in time, and it goes to the next people in its chain | A note says so, and to whom |
| Someone takes it on, or asks for its risk to be accepted | A note says who |
| It gets more or less severe | Its priority follows, with a note |
| It ends: AgentGov no longer finds the problem, someone resolves or dismisses it, or its risk is accepted | The ticket is resolved, with a note that says why (or only the note, if the desk shouldn't resolve tickets) |
| It is raised again later | A new ticket, unless the last one is still open there: then a note on it |

| In the desk | In AgentGov |
|---|---|
| Someone is assigned the ticket, or starts work on it | The issue is taken on: it goes no further up its chain, and AgentGov sends no more reminders |
| The ticket is resolved or closed, for a threat (an alert from Defender, say) | The issue is resolved: someone dealt with the event. It opens again if it happens again |
| The ticket is resolved or closed, for anything AgentGov checks itself (an agent without an owner, say) | The issue stays open until AgentGov's own check no longer finds the problem. If the check finds it again after the ticket was resolved, AgentGov opens another ticket that says so, and which one it takes over from |

Notes are for the people who work tickets: ServiceNow's work notes, internal comments on
Jira Service Management projects, Freshservice's private notes. AgentGov reads each open
ticket back every five minutes or so, by asking the desk: the desk never needs to reach
AgentGov, which suits a desk outside your network. To stop an issue for good, fix the problem
or, in AgentGov, ask an approver to accept its risk: a ticket closed while the
problem is still there comes back.

Tickets carry what agents, platforms and people wrote: an agent's name as its maker gave it,
the reason someone gave in AgentGov. It shows as it was written, never as the desk's own
markup. In Jira it is in a block that renders nothing (`{noformat}`), so a link, a mention,
an image or a macro in it stays text; in ServiceNow, `[code]` tags in it are broken up, as
they would render HTML in work notes; Freshservice gets it escaped. Only AgentGov's own link
to the issue is a link. A ticket's summary is one line.

## Which issues get one

An issue gets a ticket in each active desk once it goes to someone, if:

* it is at least as severe as the desk's minimum severity (`min_severity`, high by default);
* it wasn't found by a platform's first sync while those are kept quiet
  (`AGENTGOV_ISSUES_QUIET_FIRST_SYNC`, as for [emails](issues.md#fewer-messages));
* the desk takes its team's issues: every team's, unless the desk takes only those of the
  teams it lists (`only_listed_teams`).

An issue's team is the first team in its chain: its owner if a team owns the agent, else a
team among its sponsors, else the agent's team (its own, its blueprint's, or the default
team). A desk added while issues are open gives them no ticket, so that it isn't flooded
with what was there before it; they get one if they are raised again. To give them tickets
too, add the desk with **Open tickets for the issues already open too** (`--backfill`).

Each round opens at most 20 tickets per desk, so a backlog goes over a few minutes rather
than all at once.

## Setting one up

1. Add the desk: **Security operations** → **Add destination**, with the desk's kind, its
   URL and where its tickets go. Or `agentgov destinations create`, or a `Destination`
   manifest ([registry as code](administration.md#registry-as-code)).
2. Put its credential in the destination's secret file, `<AGENTGOV_DESTINATION_SECRETS_DIR>/<name>`
   (a mounted secret; [configuration](configuration.md#security-operations)).
3. **Test**: AgentGov signs in and looks at where its tickets go, without changing anything
   there.

The secret file holds HTTP headers, one per line (`Authorization: Basic …`, or ServiceNow's
`x-sn-apikey: …`), or one line that AgentGov turns into the header: a user name and
password (ServiceNow), an email address and API token (Jira), or an API key (Freshservice).

### ServiceNow

```bash
agentgov destinations create itsm --kind servicenow --url https://acme.service-now.com \
  --group "AI Governance" --team-group "cx-platform=CX Platform" \
  --tickets '{"fields": {"caller_id": "agentgov", "category": "security"}}'
printf 'agentgov:%s\n' "$PASSWORD" > "$AGENTGOV_DESTINATION_SECRETS_DIR/itsm"
```

* **Tickets** are incidents, through the Table API, unless `table` names another table
  (`sn_si_incident`, for Security Incident Response, say). Each has AgentGov's marker as its
  correlation ID, so that one opened while AgentGov didn't hear back is found, not opened
  twice.
* **Groups** (`group`, and by team in `groups`) are assignment groups, by name or sys_id.
  Other fields, such as a caller or a category, go in `fields`, by their names in the table;
  names stand for references there too.
* **Priority** is the incident's impact and urgency, from which ServiceNow works it out:
  critical is 1 and 1 (critical), high 1 and 2, medium 2 and 2, low 2 and 3, info 3 and 3.
* **Resolving** sets state 6 (resolved), the close code `Solution provided` and the note as
  close notes. If your instance names its close codes differently (its `sys_choice` table
  lists `incident.close_code`'s), say so in `resolve_fields`: `{"state": "6", "close_code":
  "Resolved by request"}`. Other tables are resolved with state 3 (closed complete), and
  count as over when their `active` flag is false; `done_states` and `active_states` name
  their states otherwise.
* **Credential:** an integration user that may create, read and update the table's records
  (the `itil` role, for incidents), as `user:password`; or an API key, `x-sn-apikey: …`,
  where the API Key and HMAC Authentication plugin is on and an API access policy lets keys
  reach the Table API.

### Jira Service Management

```bash
agentgov destinations create jsm --kind jira --url https://acme.atlassian.net \
  --tickets '{"group": "OPS", "issue_type": "Incident"}'
printf 'agentgov@example.com:%s\n' "$API_TOKEN" > "$AGENTGOV_DESTINATION_SECRETS_DIR/jsm"
```

* **Tickets** are issues in a project, through Jira's REST API 2, which Jira Cloud and Jira
  Data Center both have. `group` (and `groups`, by team) is the project's key, `issue_type`
  the issue type's name (`Task` by default). Any Jira project will do; a Jira Service
  Management project's comments from AgentGov are internal, so its customers don't see
  them. AgentGov's marker is a label.
* **Priority** is the issue's priority: Highest for critical, then High, Medium, Low and
  Lowest. A project whose screens have no priority refuses one: AgentGov then opens the
  ticket without it.
* **Resolving** takes the transition to a status in the Done category, then adds a comment;
  `resolve_transition` names one where there are several, and `resolve_fields` gives what
  its screen asks for (`{"resolution": {"name": "Done"}}`, say).
* **Credential:** Jira Cloud, an account's email address and API token, as
  `email:api-token`, for an account that may browse, create, edit, comment on and
  transition issues in the projects. A service account's scoped token goes through
  Atlassian's API gateway: then `url` is `https://api.atlassian.com/ex/jira/<cloud ID>`, and
  `site` is where people open tickets, `https://acme.atlassian.net`. Jira Data Center, a
  personal access token: `Authorization: Bearer <token>`.

### Freshservice

```bash
agentgov destinations create helpdesk --kind freshservice --url https://acme.freshservice.com \
  --tickets '{"requester": "agentgov@example.com", "group": 42}'
printf '%s\n' "$API_KEY" > "$AGENTGOV_DESTINATION_SECRETS_DIR/helpdesk"
```

* **Tickets** are raised for `requester`, an email address (AgentGov's mailbox, say; if it
  isn't a contact yet, Freshservice adds it), assigned to the agent group `group` (by ID).
  AgentGov's marker is a tag. In an account with several workspaces, tickets go to the
  primary one unless `fields` gives a `workspace_id`.
* **Priority:** urgent (4) for critical, high (3), medium (2), and low (1) for low and info.
* **Resolving** sets status 4 (resolved), then adds a private note.
* **Fields** that the account made required on its ticket form are required through the API
  too: give them in `fields` (`custom_fields` among them). The desk's state says which
  field it refused, if it does.
* **Credential:** the API key of an agent that may create, view and edit tickets in the
  group. Freshservice limits how many requests an account makes a minute, by plan: AgentGov
  waits as long as its `Retry-After` says.

## Settings

A desk's `tickets` settings. Changing some keeps the others; `null` takes one out. A
`Destination` manifest gives them all, so what it leaves out goes.

| Setting | Desks | Means |
|---|---|---|
| `group` | All | Where tickets go: a ServiceNow assignment group, a Jira project's key, a Freshservice group's ID |
| `groups` | All | Where a team's tickets go instead, by AgentGov team |
| `only_listed_teams` | All | Only the issues of the teams in `groups` get a ticket here |
| `fields` | All | More fields for every ticket, by the desk's own names |
| `priorities` | All | By severity, the fields that say how urgent a ticket is (the defaults above; `{}` sends none) |
| `resolve` | All | `false`: when an issue ends, a note says so, and someone resolves the ticket there |
| `resolve_fields` | All | What resolving sends, instead of the defaults above |
| `table`, `active_states`, `done_states` | ServiceNow | The table tickets go to, and, for a table other than incident, its states that mean someone is on it, or it is over |
| `issue_type`, `resolve_transition`, `site` | Jira | The issue type, the transition that resolves, and where people open tickets (with the API gateway) |
| `requester` | Freshservice | The email address tickets are raised for |

## When something goes wrong

* **The desk as a whole** (it can't be reached, it refused AgentGov's credential, or it
  asked AgentGov to slow down): AgentGov leaves it, five seconds at first and up to ten
  minutes, or as long as its `Retry-After` says, then carries on where it stopped. The
  destination says why, on **Security operations**.
* **One ticket** (the desk refused it: a field its form requires, a group it doesn't have):
  tried again, waiting longer each time, and given up on after about an hour, which the
  issue's history says (`finding.ticket_failed`). Its error is on the issue's page and the
  desk's. Changing the desk's settings tries what it refused again at once.
* **A ticket opened without AgentGov hearing back** (a timeout): the next try looks for it
  by AgentGov's marker before opening another, so the desk doesn't get two.
* **A ticket deleted in the desk** counts as closed there.
* **Paused:** AgentGov opens no tickets there, and neither tells nor reads back the ones it
  has, until it is resumed.

AgentGov doesn't copy the desk's own comments back, and doesn't reopen tickets in the desk:
a problem that comes back gets a new ticket that names the old one. Each desk is read with
the credential in its file; tokens that expire within the hour (OAuth's) aren't supported.

## Where

| Where | How |
|---|---|
| Admin UI | **Security operations** → **Add destination** (ServiceNow, Jira Service Management, Freshservice), **Test**, **Edit**, **Pause**; an issue's page → *Tickets*, each with its number, its state there and who has it |
| CLI | `agentgov destinations create NAME --kind servicenow\|jira\|freshservice --url URL [--group G] [--team-group TEAM=GROUP] [--tickets JSON\|@FILE] [--backfill]`, `destinations update`, `destinations test NAME`; `agentgov tickets list [--desk NAME] [--status S]` |
| API | `POST`/`PATCH /v1/destinations` with `kind` and `tickets`, `POST /v1/destinations/{name}/test`; `GET /v1/tickets?desk=&status=`; `tickets` on `GET /v1/findings/{id}` |
| Manifests | `kind: Destination` with `spec.kind: servicenow` (or `jira`, `freshservice`), `spec.url` and `spec.tickets` |

Administrators add and change desks; everyone who reads AgentGov sees them and the tickets.
Desks open tickets while the [issues](issues.md) feature is on.

## In the ledger

| Entry | When |
|---|---|
| `finding.ticket_opened` | A ticket opened, with the desk, its number and its link (and the one it took over from) |
| `finding.acknowledged`, by `servicenow:INC0012345` (say) | Someone was assigned the ticket, or started work on it, there |
| `finding.ticket_done` | The ticket was resolved or closed there, by whom, and with what resolution |
| `finding.resolved`, by the ticket | A threat's ticket was resolved there |
| `finding.ticket_closed` | The issue ended and AgentGov resolved the ticket (or noted it) |
| `finding.ticket_failed` (warning) | A ticket was given up on after retrying, and why |
| `destination.tested` | A desk's test: whether AgentGov signed in and saw where its tickets go |
