// Security operations: what AgentGov hands to the security team's tools (the evidence ledger
// to SIEMs, alerts to chats, issues as tickets to service desks), and how much the security
// team's secops role may do here.

import type { ReactNode } from 'react';
import { ask, type Field, type Values } from '../components/dialog';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import { Callout, Card, Chip, Copyable, EmptyState, Facts, PageHead, PlainChip, RefreshButton, TimeEl } from '../components/ui';
import { API_ROOT, api } from '../lib/api';
import { fmt, humanize, plural } from '../lib/format';
import { formatLabels, orNull, parseLabels } from '../lib/forms';
import { refresh, type PageDef } from '../lib/router';
import { can } from '../lib/session';
import { MODE_WORDS, NAME_HINT } from '../lib/shared';
import { featureProvenance, ModeControl } from './features';

type Destination = any;

// Destinations by kind: name, whether it is a SIEM or a chat, a URL like its own, and the URL's hint.
const DEST_KINDS: Record<string, [name: string, family: string, url?: string, hint?: string]> = {
  otlp: ['OpenTelemetry (OTLP)', 'siem', 'http://otel-collector:4318', "The collector's OTLP/HTTP endpoint. Events go to /v1/logs there."],
  webhook: ['Webhook (HTTP input)', 'siem', 'https://siem.example.com/ingest', "A SIEM's or log pipeline's HTTP input. Leave it empty when the URL is the credential: it then goes in the secret file."],
  'splunk-hec': ['Splunk HTTP Event Collector', 'siem', 'https://splunk.example.com:8088', "Splunk's HTTP Event Collector. Events go to /services/collector/event there."],
  slack: ['Slack', 'chat'],
  teams: ['Microsoft Teams', 'chat'],
  servicenow: ['ServiceNow', 'desk', 'https://your-instance.service-now.com', 'Your instance. Tickets go to its Table API: the incident table, unless you choose another.'],
  jira: ['Jira Service Management', 'desk', 'https://your-site.atlassian.net', "Your site (Jira Data Center: its base URL). With a service account's scoped token: https://api.atlassian.com/ex/jira/<cloud ID>."],
  freshservice: ['Freshservice', 'desk', 'https://your-domain.freshservice.com', 'Your helpdesk.'],
};
// A desk's main setting: where its tickets go.
const DESK_GROUP: Record<string, [label: string, placeholder: string, hint: string]> = {
  servicenow: ['Assignment group', 'AI Governance', "By name or sys_id. Empty: the table's own rules assign them."],
  jira: ['Project', 'OPS', 'The key of the project tickets go to.'],
  freshservice: ['Group ID', '42', "The ID of the agent group tickets go to (in its URL in Freshservice's admin). Empty: Freshservice's own rules assign them."],
};
const DEST_EVENTS: Record<string, [key: string, label: string, hint: string][]> = {
  siem: [
    ['decisions', 'Decisions', 'tool and model calls at the gateway'],
    ['approvals', 'Approvals', 'requested, decided, used'],
    ['findings', 'Issues', 'raised, resolved, dismissed'],
    ['access', 'Access', 'sign-ins and API keys'],
    ['changes', 'Changes', 'everything else: what AgentGov governs, and who changed it'],
  ],
  chat: [
    ['findings', 'Issues', 'from the minimum severity up'],
    ['approvals', 'Approval requests', 'whatever their severity'],
    ['blocks', 'Kill switches', 'agents, tool servers, model providers and identity issuers blocked, agents deleted'],
  ],
};
const DEST_SECRET: Record<string, string> = {
  otlp: 'Optional: HTTP headers to send, one per line, such as Authorization: Bearer <token>.',
  webhook: 'Optional: HTTP headers to send, one per line; and the URL, on a line of its own, when the URL is the credential (as with Sumo Logic).',
  'splunk-hec': "The HTTP Event Collector's token.",
  slack: "The incoming webhook's URL (https://hooks.slack.com/services/…).",
  teams: 'The webhook URL of a Teams workflow that posts to the channel (the workflow "When a Teams webhook request is received").',
  servicenow: 'user:password on one line (an integration user with the itil role, say), or HTTP headers, one per line: x-sn-apikey: <key>, or Authorization: Basic <…>.',
  jira: 'email:api-token on one line (Jira Cloud), or HTTP headers, one per line: Authorization: Bearer <personal access token> (Jira Data Center).',
  freshservice: 'The API key, on one line (in Freshservice, Profile settings → API key).',
};
const destKind = (kind: string): string => (DEST_KINDS[kind] || [kind])[0];
const destFamily = (kind: string): string => (DEST_KINDS[kind] || [kind, 'siem'])[1];

interface SecopsData { view: any; feature: any }

export const secopsPage: PageDef<SecopsData> = {
  re: /^\/secops$/,
  nav: 'secops',
  title: 'Security operations',
  load: async () => {
    const [view, feature] = await Promise.all([api('v1/secops'), api('v1/features/security-operations')]);
    return { view, feature };
  },
  View: ({ data: { view, feature } }) => (
    <div className="page">
      <PageHead
        title="Security operations"
        sub="What AgentGov hands to other tools: the evidence ledger, as OCSF events, to the security team's SIEMs; alerts to Teams and Slack channels; issues, as tickets, to service desks; and how much the security team's secops role may do here."
        actions={[<RefreshButton key="refresh" />]}
      />
      {view.sending ? null : (
        <Callout tone="neutral" icon="power">
          <span>
            <strong>{'Nothing is sent. '}</strong>
            {can('admin') ? 'Choose inform or above to send the destinations below their events and alerts.' : 'An administrator chooses how much is handed over.'}
          </span>
        </Callout>
      )}
      <HandoffCard view={view} f={feature} />
      <DestinationsCard view={view} />
      <EventsApiCard view={view} />
    </div>
  ),
};

function HandoffCard({ view, f }: { view: any; f: any }) {
  const reached = view.levels.indexOf(view.level);
  return (
    <Card
      title="Hand-off"
      sub="Each level includes the ones before it. The secops role is for the security team's tools (an API key) and analysts (the agentgov-secops role at sign-in). Everything it does is in the ledger under its name, and administrators can undo it."
    >
      <div className="stack">
        <div><ModeControl f={f} />{featureProvenance(f)}</div>
        <ol className="levels">
          {f.modes.map((m: string, n: number) => (
            <li key={m} data-reached={n <= reached ? 'true' : 'false'} aria-current={m === view.level ? 'step' : undefined}>
              <Icon name={n <= reached ? 'check-circle' : 'minus'} />
              <div><strong>{MODE_WORDS[m] || humanize(m)}</strong><div className="cell-sub">{f.effects[m] || ''}</div></div>
            </li>
          ))}
        </ol>
      </div>
    </Card>
  );
}

function destinationState(d: Destination): ReactNode {
  const delivery = d.delivery;
  if (d.secret.need === 'required' && !d.secret.present) {
    return (
      <>
        <PlainChip text="No secret file" tone="warning" iconName="key" />
        <div className="cell-sub break">{'Put it in '}<code>{d.secret.file}</code></div>
      </>
    );
  }
  if (delivery.last_error) {
    return (
      <>
        <PlainChip text={`Failing (${fmt(delivery.failures)})`} tone="critical" iconName="octagon" title={delivery.last_error} />
        <div className="cell-sub break">{delivery.last_error}</div>
        {delivery.retry_at ? <div className="cell-sub">{'Tries again '}<TimeEl iso={delivery.retry_at} /></div> : null}
      </>
    );
  }
  if (destFamily(d.kind) === 'desk') {
    const t = delivery.tickets || {};
    return (
      <>
        <PlainChip text={`${fmt(t.open || 0)} ${t.open === 1 ? 'ticket' : 'tickets'} kept in step`} tone="good" iconName="check-circle" />
        {t.pending ? <div className="cell-sub">{`${fmt(t.pending)} opening`}</div> : null}
        {t.failed ? <div className="cell-sub"><PlainChip text={`${fmt(t.failed)} it couldn't open`} tone="critical" iconName="octagon" /></div> : null}
        {t.erring ? <div className="cell-sub">{`${fmt(t.erring)} refused for now: their issues say why`}</div> : null}
        {delivery.delivered_at
          ? <div className="cell-sub">{'Last change sent '}<TimeEl iso={delivery.delivered_at} /></div>
          : <div className="cell-sub">Nothing sent yet</div>}
      </>
    );
  }
  const sent = delivery.delivered_at
    ? <div className="cell-sub">{`${plural(delivery.delivered, destFamily(d.kind) === 'chat' ? 'alert' : 'event')} sent, last `}<TimeEl iso={delivery.delivered_at} /></div>
    : <div className="cell-sub">Nothing sent yet</div>;
  const behind = delivery.behind
    ? <PlainChip text={`${fmt(delivery.behind)} ledger ${delivery.behind === 1 ? 'entry' : 'entries'} to go`} tone="neutral" iconName="clock" />
    : <PlainChip text="Up to date" tone="good" iconName="check-circle" />;
  return <>{behind}{sent}</>;
}

function DestinationsCard({ view }: { view: any }) {
  const rows: Destination[] = view.destinations;
  return (
    <Card
      title="Destinations"
      sub="SIEMs get what is new in the ledger, at least once and in order, and keep their place while paused or failing; chats get alerts; service desks get issues as tickets, kept in step with them. Each one's credential is a file the control plane reads, named after it: never in AgentGov's database."
      actions={can('admin') ? [
        <button key="add" type="button" className="btn btn--sm btn--primary" onClick={guarded(() => destinationForm(null))}><Icon name="plus" />Add destination</button>,
      ] : null}
      flush={rows.length > 0}
    >
      {rows.length ? (
        <div className="table-wrap">
          <table className="data rtable">
            <caption className="sr-only">Destinations</caption>
            <thead>
              <tr>{['Destination', 'Gets', 'Status', 'Delivery', ''].map((t, i) => <th key={i} scope="col">{t || <span className="sr-only">Actions</span>}</th>)}</tr>
            </thead>
            <tbody>
              {rows.map((d) => (
                <tr key={d.name} data-destination={d.name}>
                  <td data-label="Destination" className="break">
                    <span className="cell-title">{d.name}</span>
                    <div className="cell-sub">{destKind(d.kind)}{d.format === 'ndjson' ? ', JSON lines' : ''}</div>
                    {d.url ? <div className="cell-sub"><code>{d.url}</code></div> : null}
                    {d.description ? <div className="cell-sub">{d.description}</div> : null}
                  </td>
                  <td data-label="Gets">
                    <div className="chip-row">
                      {destFamily(d.kind) === 'desk'
                        ? <PlainChip text="Issues, as tickets" iconName="ticket" />
                        : d.events.map((e: string) => <PlainChip key={e} text={humanize(e)} />)}
                    </div>
                    {d.min_severity !== 'info' ? <div className="cell-sub">{`${humanize(d.min_severity)} severity and up`}</div> : null}
                  </td>
                  <td data-label="Status"><Chip kind="destination" value={d.status} /></td>
                  <td data-label="Delivery">{destinationState(d)}</td>
                  <td data-label="">
                    {can('admin') ? (
                      <div className="btn-row">
                        <button type="button" className="btn btn--sm" onClick={guarded(() => testDestination(d))}><Icon name="play" />Test</button>
                        <button type="button" className="btn btn--sm" onClick={guarded(() => destinationForm(d))}><Icon name="edit" />Edit</button>
                        <button type="button" className="btn btn--sm" onClick={guarded(() => pauseDestination(d))}>
                          <Icon name={d.status === 'paused' ? 'play' : 'minus'} />{d.status === 'paused' ? 'Resume' : 'Pause'}
                        </button>
                        {destFamily(d.kind) === 'siem' ? (
                          <button type="button" className="btn btn--sm" onClick={guarded(() => replayDestination(d))}><Icon name="undo" />Replay</button>
                        ) : null}
                        <button type="button" className="btn btn--sm btn--danger-quiet" onClick={guarded(() => deleteDestination(d))}><Icon name="trash" />Delete</button>
                      </div>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState
          title="No destinations"
          text="Add a SIEM, through OpenTelemetry, an HTTP input or Splunk, to send it the ledger as OCSF events; a Teams or Slack channel, to send it alerts; or a service desk, where issues become tickets."
        />
      )}
    </Card>
  );
}

function EventsApiCard({ view }: { view: any }) {
  const url = new URL('v1/secops/events', API_ROOT).href;
  return (
    <Card title="Events API" sub="For SIEMs that collect rather than receive: the same OCSF events, from an API key with the secops role. Each page says where the next one starts.">
      <div className="stack">
        <Facts rows={[
          ['Events', <Copyable text={`${url}?after=0&limit=200`} label="events URL" />],
          ['From the CLI', <Copyable text="agentgov secops events --follow" label="CLI command" />],
          ['Ledger entries', fmt(view.ledger_head)],
        ]} />
        {view.sending ? null : <p className="hint">It answers once the hand-off is at inform or above.</p>}
      </div>
    </Card>
  );
}

// A desk's groups by team, a "team = group" a line.
function teamGroupsText(groups: Record<string, string> | null | undefined): string {
  return Object.entries(groups || {}).map(([team, group]) => `${team} = ${group}`).join('\n');
}

function parseTeamGroups(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of (text || '').split('\n').map((l) => l.trim()).filter(Boolean)) {
    const at = line.indexOf('=');
    if (at < 1 || !line.slice(at + 1).trim()) throw new Error(`Per team: "${line}" isn't "team = group".`);
    out[line.slice(0, at).trim()] = line.slice(at + 1).trim();
  }
  return out;
}

function jsonObject(text: string, what: string): Record<string, unknown> | null {
  if (!(text || '').trim()) return null;
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    value = null;
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${what}: a JSON object, such as {"category": "security"}.`);
  return value;
}

/** Add a destination (no `d`) or edit one. The form follows the kind: a SIEM's URL and the
 * events it gets, a chat's alerts, or a service desk's tickets. */
async function destinationForm(d: Destination | null) {
  const editing = Boolean(d);
  const kind0 = d?.kind || 'otlp';
  const tk = d?.tickets || {};
  // A kind this page has no words for fails here, before the form opens.
  const urlPlaceholder0 = DEST_KINDS[kind0][2];
  const urlHint0 = DEST_KINDS[kind0][3];
  const kindOf = (v: Values): string => (editing ? d.kind : v.kind);
  const familyOf = (v: Values): string => destFamily(kindOf(v));
  const eventFields = (family: string): Field[] => DEST_EVENTS[family].map(([key, label, hint]) => ({
    id: `ev-${family}-${key}`, label, hint, type: 'checkbox',
    value: editing ? d.events.includes(key) : true,
    hidden: (v) => familyOf(v) !== family,
  }));
  const pretty = (value: unknown) => (value ? JSON.stringify(value, null, 2) : '');
  const desk = (v: Values) => familyOf(v) === 'desk';
  const deskHidden = (v: Values) => !desk(v);
  const saved = await ask<any>({
    title: editing ? `Edit ${d.name}` : 'Add a destination',
    text: editing
      ? `${destKind(d.kind)}. Changes apply to what it is sent next, and are recorded in the evidence ledger.`
      : 'A SIEM gets the ledger as OCSF events; a chat gets alerts; a service desk gets issues as tickets, kept in step with them. Put its credential in its secret file, which the control plane reads when it sends.',
    iconName: editing ? 'edit' : 'secops', confirm: editing ? 'Save changes' : 'Add destination', wide: true,
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'soc-splunk', hint: NAME_HINT },
      editing ? null : {
        id: 'kind', label: 'Kind', type: 'select', value: kind0,
        options: Object.entries(DEST_KINDS).map(([value, [label, family]]) => ({
          value, label: `${label}: ${({ chat: 'alerts', desk: 'tickets' } as Record<string, string>)[family] || 'OCSF events'}`,
        })),
      },
      {
        id: 'url', label: 'URL', mono: true, value: d?.url || '',
        placeholder: (v) => (editing ? urlPlaceholder0 : DEST_KINDS[v.kind][2]) || '',
        hint: (v) => (editing ? urlHint0 : DEST_KINDS[v.kind][3]) || '',
        hidden: (v) => familyOf(v) === 'chat',
      },
      {
        id: 'format', label: 'Body', type: 'select', value: d?.format || 'json', options: [
          { value: 'json', label: 'A JSON array of events' }, { value: 'ndjson', label: 'JSON lines: one event per line' },
        ],
        hidden: (v) => kindOf(v) !== 'webhook',
      },
      { type: 'section', id: 'sec-gets', label: 'What it gets', hidden: desk },
      ...eventFields('siem'),
      ...eventFields('chat'),
      { type: 'section', id: 'sec-tickets', label: 'Its tickets', hidden: deskHidden },
      {
        id: 'tk-group', label: (v) => (desk(v) ? DESK_GROUP[kindOf(v)][0] : 'Assignment group'), mono: true, value: tk.group ?? '',
        placeholder: (v) => (desk(v) ? DESK_GROUP[kindOf(v)][1] : undefined),
        hint: (v) => (desk(v) ? DESK_GROUP[kindOf(v)][2] : undefined),
        hidden: deskHidden,
      },
      {
        id: 'tk-groups', label: 'Per team', type: 'textarea', mono: true, value: teamGroupsText(tk.groups), placeholder: 'cx-platform = CX Platform',
        hint: "Where the issues of AgentGov's teams go instead, a team a line. An issue's team is the first team in its chain: its owner, a sponsor, or its team.",
        hidden: deskHidden,
      },
      { id: 'tk-only', label: 'Only the issues of the teams listed', type: 'checkbox', value: Boolean(tk.only_listed_teams), hidden: deskHidden },
      {
        id: 'tk-table', label: 'Table', mono: true, value: tk.table || '', placeholder: 'incident', hint: 'incident, unless you choose another: sn_si_incident for Security Incident Response, say.',
        hidden: (v) => kindOf(v) !== 'servicenow',
      },
      {
        id: 'tk-issue_type', label: 'Issue type', value: tk.issue_type || '', placeholder: 'Task', hint: 'Its name in the project: Task, unless you choose another.',
        hidden: (v) => kindOf(v) !== 'jira',
      },
      {
        id: 'tk-site', label: 'Site', mono: true, value: tk.site || '', placeholder: 'https://your-site.atlassian.net', hint: "Where people open tickets: needed when the URL is Atlassian's API gateway.",
        hidden: (v) => kindOf(v) !== 'jira',
      },
      {
        id: 'tk-requester', label: 'Raised for', mono: true, value: tk.requester || '', placeholder: 'agentgov@example.com', hint: "The requester's email address: AgentGov's mailbox, say.",
        hidden: (v) => kindOf(v) !== 'freshservice',
      },
      {
        id: 'tk-fields', label: 'More fields', type: 'textarea', mono: true, value: pretty(tk.fields), placeholder: '{"category": "security"}',
        hint: "As JSON, by the desk's own names: what its forms require, such as a caller, a category or a custom field.",
        hidden: deskHidden,
      },
      {
        id: 'tk-resolve', label: 'Resolve the ticket when the issue ends', type: 'checkbox', value: tk.resolve !== false, hint: 'Otherwise AgentGov adds a note that it ended, and someone resolves it there.',
        hidden: deskHidden,
      },
      {
        id: 'tk-resolve_fields', label: 'Resolve it with', type: 'textarea', mono: true, value: pretty(tk.resolve_fields), placeholder: '{"close_code": "Solution provided"}',
        hint: 'As JSON: what resolving takes there, if not the defaults (docs/tickets.md).',
        hidden: deskHidden,
      },
      {
        id: 'min_severity', label: 'Minimum severity', type: 'select', value: d?.min_severity || (destFamily(kind0) === 'siem' ? 'info' : 'high'),
        options: ['info', 'low', 'medium', 'high', 'critical'].map((value) => ({ value, label: humanize(value) })),
        hint: (v) => (desk(v) ? 'Issues from this severity up become tickets.' : 'For a chat, of issues: approval requests and blocks always go.'),
      },
      editing ? null : {
        id: 'backfill', type: 'checkbox', value: false,
        label: (v) => (desk(v) ? 'Open tickets for the issues already open too, not only those from now on' : 'Send it the ledger from its start, not from now'),
        hidden: (v) => familyOf(v) === 'chat',
      },
      { id: 'description', label: 'Description', type: 'textarea', value: d?.description || '' },
      { id: 'labels', label: 'Labels', value: formatLabels(d?.labels), placeholder: 'team=soc', mono: true },
    ],
    extra: ({ values }) => {
      const name = editing ? d.name : (values.name || '<name>');
      return <p className="hint" id="dest-secret-hint">{`Secret file: ${d?.secret?.file || `<destination secrets>/${name}`}. ${DEST_SECRET[kindOf(values)]}`}</p>;
    },
    // A new one's minimum severity follows its kind (and starts again from it as its name is typed).
    onChange: editing ? undefined : (values, changed) => (changed === 'kind' || changed === 'name'
      ? { min_severity: destFamily(values.kind) === 'siem' ? 'info' : 'high' }
      : undefined),
    submit: (v) => {
      const kind = editing ? d.kind : v.kind;
      const family = destFamily(kind);
      const body: Record<string, any> = { min_severity: v.min_severity, description: v.description, labels: parseLabels(v.labels) };
      if (family === 'desk') {
        const groups = parseTeamGroups(v['tk-groups']);
        // Cleared settings go (null), so that an edit can take one out.
        body.tickets = {
          group: orNull(v['tk-group']),
          groups: Object.keys(groups).length ? groups : null,
          only_listed_teams: v['tk-only'] || null,
          fields: jsonObject(v['tk-fields'], 'More fields'),
          resolve: v['tk-resolve'] ? null : false,
          resolve_fields: jsonObject(v['tk-resolve_fields'], 'Resolve it with'),
          ...(kind === 'servicenow' ? { table: orNull(v['tk-table']) } : {}),
          ...(kind === 'jira' ? { issue_type: orNull(v['tk-issue_type']), site: orNull(v['tk-site']) } : {}),
          ...(kind === 'freshservice' ? { requester: orNull(v['tk-requester']) } : {}),
        };
        body.url = orNull(v.url);
      } else {
        const events = DEST_EVENTS[family].map(([key]) => key).filter((key) => v[`ev-${family}-${key}`]);
        // A chat may take no alerts: a team's channel, for the issues its team posts there.
        if (!events.length && family !== 'chat') throw new Error('Choose at least one kind of event to send it.');
        body.events = events;
        if (family === 'siem') body.url = orNull(v.url);
        if (kind === 'webhook') body.format = v.format;
      }
      if (editing) return api(`v1/destinations/${encodeURIComponent(d.name)}`, { method: 'PATCH', body, ifMatch: d.version });
      return api('v1/destinations', { method: 'POST', body: { name: v.name, kind, ...body, ...(family !== 'chat' && v.backfill ? { backfill: true } : {}) } });
    },
  });
  if (!saved) return;
  const missing = !saved.secret.present && saved.secret.need === 'required';
  toast(editing ? `Saved ${saved.name}.` : `Added ${saved.name}.${missing ? ` Put its credential in ${saved.secret.file}.` : ''}`);
  await refresh();
}

async function testDestination(d: Destination) {
  const out = await api(`v1/destinations/${encodeURIComponent(d.name)}/test`, { method: 'POST' });
  if (out.ok && out.message) toast(`${d.name}: ${out.message}.`);
  else if (out.ok) toast(`Sent ${d.name} a test ${destFamily(d.kind) === 'chat' ? 'message' : 'event'}.`);
  else toast(`${d.name}: ${out.error}`, { tone: 'critical' });
  await refresh();
}

async function pauseDestination(d: Destination) {
  const pause = d.status !== 'paused';
  const done = await ask({
    title: pause ? `Pause ${d.name}?` : `Resume ${d.name}?`,
    text: destFamily(d.kind) === 'desk'
      ? (pause ? 'AgentGov opens no tickets there, and neither updates nor reads back the ones it has, until it is resumed.' : 'AgentGov opens the tickets due meanwhile, tells it what changed, and reads its tickets back.')
      : (pause ? 'It gets nothing until it is resumed, then everything it missed (alerts older than an hour excepted).' : 'It gets what it missed while it was paused, then what happens next.'),
    tone: pause ? 'danger' : 'primary', iconName: pause ? 'minus' : 'play', confirm: pause ? 'Pause' : 'Resume',
    submit: () => api(`v1/destinations/${encodeURIComponent(d.name)}/${pause ? 'pause' : 'resume'}`, { method: 'POST' }),
  });
  if (!done) return;
  toast(pause ? `Paused ${d.name}.` : `Resumed ${d.name}.`);
  await refresh();
}

async function replayDestination(d: Destination) {
  const done = await ask<any>({
    title: `Send ${d.name} the ledger again?`,
    text: 'From after the ledger entry you choose (0: from the start). The SIEM drops events it already has by their metadata.uid.',
    iconName: 'undo', confirm: 'Replay',
    fields: [{ id: 'after', label: 'After ledger entry', type: 'number', min: 0, value: 0, required: true }],
    submit: (v) => api(`v1/destinations/${encodeURIComponent(d.name)}/replay`, { method: 'POST', body: { after: Number(v.after) } }),
  });
  if (!done) return;
  toast(`${d.name} gets the ledger again from after entry ${done.delivery.cursor}.`);
  await refresh();
}

async function deleteDestination(d: Destination) {
  const done = await ask({
    title: `Delete ${d.name}?`,
    text: 'It gets nothing more. Its secret file stays where it is.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete destination', busy: 'Deleting…',
    submit: () => api(`v1/destinations/${encodeURIComponent(d.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted ${d.name}.`);
  await refresh();
}
