// Agents built on other platforms (Microsoft 365 Copilot, Copilot Studio, Microsoft Foundry,
// AWS, Google Cloud, Salesforce, Databricks). They never call the gateway, so AgentGov
// governs what their platform reports about them: the connections it reads them with, their
// imports and syncs, and the connector allowlist. PlatformCard is an agent's record on its
// platform, on the agent's page.

import { Fragment, useState, type ReactNode } from 'react';
import { ask } from '../components/dialog';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import {
  AgentLink, Callout, Card, Chip, Copyable, EmptyState, Facts, PageHead, PlainChip, RefreshButton, TimeEl,
  type FactRow,
} from '../components/ui';
import { API_ROOT, api } from '../lib/api';
import { refreshBadges } from '../lib/badges';
import { fmt, fullFmt, humanize, plural } from '../lib/format';
import { refresh, type PageDef } from '../lib/router';
import { can, getMe } from '../lib/session';
import { featureModes, INVENTORY_SOURCES } from '../lib/shared';
import { platformBlock } from './agent';

type Source = any;
type Connection = any;
type ConnectorRow = any;

const M365_SETTINGS = 'AGENTGOV_M365_TENANT_ID, AGENTGOV_M365_CLIENT_ID and AGENTGOV_M365_CLIENT_SECRET';
const INVENTORY_EXPORT = [
  'az login',
  `az graph query -q "PowerPlatformResources | where type == 'microsoft.copilotstudio/agents'" --first 1000 -o json > copilot-studio-agents.json`,
].join('\n');
const PACKAGE_TYPES: Record<string, string> = {
  custom: 'Built by your organisation', shared: 'Shared by a user', external: 'From a partner', microsoft: 'Built by Microsoft',
};
const AUDIENCE: Record<string, string> = { all: 'Everyone', some: 'Some users or groups', none: 'Nobody' };

function connectorKey(id: string | null | undefined): string {
  return String(id || '').trim().replace(/\/+$/, '').split('/').pop() as string;
}

function syncCounts(c: any): string {
  const parts = [`${fmt(c.created)} new`, `${fmt(c.updated)} updated`, `${fmt(c.skipped)} skipped`];
  if (c.gone) parts.push(`${fmt(c.gone)} gone from the platform`);
  if (c.findings != null) parts.push(plural(c.findings, 'open issue'));
  return parts.join(', ');
}

interface PlatformsData { view: any; usage: any; modes: Record<string, string> }

export const platformsPage: PageDef<PlatformsData> = {
  re: /^\/platforms$/,
  nav: 'platforms',
  title: 'Platforms',
  load: async () => {
    const [view, usage, modes] = await Promise.all([
      api('v1/platforms'), api('v1/platforms/connectors'), featureModes().catch(() => ({} as Record<string, string>)),
    ]);
    return { view, usage, modes };
  },
  View: ({ data: { view, usage, modes } }) => {
    const sources = Object.fromEntries(view.sources.map((src: Source) => [src.source, src]));
    return (
      <div className="page">
        <PageHead
          title="Platforms"
          sub="Agents built on Microsoft 365 Copilot and Copilot Studio. They don't call tools through AgentGov's gateway, so AgentGov governs what their platform reports: who owns them, who they are shared with and which connectors they use."
          actions={[<RefreshButton key="refresh" />]}
        />
        {platformsCallout(view)}
        <ConnectionsCard view={view} />
        <div className="grid-halves">
          <M365Card src={sources['microsoft-365']} />
          <CopilotStudioCard src={sources['copilot-studio']} adminActions={view.admin_actions} summary={view.people} />
        </div>
        <ConnectorsCard usage={usage} view={view} modes={modes} />
        <OtherPlatformsCard view={view} />
      </div>
    );
  },
};

// A sync's button: while the sync runs it says so, and can't be pressed again.
function SyncButton({ cls, label, run }: { cls: string; label: string; run: () => Promise<void> }) {
  const [syncing, setSyncing] = useState(false);
  const onClick = async () => {
    setSyncing(true);
    try {
      await run();
    } finally {
      setSyncing(false);
    }
  };
  return (
    <button type="button" className={cls} disabled={syncing} onClick={onClick}>
      <Icon name="refresh" />{syncing ? 'Syncing…' : label}
    </button>
  );
}

function inventoryStatus(src: Source): string {
  if (!src.configured) return 'off';
  if (!src.turned_on) return 'turned_off';
  const last = src.last_sync;
  if (!last) return 'waiting';
  if (last.ok) return 'ok';
  // Some parts (a region, an account) couldn't be read, but the rest was.
  return last.counts?.failed && (last.counts.created || last.counts.updated) ? 'partial' : 'failing';
}

function OtherPlatformsCard({ view }: { view: any }) {
  const rows: Source[] = view.sources.filter((src: Source) => INVENTORY_SOURCES.has(src.source));
  if (!rows.length) return null;
  const names = rows.map((src) => src.name);
  const listed = names.length > 1 ? `${names.slice(0, -1).join(', ')} and ${names.at(-1)}` : names[0];
  return (
    <Card
      title="Other platforms"
      sub={`Agents built on ${listed}. AgentGov reads each platform it is set up for, on a schedule, and flags its agents' risky settings; it doesn't change them.`}
      flush
    >
      <div className="table-wrap">
        <table className="data rtable">
          <caption className="sr-only">Other platforms</caption>
          <thead>
            <tr>{['Platform', 'Status', 'Last sync', ''].map((t, i) => <th key={i} scope="col">{t || <span className="sr-only">Actions</span>}</th>)}</tr>
          </thead>
          <tbody>
            {rows.map((src) => {
              const status = inventoryStatus(src);
              const last = src.last_sync;
              const help = status === 'off' && src.needs ? `Needs ${src.needs}.`
                : status === 'turned_off' ? 'Turn it on again on the Features page.' : null;
              return (
                <tr key={src.source} data-platform={src.source}>
                  <td data-label="Platform">
                    <span className="cell-title">{src.name}</span>
                    <div className="cell-sub">
                      {src.agents
                        ? <a href={`#/agents?source=${encodeURIComponent(`platform:${src.source}`)}`}>{plural(src.agents, 'agent')}</a>
                        : 'No agents yet'}
                    </div>
                  </td>
                  <td data-label="Status">
                    <Chip kind="connection" value={status} />
                    {help ? <div className="cell-sub break">{help}</div> : null}
                  </td>
                  <td data-label="Last sync">
                    {last ? (
                      <div>
                        <TimeEl iso={last.at} />
                        <div className={last.ok ? 'cell-sub' : 'cell-sub tone-text-critical'}>{last.ok ? syncCounts(last.counts || {}) : last.message}</div>
                      </div>
                    ) : <span className="muted">Never</span>}
                  </td>
                  <td data-label="">
                    {can('admin') && src.configured && src.turned_on
                      ? <SyncButton cls="btn btn--sm" label="Sync now" run={() => syncConnection({ key: src.source, name: src.name })} />
                      : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function platformsCallout(view: any): ReactNode {
  const enforcing = view.threat_detection?.mode === 'enforce';
  // Blocked here, an agent its platform still runs gets an issue asking its people to stop it there.
  const handOff = 'An agent blocked here that its platform still runs gets an issue asking its people to stop it there, which closes once a sync shows it stopped.';
  if (!view.admin_actions && !enforcing) {
    return (
      <Callout tone="neutral" icon="info">
        <span><strong>{'AgentGov reads these platforms; on its own it does not change them. '}</strong>{handOff}</span>
      </Callout>
    );
  }
  const may = [
    view.admin_actions ? 'admins signed in through Microsoft Entra ID can quarantine and block these agents from here' : null,
    enforcing ? "AgentGov's policies decide about each tool call Copilot Studio agents make, so blocking one here stops its tool calls" : null,
  ].filter(Boolean);
  return (
    <Callout tone="neutral" icon="info">
      <span><strong>{'AgentGov works alongside these platforms: '}</strong>{`${may.join(', and ')}. ${handOff}`}</span>
    </Callout>
  );
}

const CONNECTION_COUNTS: Record<string, (c: any) => string> = {
  'microsoft-365': (c) => syncCounts(c),
  'copilot-studio': (c) => syncCounts(c),
  'entra-agent-id': (c) => `${fmt(c.created)} new, ${fmt(c.updated)} updated, ${fmt(c.linked)} linked to agents`,
  'entra-users': (c) => [`${plural(c.found, 'person', 'people')} found`, c.not_found ? `${fmt(c.not_found)} not users` : null,
    c.left ? `${fmt(c.left)} left` : null].filter(Boolean).join(', '),
  'purview-audit': (c) => [`${plural(c.interactions, 'interaction')}`, `${plural(c.maker_events, 'maker change')}`,
    c.searching ? `${plural(c.searching, 'search', 'searches')} running` : null].filter(Boolean).join(', '),
  defender: (c) => `${plural(c.alerts, 'alert')} about agents, ${fmt(c.matched)} matched, ${fmt(c.resolved)} resolved`,
  'entra-access-packages': (c) => `${plural(c.packages, 'package')} agents can hold, ${plural(c.assignments, 'assignment')} to agents, ${fmt(c.expiring)} expiring`,
  'connector-policies': (c) => `${plural(c.connectors, 'connector')} applied to ${plural(c.targets, 'group or environment', 'groups or environments')}`,
};

function connectionHelp(c: Connection): string | null {
  if (c.status === 'missing_permission') return `Grant AgentGov's app registration the application permission ${c.permission}, with admin consent, then sync.`;
  if (c.status === 'out_of_date') return 'The allowlist changed since it was pushed: push it again.';
  if (c.status === 'turned_off') return 'Turn it on again on the Features page.';
  if (c.key === 'threat-detection') {
    const origin = new URL(API_ROOT).origin;
    return c.status === 'off'
      ? `Needs ${c.needs.join(', ')}. Connect ${origin}/integrations/copilot-studio in the Power Platform admin center, then turn on Copilot Studio threat detection on the Features page.`
      : `Endpoint: ${origin}/integrations/copilot-studio`;
  }
  if (c.status === 'off' || c.status === 'import') return `Needs ${c.needs.join(', and ')}.`;
  if (c.manage === 'unknown') {
    return "Managing: the app's token holds no EntitlementManagement.ReadWrite.All, so Entra takes AgentGov's requests only for catalogs where its app is an Access package assignment manager.";
  }
  return null;
}

function connectionLastRun(c: Connection, view: any): ReactNode {
  if (c.key === 'threat-detection') {
    const t = view.threat_detection || {};
    if (!t.calls) return <span className="muted">{c.status === 'off' ? '—' : 'No calls yet'}</span>;
    return (
      <div>
        {`${plural(t.calls, 'tool call')}, ${fmt(t.blocked || 0)} blocked`}
        {t.would_block ? `, ${fmt(t.would_block)} would have been` : ''}
        <div className="cell-sub">{'Last call '}<TimeEl iso={t.last_call_at} /></div>
      </div>
    );
  }
  const last = c.last_run;
  if (!last) return <span className="muted">Never</span>;
  const summary = last.ok ? (CONNECTION_COUNTS[c.key] || syncCounts)(last.counts || {}) : last.message;
  return (
    <div>
      <TimeEl iso={last.at} />
      <div className={last.ok ? 'cell-sub' : 'cell-sub tone-text-critical'}>{summary}</div>
    </div>
  );
}

function ConnectionsCard({ view }: { view: any }) {
  const rows: Connection[] = view.connections || [];
  const appReady = rows.some((c) => c.via === 'app' && !['off', 'turned_off'].includes(c.status));
  const actions = can('admin') && appReady
    ? [<SyncButton key="sync-all" cls="btn btn--sm" label="Sync all" run={syncConnections} />]
    : null;
  return (
    <Card title="Microsoft connections" sub="Each one is optional. AgentGov uses the ones it can reach and works without the others." actions={actions} flush>
      <div className="table-wrap">
        <table className="data rtable">
          <caption className="sr-only">Microsoft connections</caption>
          <thead>
            <tr>{['Connection', 'Status', 'Last run', ''].map((t, i) => <th key={i} scope="col">{t || <span className="sr-only">Actions</span>}</th>)}</tr>
          </thead>
          <tbody>
            {rows.map((c) => {
              const help = connectionHelp(c);
              const syncable = can('admin') && c.via === 'app' && !['off', 'turned_off'].includes(c.status);
              return (
                <tr key={c.key} data-connection={c.key}>
                  <td data-label="Connection"><span className="cell-title">{c.name}</span><div className="cell-sub">{c.gives}</div></td>
                  <td data-label="Status">
                    <Chip kind="connection" value={c.status} />
                    {help ? <div className="cell-sub break">{help}</div> : null}
                  </td>
                  <td data-label="Last run">{connectionLastRun(c, view)}</td>
                  <td data-label="">{syncable ? <SyncButton cls="btn btn--sm" label="Sync now" run={() => syncConnection(c)} /> : null}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

async function syncConnection(c: { key: string; name: string }): Promise<void> {
  try {
    const counts = await api(`v1/platforms/${encodeURIComponent(c.key)}/sync`, { method: 'POST' });
    toast(`${c.name}: ${(CONNECTION_COUNTS[c.key] || syncCounts)(counts)}.`);
  } catch (err: any) {
    toast(err.message, { tone: 'critical' });
  }
  void refreshBadges();
  await refresh();
}

async function syncConnections(): Promise<void> {
  try {
    const results = await api<Record<string, any>>('v1/platforms/sync', { method: 'POST' });
    const failed = Object.entries(results).filter(([, r]) => r.error);
    if (failed.length) toast(`Synced, but ${failed.map(([k]) => k).join(', ')} failed: see Microsoft connections.`, { tone: 'critical' });
    else toast('Synced every Microsoft connection AgentGov may use.');
  } catch (err: any) {
    toast(err.message, { tone: 'critical' });
  }
  void refreshBadges();
  await refresh();
}

function sourceFacts(src: Source, verb: string): ReactNode {
  const last = src.last_sync;
  return (
    <Facts rows={[
      ['Agents', src.agents
        ? <a href={`#/agents?source=${encodeURIComponent(`platform:${src.source}`)}`}>{plural(src.agents, 'agent')}</a>
        : <span className="muted">None yet</span>],
      [`Last ${verb}`, last ? <><Chip kind="sync" value={last.ok ? 'ok' : 'failed'} />{' '}<TimeEl iso={last.at} /></> : <span className="muted">Never</span>],
      last?.ok ? ['Result', syncCounts(last.counts)] : null,
    ]} />
  );
}

function M365Card({ src }: { src: Source }) {
  const last = src.last_sync;
  const actions = can('admin') && src.configured
    ? [<SyncButton key="m365-sync" cls="btn btn--sm btn--primary" label="Sync now" run={syncMicrosoft365} />]
    : null;
  return (
    <Card
      title="Microsoft 365"
      sub="The organisation's agent catalog, read from Microsoft Graph on a schedule: custom agents, agents users share, and partners' agents."
      actions={actions}
    >
      {src.configured ? (
        <>
          {last && !last.ok ? (
            <Callout tone="critical" icon="octagon"><span><strong>{'The last sync failed. '}</strong>{last.message}</span></Callout>
          ) : null}
          {sourceFacts(src, 'sync')}
        </>
      ) : (
        <EmptyState
          title="Not connected"
          text={`To sync, set ${M365_SETTINGS} for a Microsoft Entra app that has the Microsoft Graph application permission CopilotPackages.Read.All. Microsoft requires a Microsoft Agent 365 licence for this API.`}
        />
      )}
    </Card>
  );
}

async function syncMicrosoft365(): Promise<void> {
  try {
    const counts = await api('v1/platforms/microsoft-365/sync', { method: 'POST' });
    toast(`Synced the Microsoft 365 catalog: ${syncCounts(counts)}.`);
  } catch (err: any) {
    toast(err.message, { tone: 'critical' });
  }
  void refreshBadges();
  await refresh();
}

// Who made Copilot Studio's agents, as far as AgentGov knows them.
function makersFact(summary: any): FactRow {
  if (!summary?.named) return null;
  const parts = [`${fmt(summary.known)} of ${fmt(summary.named)} known by name`];
  if (summary.unknown) parts.push(`${fmt(summary.unknown)} not looked up yet`);
  if (summary.left) parts.push(`${fmt(summary.left)} left`);
  if (summary.disabled) parts.push(`${fmt(summary.disabled)} with their account disabled`);
  return ['Makers and owners', parts.join(', ')];
}

function CopilotStudioCard({ src, adminActions, summary }: { src: Source; adminActions: any; summary: any }) {
  const asYou = adminActions && can('admin') && getMe()?.microsoft;
  const actions = can('admin') ? [
    asYou ? <SyncButton key="studio-sync" cls="btn btn--sm btn--primary" label="Sync now" run={syncCopilotStudio} /> : null,
    <button key="studio-import" type="button" className={asYou ? 'btn btn--sm' : 'btn btn--sm btn--primary'} onClick={guarded(importCopilotStudio)}>
      <Icon name="upload" />Import inventory
    </button>,
    summary?.named ? (
      <button key="people-import" type="button" className="btn btn--sm" onClick={guarded(importPeople)}><Icon name="upload" />Upload users</button>
    ) : null,
  ].filter(Boolean) : null;
  const makers = makersFact(summary);
  return (
    <Card
      title="Copilot Studio"
      sub={asYou
        ? 'Copilot Studio and Agent Builder agents with the connectors they use, from the Power Platform inventory. Microsoft only lets a signed-in admin read it, so AgentGov syncs it as you.'
        : 'Copilot Studio and Agent Builder agents with the connectors they use, from the Power Platform inventory. Microsoft only lets a signed-in admin read the inventory, so export it and import the file here'
          + (adminActions && can('admin') ? ', or sign in to AgentGov with Microsoft Entra ID to sync it from here.' : '.')}
      actions={actions}
    >
      {src.last_sync ? (
        <>
          {sourceFacts(src, 'update')}
          {makers ? <Facts rows={[makers]} /> : null}
          {summary?.unknown ? (
            <p className="hint">Copilot Studio names makers by their Entra IDs. AgentGov looks them up with its app (User.Read.All) or as an admin signed in with Microsoft; without either, upload the list of users from the Microsoft Entra admin center (Users, Download users).</p>
          ) : null}
        </>
      ) : (
        <EmptyState
          title="Nothing imported yet"
          text="Export the inventory as a Power Platform or AI administrator (a reader role is enough), then import the file:"
          action={<pre className="kv-pre">{INVENTORY_EXPORT}</pre>}
        />
      )}
    </Card>
  );
}

async function importPeople() {
  const result = await ask<any>({
    title: 'Upload a list of users',
    text: "So that AgentGov knows the people Copilot Studio names by their Entra IDs. In the Microsoft Entra admin center, go to Users, then Download users (anyone can): the file has each user's object ID, name and email address. AgentGov keeps those; it doesn't take a user missing from the list to have left.",
    iconName: 'upload', confirm: 'Upload', busy: 'Uploading…', wide: true,
    fields: [{ id: 'csv', label: 'Users (CSV)', type: 'code', rows: 8, required: true, file: '.csv', placeholder: 'objectId,userPrincipalName,displayName,mail,accountEnabled\n…' }],
    submit: (v) => api('v1/platforms/entra-users/import', { method: 'POST', text: v.csv, contentType: 'text/csv' }),
  });
  if (!result) return;
  const m = result.makers || {};
  toast(`Kept ${plural(result.people, 'person', 'people')}. AgentGov now knows ${fmt(m.known)} of the ${fmt(m.named)} people Copilot Studio names.`);
  await refresh();
}

async function syncCopilotStudio(): Promise<void> {
  try {
    const counts = await api('v1/platforms/copilot-studio/sync', { method: 'POST' });
    toast(`Synced the Copilot Studio inventory: ${syncCounts(counts)}.`);
  } catch (err: any) {
    toast(err.message, { tone: 'critical' });
  }
  void refreshBadges();
  await refresh();
}

async function importCopilotStudio() {
  const result = await ask<any>({
    title: 'Import Copilot Studio agents',
    text: 'Load or paste the Power Platform inventory, as JSON. Export it as a Power Platform or AI administrator (a reader role is enough) with the Azure CLI, the Power Platform API or `pac resource-query`. Importing again updates the agents already here.',
    extra: <pre className="kv-pre">{INVENTORY_EXPORT}</pre>,
    iconName: 'upload', confirm: 'Import', busy: 'Importing…', wide: true,
    fields: [{
      id: 'json', label: 'Inventory (JSON)', type: 'code', rows: 10, required: true, file: '.json',
      placeholder: '{"data": [{"name": "…", "type": "microsoft.copilotstudio/agents", "properties": {…}}]}',
    }, {
      id: 'complete', type: 'checkbox', value: false,
      label: 'This is the whole inventory, every environment',
      hint: 'Agents missing from it are marked gone from Copilot Studio, and their issues close. Leave it unticked for an export of some environments, or one page of a larger one (import every page at once with `agentgov platforms import --complete`).',
    }],
    submit: (v) => {
      try {
        JSON.parse(v.json);
      } catch (err: any) {
        throw new Error(`That isn't valid JSON: ${err.message}`, { cause: err });
      }
      const path = `v1/platforms/copilot-studio/import${v.complete ? '?complete=true' : ''}`;
      return api(path, { method: 'POST', text: v.json, contentType: 'application/json' });
    },
  });
  if (!result) return;
  toast(`Imported Copilot Studio agents: ${syncCounts(result)}.`);
  void refreshBadges();
  await refresh();
}

// What happens to an agent that uses a connector the allowlist doesn't name
// (docs/platforms.md#when-an-agent-uses-a-connector-that-isnt-approved).
function connectorResponse(modes: Record<string, string>): ReactNode {
  const detection = modes['copilot-studio-threat-detection'];
  const control = modes['connector-allowlist'];
  let runtime;
  if (!detection || detection === 'off') runtime = 'not checked as they run, because Copilot Studio threat detection is off';
  else if (control === 'off') runtime = 'not checked as they run, because the connector allowlist control is off';
  else if (detection === 'monitor' || control === 'monitor') runtime = 'let through, and recorded as what AgentGov would refuse';
  else runtime = 'refused by Copilot Studio threat detection';
  return (
    <p className="hint">
      {'An agent that uses a connector that is not approved is flagged, and its people are told. Its calls through that connector are '}
      {runtime}{'. '}<a href="#/features">Features</a>{' sets this, and a '}<a href="#/policies">management rule</a>
      {' can block such agents too.'}
    </p>
  );
}

// The first few of a list, and how many more there are.
function listed<T>(items: T[], max: number, render: (item: T) => ReactNode): ReactNode[] {
  return [
    ...items.slice(0, max).map((item, i) => <Fragment key={i}>{render(item)}</Fragment>),
    items.length > max ? <span key="more" className="muted small">{`and ${fmt(items.length - max)} more`}</span> : null,
  ];
}

function ConnectorsCard({ usage, view, modes = {} }: { usage: any; view: any; modes?: Record<string, string> }) {
  const rows: ConnectorRow[] = usage.connectors || [];
  const active = usage.allowlist_active;
  const pushable = can('admin') && view?.admin_actions && getMe()?.microsoft;
  const approved = rows.filter((r) => r.approved).length;
  const status = (r: ConnectorRow) => {
    if (r.approved) {
      const title = [r.approved_by && `Approved by ${r.approved_by}`, r.approved_at && fullFmt.format(new Date(r.approved_at))].filter(Boolean).join(', ') || null;
      return <Chip kind="connector" value="approved" title={title} />;
    }
    return active
      ? <Chip kind="connector" value="unapproved" title="Agents that use it get an issue" />
      : <Chip kind="connector" value="unchecked" title="The allowlist is empty, so nothing is flagged yet" />;
  };
  return (
    <Card
      title="Connectors"
      sub={active
        ? 'The Power Platform connectors Copilot Studio agents use. An agent that uses a connector that is not approved gets a high-severity issue.'
        : 'The Power Platform connectors Copilot Studio agents use. The allowlist is empty, so none is flagged yet: approve the connectors your organisation allows, and agents that use any other connector get an issue.'}
      actions={can('admin') ? [
        pushable ? (
          <button key="push" type="button" className="btn btn--sm" onClick={guarded(pushConnectorPolicy)}><Icon name="upload" />Push to Power Platform</button>
        ) : null,
        <button key="approve" type="button" className="btn btn--sm btn--primary" onClick={guarded(() => approveConnector(null, active))}>
          <Icon name="plus" />Approve a connector
        </button>,
      ].filter(Boolean) : null}
      flush={rows.length > 0}
      foot={active ? connectorResponse(modes) : null}
    >
      {rows.length ? (
        <div className="table-wrap">
          <table className="data rtable">
            <caption className="sr-only">Connectors</caption>
            <thead>
              <tr>
                {['Connector', 'Allowlist', 'Agents', 'Tools', 'Maker connections', ''].map((t, i) => (
                  <th key={i} scope="col" className={t === 'Maker connections' ? 'num' : undefined}>{t || <span className="sr-only">Actions</span>}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.connector_id}>
                  <td data-label="Connector" className="break">
                    <code className="cell-title">{r.connector_id}</code>
                    {r.note ? <div className="cell-sub">{r.note}</div> : null}
                  </td>
                  <td data-label="Allowlist">{status(r)}</td>
                  <td data-label="Agents">
                    {r.agents.length
                      ? <div className="chip-row">{listed(r.agents, 3, (ag: any) => <AgentLink id={ag.id} name={ag.name} />)}</div>
                      : <span className="muted">None</span>}
                  </td>
                  <td data-label="Tools">
                    {r.operations.length
                      ? <div className="chip-row">{listed(r.operations, 3, (op: string) => <PlainChip text={op} mono />)}</div>
                      : <span className="muted">—</span>}
                  </td>
                  <td data-label="Maker connections" className="num">
                    {r.maker_connections
                      ? <span title="Tools that run with the maker's credentials for every user">{fmt(r.maker_connections)}</span>
                      : <span className="muted">0</span>}
                  </td>
                  <td data-label="">
                    {can('admin') ? (r.approved ? (
                      <button type="button" className="btn btn--sm btn--danger-quiet" onClick={guarded(() => unapproveConnector(r, approved))}>
                        <Icon name="ban" />Remove approval
                      </button>
                    ) : (
                      <button type="button" className="btn btn--sm" onClick={guarded(() => approveConnector(r, active))}><Icon name="check" />Approve</button>
                    )) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState title="No connectors yet" text="They appear here once Copilot Studio agents are imported. You can approve connectors before that." />
      )}
    </Card>
  );
}

async function pushConnectorPolicy() {
  const preview = await api('v1/platforms/connector-policy');
  if (!preview.allowlist.length) {
    toast('Approve at least one connector first: Power Platform would block every connector.', { tone: 'critical' });
    return;
  }
  const free = preview.targets.filter((t: any) => !t.other_policies.length);
  const taken = preview.targets.filter((t: any) => t.other_policies.length);
  const key = (t: any) => `target:${t.scope}:${t.id}`;
  const label = (t: any) => (t.scope === 'group'
    ? `${t.name} (environment group)`
    : `Environment ${t.name}${t.agents ? ` (${plural(t.agents, 'Copilot Studio agent')})` : ''}`);
  const losing = preview.agents_losing_connectors;
  const extra = (
    <div className="stack">
      <Callout tone="warning" icon="triangle">
        <span>
          <strong>{"Power Platform blocks every connector this policy doesn't list"}</strong>
          {`, for apps and flows as well as agents, in the groups and environments you choose. It will allow: ${preview.allowlist.join(', ')}.`}
        </span>
      </Callout>
      {losing.length ? (
        <Callout tone="serious" icon="triangle">
          <span>
            <strong>{`${plural(losing.length, 'agent')} would lose connectors: `}</strong>
            {losing.map((a: any) => `${a.name} (${a.connectors.join(', ')})`).join('; ')}{'.'}
          </span>
        </Callout>
      ) : null}
      {preview.out_of_date ? <p className="hint">{"Power Platform's copy of the policy differs from the allowlist; pushing replaces it."}</p> : null}
      {taken.length ? (
        <p className="hint">
          {'Not offered, because another connector policy applies there and an environment takes one: '}
          {taken.map((t: any) => `${t.name} (${t.other_policies.join(', ')})`).join('; ')}{'.'}
        </p>
      ) : null}
      {free.length ? null : <p className="hint">No environment group or environment is free for this policy.</p>}
    </div>
  );
  const done = await ask<any>({
    title: 'Push the connector allowlist to Power Platform?',
    text: `AgentGov saves it as the connector policy "${preview.policy_name}" and applies it where you choose, as you. Wherever the policy already applies, its list changes too. The ledger records it.`,
    tone: 'danger', iconName: 'upload', confirm: 'Push to Power Platform', busy: 'Pushing…', wide: true, extra,
    fields: free.map((t: any) => ({ id: key(t), type: 'checkbox', value: t.applied, label: label(t), hint: t.applied ? 'Already applied: its list is updated.' : null })),
    submit: (values) => {
      const targets = free.filter((t: any) => values[key(t)]).map((t: any) => ({ scope: t.scope, id: t.id }));
      if (!targets.length) throw new Error('Pick at least one environment group or environment.');
      return api('v1/platforms/connector-policy', { method: 'POST', body: { targets } });
    },
  });
  if (!done) return;
  toast(`Pushed ${plural(done.connectors.length, 'connector')} to Power Platform, applied to ${plural(done.targets.length, 'group or environment', 'groups or environments')}.`);
  await refresh();
}

async function approveConnector(row: ConnectorRow | null, active: any) {
  const first = active ? '' : ' This is the first approved connector: from now on, agents that use connectors which are not approved get an issue.';
  const done = await ask<any>({
    title: row ? `Approve ${row.connector_id}?` : 'Approve a connector',
    text: (row ? `Copilot Studio agents may use ${row.connector_id} without an issue.` : 'Add a Power Platform connector to the allowlist.') + first,
    iconName: 'check', confirm: 'Approve', busy: 'Approving…',
    fields: [
      row ? null : { id: 'connector', label: 'Connector ID', required: true, mono: true, placeholder: 'shared_office365', hint: 'As the inventory or the connector reference names it, with or without /providers/Microsoft.PowerApps/apis/.' },
      { id: 'note', label: 'Note', type: 'textarea', value: row?.note || '', hint: 'Why it is allowed. Shown here and recorded in the evidence ledger.' },
    ],
    submit: (v) => api(`v1/platforms/connectors/${encodeURIComponent(connectorKey(row ? row.connector_id : v.connector))}/approval`, { method: 'PUT', body: { note: v.note || '' } }),
  });
  if (!done) return;
  toast(`Approved ${done.connector_id}.`);
  void refreshBadges();
  await refresh();
}

async function unapproveConnector(row: ConnectorRow, approvedCount: number) {
  const users = row.agents.length ? `${plural(row.agents.length, 'agent')} that use it will get an issue.` : 'No imported agent uses it.';
  const last = approvedCount === 1 ? ' It is the last approved connector, so the allowlist stops being checked until you approve another.' : '';
  const done = await ask({
    title: `Remove ${row.connector_id} from the allowlist?`,
    text: approvedCount === 1 ? `No connector will be approved.${last}` : users,
    tone: 'danger', iconName: 'ban', confirm: 'Remove approval', busy: 'Removing…',
    submit: () => api(`v1/platforms/connectors/${encodeURIComponent(row.connector_id)}/approval`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`${row.connector_id} is no longer approved.`);
  void refreshBadges();
  await refresh();
}

const yesNo = (value: unknown) => (value == null ? null : value ? 'Yes' : 'No');

/** What Microsoft Entra ID reports about an agent's identity (its page's main card). */
function EntraCard({ v }: { v: any }) {
  const why = String(v.disabled_by_microsoft || '').replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase();
  return (
    <Card title={v.source_name} sub="The agent's identity in Microsoft Entra ID, as it was at the last sync">
      {v.disabled_by_microsoft ? (
        <Callout tone="critical" icon="octagon">{`Microsoft disabled this identity (${why}), so the agent cannot sign in.`}</Callout>
      ) : null}
      {v.in_directory === false ? <Callout tone="warning" icon="triangle">This identity is no longer in Microsoft Entra ID.</Callout> : null}
      <Facts rows={[
        ['Name in Entra', v.display_name],
        ['Enabled', yesNo(v.enabled)],
        ['Created from', v.blueprint ? `${v.blueprint} (its agent identity blueprint)` : (v.blueprint_id ? <code>{v.blueprint_id}</code> : null)],
        ['Created', <TimeEl iso={v.created_at} />],
        ['Entra agent ID', <Copyable text={v.external_id} label="Entra agent ID" />],
        ['Synced', <TimeEl iso={v.synced_at} />],
      ]} />
    </Card>
  );
}

/** Who used the agent lately and where, from the Microsoft Purview audit log. */
function usageRows(v: any): FactRow[] {
  const u = v.usage;
  if (!u) return [];
  return [
    ['Last used', <TimeEl iso={u.last_used_at} />],
    (u.recent_users || []).length ? ['Recent users', (
      <div className="chip-row">
        {u.recent_users.slice(0, 5).map((x: string, i: number) => <PlainChip key={i} text={x} />)}
        {u.recent_users.length > 5 ? <span className="muted small">{`and ${fmt(u.recent_users.length - 5)} more`}</span> : null}
      </div>
    )] : null,
    Object.keys(u.hosts || {}).length ? ['Used in', (
      <div className="chip-row">
        {Object.entries(u.hosts as Record<string, number>).map(([host, n]) => <PlainChip key={host} text={`${host} · ${fmt(n)}`} />)}
      </div>
    )] : null,
  ];
}

// What a connector of AgentGov's own read about an agent on its platform.
function InventoryCard({ v }: { v: any }) {
  const notes = v.in_inventory === false
    ? <Callout tone="warning" icon="triangle">{`${v.source_name} no longer reports this agent. Delete it here when you no longer need its record.`}</Callout>
    : v.stopped ? <Callout tone="neutral" icon="ban">{`Stopped in ${v.source_name}: it takes no calls there.`}</Callout> : null;
  const value = (f: any): ReactNode => {
    if (f.tone) return <PlainChip text={f.value} tone={f.tone} iconName={f.tone === 'serious' ? 'triangle' : 'alert-circle'} />;
    return f.code ? <code>{f.value}</code> : f.value;
  };
  const rows: FactRow[] = [
    ['Name there', v.display_name],
    ['What it is', v.kind],
    ...(v.facts || []).map((f: any): FactRow => [f.label, value(f)]),
    ['ID', <Copyable text={v.external_id} label={`${v.source_name} ID`} />],
    /^https:\/\//.test(v.url || '') ? ['Open', <a href={v.url} target="_blank" rel="noopener noreferrer">{`In ${v.source_name}`}</a>] : null,
    ['Synced', <TimeEl iso={v.synced_at} />],
  ];
  const tools = v.tools || [];
  return (
    <Card title={v.source_name} sub={`As ${v.source_name} reported it at the last sync`}>
      {notes}
      <Facts rows={rows} />
      {tools.length ? (
        <div className="stack" style={{ gap: 8, marginTop: 14 }}>
          <h3 className="dialog-section">Tools</h3>
          <ul className="perm-list" role="list">
            {tools.map((t: any, i: number) => (
              <li key={i}>
                <span className="perm-server"><code>{t.name}</code>{' '}<PlainChip text={t.kind} tone={t.tone || null} /></span>
                {t.detail ? <div className="cell-sub break">{t.detail}</div> : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </Card>
  );
}

/** What a platform reports about an agent (its page's main card), and blocking it there. */
export function PlatformCard({ a, v, where }: { a: any; v: any; where: any }) {
  if (v.source === 'entra-agent-id') return <EntraCard v={v} />;
  if (INVENTORY_SOURCES.has(v.source)) return <InventoryCard v={v} />;
  const microsoft = getMe()?.microsoft;
  const studio = v.source === 'copilot-studio';
  // Only on the card for the record the control plane acts on.
  const acts = where && where.source === v.source;
  const blockedThere = studio ? v.quarantined : v.blocked;
  const actions = acts && microsoft ? [blockedThere ? (
    <button key="platform-unblock" type="button" className="btn btn--sm" onClick={guarded(() => platformBlock(a, where, false))}>
      <Icon name="undo" />{studio ? 'Release from quarantine' : 'Unblock in Microsoft 365'}
    </button>
  ) : (
    <button key="platform-block" type="button" className="btn btn--sm btn--danger-quiet" onClick={guarded(() => platformBlock(a, where, true))}>
      <Icon name="ban" />{studio ? 'Quarantine' : 'Block in Microsoft 365'}
    </button>
  )] : null;
  const rows: FactRow[] = studio ? [
    ['Name in Copilot Studio', v.display_name],
    ['Created in', v.created_in],
    ['Authentication', String(v.authentication).toLowerCase() === 'none'
      ? <PlainChip text="None: anyone can use it" tone="serious" iconName="triangle" /> : v.authentication],
    ['Shared with', v.shared_with_everyone
      ? <PlainChip text="Everyone in the organisation" tone="warning" iconName="alert-circle" />
      : `${plural(v.viewers?.users ?? 0, 'person', 'people')}, ${plural(v.viewers?.groups ?? 0, 'group')}`],
    (v.channels || []).length ? ['Channels', <div className="chip-row">{v.channels.map((c: string, i: number) => <PlainChip key={i} text={c} />)}</div>] : null,
    v.orchestration ? ['Orchestration', v.orchestration] : null,
    v.model ? ['Model', <code>{v.model}</code>] : null,
    v.web_search_knowledge != null ? ['Web search for knowledge', yesNo(v.web_search_knowledge)] : null,
    ['Published', <TimeEl iso={v.published_at} empty="Not published (draft)" />],
    v.owner_id ? ['Owner (Entra object ID)', <code>{v.owner_id}</code>] : null,
    v.environment_id ? ['Environment', <code>{v.environment_id}</code>] : null,
    ['Agent ID', <Copyable text={v.external_id} label="Copilot Studio agent ID" />],
    ['Imported', <TimeEl iso={v.synced_at} />],
    ...usageRows(v),
  ] : [
    ['Name in Microsoft 365', v.display_name],
    ['Type', PACKAGE_TYPES[v.type] || humanize(v.type)],
    v.publisher ? ['Publisher', v.publisher] : null,
    v.built_with ? ['Built with', v.built_with] : null,
    v.classification ? ['Classification', v.classification] : null,
    ['Available to', AUDIENCE[v.available_to] || humanize(v.available_to)],
    ['Deployed to', AUDIENCE[v.deployed_to] || humanize(v.deployed_to)],
    v.request ? ['Request', `${humanize(v.request.type)} request, ${v.request.status}`] : null,
    v.version ? ['Version', v.version] : null,
    ['Package ID', <Copyable text={v.external_id} label="package ID" />],
    ['Changed', <TimeEl iso={v.last_modified} />],
    ['Synced', <TimeEl iso={v.synced_at} />],
    ...usageRows(v),
  ];
  return (
    <Card
      title={v.source_name}
      sub={studio ? 'As the Power Platform inventory reported it at the last import' : 'As the Microsoft 365 agent catalog reported it at the last sync'}
      actions={actions}
    >
      {v.in_catalog === false ? (
        <Callout tone="warning" icon="triangle">This agent is no longer in the Microsoft 365 catalog. Delete it here when you no longer need its record.</Callout>
      ) : null}
      {studio && v.in_inventory === false ? (
        <Callout tone="warning" icon="triangle">
          {"Copilot Studio no longer has this agent: the last sync, or an import of the whole inventory, didn't list it. Delete it here when you no longer need its record."}
        </Callout>
      ) : null}
      {v.blocked ? <Callout tone="neutral" icon="ban">Blocked in Microsoft 365.</Callout> : null}
      {v.quarantined ? <Callout tone="neutral" icon="ban">{"Quarantined in Copilot Studio: it works only in its makers' test pane."}</Callout> : null}
      {acts && !microsoft ? (
        <p className="hint">{`To ${studio ? 'quarantine' : 'block'} it in ${v.source_name} from here, sign in to AgentGov with Microsoft Entra ID.`}</p>
      ) : null}
      <Facts rows={rows} />
      {studio ? connectorList(v) : null}
    </Card>
  );
}

function connectorList(v: any): ReactNode {
  const connectors = v.connectors || [];
  return (
    <div className="stack" style={{ gap: 8, marginTop: 14 }}>
      <h3 className="dialog-section">Connectors</h3>
      {connectors.length ? (
        <ul className="perm-list" role="list">
          {connectors.map((c: any, i: number) => (
            <li key={i}>
              <span className="perm-server">
                <code>{c.connector_id}</code>{' '}
                {v.allowlist_active ? <Chip kind="connector" value={c.approved ? 'approved' : 'unapproved'} /> : null}
              </span>
              <div className="chip-row">
                {(c.operations || []).map((op: any, j: number) => (
                  <PlainChip
                    key={j}
                    text={op.operation_id || '(unnamed)'}
                    mono
                    tone={op.maker_connection ? 'warning' : null}
                    title={[op.used_as, op.maker_connection ? "runs with the maker's connection" : "runs with the user's own connection", op.enabled ? null : 'disabled'].filter(Boolean).join(', ')}
                  />
                ))}
              </div>
            </li>
          ))}
        </ul>
      ) : <p className="muted small">No Power Platform connectors.</p>}
      {connectors.some((c: any) => (c.operations || []).some((op: any) => op.maker_connection))
        ? <p className="hint">{"Highlighted tools run with their maker's connection, so every user reaches data with the maker's access."}</p> : null}
      {v.allowlist_active ? null : <p className="hint"><a href="#/platforms">The connector allowlist</a>{' is empty, so connectors are not checked yet.'}</p>}
    </div>
  );
}
