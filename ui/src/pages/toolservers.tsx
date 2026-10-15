// MCP tool servers: published through the gateway, listed for developers, or reached
// outside the gateway with identity assertions; and the tools each one has.

import { useId, useState } from 'react';
import { ask } from '../components/dialog';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import {
  Callout, Chip, Copyable, EmptyState, Facts, PageHead, PlainChip, RefreshButton, TimeEl,
} from '../components/ui';
import { api } from '../lib/api';
import { fmt, humanize, plural, shortHash } from '../lib/format';
import { formatLabels, orNull, parseLabels } from '../lib/forms';
import { refresh, type PageDef } from '../lib/router';
import { can } from '../lib/session';
import { NAME_HINT } from '../lib/shared';

type Server = any;
type Tool = any;

// The catalogs shown, by server: kept while the app is open. A server's catalog opens by
// itself the first time it has a tool poisoned or changed.
const openCatalogs = new Set<string>();
const ANNOTATION_LABELS: Record<string, [string, string | null]> = {
  readOnlyHint: ['Read-only', null],
  destructiveHint: ['Destructive', 'warning'],
  idempotentHint: ['Idempotent', null],
  openWorldHint: ['Open world', null],
};

function isChanged(t: Tool): boolean {
  return Boolean(t.changed_at) || Boolean(t.approved_fingerprint && t.fingerprint && t.approved_fingerprint !== t.fingerprint);
}

export const toolserversPage: PageDef<Server[]> = {
  re: /^\/toolservers$/,
  nav: 'toolservers',
  title: 'Tool servers',
  load: () => api('v1/toolservers'),
  View: ({ data: servers }) => (
    <div className="page">
      <PageHead
        title="Tool servers"
        sub="MCP servers published through the gateway. AgentGov fingerprints every tool definition when it is first seen and quarantines tools that change or carry hidden instructions."
        actions={[
          can('admin') ? (
            <button key="register" type="button" className="btn btn--primary" onClick={guarded(registerToolserver)}>
              <Icon name="plus" />Register tool server
            </button>
          ) : null,
          <RefreshButton key="refresh" />,
        ]}
      />
      {servers.length ? (
        <div className="stack">{servers.map((ts) => <ServerCard key={ts.id} ts={ts} />)}</div>
      ) : (
        <section className="card">
          <EmptyState
            title="No tool servers registered"
            text={can('admin') ? 'Register an MCP server to publish it through the gateway.' : 'An admin registers MCP servers here, with the CLI or with a ToolServer manifest.'}
          />
        </section>
      )}
    </div>
  ),
};

const TRUST_LEVELS = [['unverified', 'Unverified'], ['verified', 'Verified']];
const CLASSIFICATIONS = [['public', 'Public'], ['internal', 'Internal'], ['confidential', 'Confidential'], ['restricted', 'Restricted']];

// Packages developers run, one per line as type:identifier@version (the CLI's --package).
export function formatPackages(packages: any[] | null | undefined): string {
  return (packages || []).map((p) => `${p.registry_type}:${p.identifier}${p.version ? `@${p.version}` : ''}`).join('\n');
}

function parsePackages(text: string) {
  return text.split('\n').map((line) => line.trim()).filter(Boolean).map((line) => {
    const colon = line.indexOf(':');
    if (colon < 1) throw new Error(`"${line}" isn't a package: write type:identifier@version, such as npm:@playwright/mcp@0.0.41.`);
    const kind = line.slice(0, colon);
    const rest = line.slice(colon + 1);
    const at = rest.lastIndexOf('@');
    return at > 0
      ? { registry_type: kind, identifier: rest.slice(0, at), version: rest.slice(at + 1) }
      : { registry_type: kind, identifier: rest };
  });
}

/** Register a tool server (no `ts`, starting from `draft` if given) or edit one. Resolves
 * to the saved server, or null. */
export function toolserverForm(existing: Server | null, draft: Server | null = null): Promise<Server | null> {
  const editing = Boolean(existing);
  const ts = existing || draft;
  const options = (pairs: string[][]) => pairs.map(([value, label]) => ({ value, label }));
  return ask<Server>({
    title: editing ? `Edit ${ts.name}` : 'Register a tool server',
    text: editing
      ? 'Changes are recorded in the evidence ledger. A new upstream URL takes effect when the gateway reloads its generated configuration.'
      : 'Published on the gateway, the server is at /mcp/<name>, where agents whose grants cover it call its tools. Listed for developers, it is in the MCP registry their MCP clients read.',
    iconName: editing ? 'edit' : 'toolservers',
    confirm: editing ? 'Save changes' : 'Register server',
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, value: ts?.name || '', placeholder: 'crm', hint: `${NAME_HINT} It becomes the gateway path /mcp/<name>.` },
      { id: 'url', label: 'Upstream URL', mono: true, value: ts?.url || '', placeholder: 'http://crm-mcp:8000/mcp', hint: 'The streamable HTTP MCP endpoint, required on the gateway: agents reach it through the gateway, never directly. For a server outside the gateway, where agents reach it.' },
      { id: 'description', label: 'Description', type: 'textarea', value: ts?.description || '' },
      { id: 'owner', label: 'Owner', value: ts?.owner || '', placeholder: 'Team or person' },
      {
        type: 'row',
        fields: [
          { id: 'trust_level', label: 'Trust level', type: 'select', value: ts?.trust_level || 'unverified', options: options(TRUST_LEVELS) },
          { id: 'data_classification', label: 'Data classification', type: 'select', value: ts?.data_classification || 'internal', options: options(CLASSIFICATIONS) },
        ],
      },
      { id: 'labels', label: 'Labels', value: formatLabels(ts?.labels), placeholder: 'team=cx', mono: true },
      { type: 'section', label: 'Who uses it' },
      { id: 'gateway', label: 'Agents, through the gateway', type: 'checkbox', value: ts ? ts.gateway : true, hint: 'Published at /mcp/<name>, with every control.' },
      { id: 'developers', label: 'Developers, in the MCP registry', type: 'checkbox', value: Boolean(ts?.developers), hint: 'Listed in the registry GitHub Copilot and VS Code read (Developer tools).' },
      { id: 'packages', label: 'Packages developers run', type: 'code', rows: 2, value: formatPackages(ts?.packages), placeholder: 'npm:@playwright/mcp@0.0.41', hint: 'For a server developers run on their machines: one per line, type:identifier@version (npm, pypi, oci, nuget, cargo, mcpb).' },
      { id: 'registry_name', label: 'Name in the registry', mono: true, value: ts?.registry_name || '', placeholder: 'com.contoso/crm', hint: 'By default <namespace>/<name>.' },
      { type: 'section', label: 'Outside the gateway' },
      {
        id: 'authorization_server', label: 'Its authorization server', mono: true, value: ts?.authorization_server || '', placeholder: 'https://id.wiki.example.com/realms/wiki',
        hint: 'For a server outside the gateway that takes access tokens from an authorization server of its own: its issuer. Agents get identity assertions (ID-JAG) for it from AgentGov, as their grants allow, while Identity assertions is on, and trade them there for access tokens.',
      },
      { id: 'oauth_client_id', label: "AgentGov's agents' client there", mono: true, value: ts?.oauth_client_id || '', placeholder: 'agentgov-agents', hint: "The client ID agents have at that authorization server. Empty: each agent's own client ID." },
    ],
    submit: (v) => {
      const body = {
        url: v.url, description: v.description, owner: orNull(v.owner),
        trust_level: v.trust_level, data_classification: v.data_classification, labels: parseLabels(v.labels),
        gateway: v.gateway, developers: v.developers, packages: parsePackages(v.packages), registry_name: orNull(v.registry_name),
        authorization_server: orNull(v.authorization_server), oauth_client_id: orNull(v.oauth_client_id),
      };
      if (editing) return api(`v1/toolservers/${encodeURIComponent(ts.name)}`, { method: 'PATCH', body, ifMatch: ts.version });
      return api('v1/toolservers', { method: 'POST', body: { name: v.name, ...body } });
    },
  });
}

async function registerToolserver() {
  const created = await toolserverForm(null);
  if (!created) return;
  let said = `Registered ${created.name} for developers.`;
  if (created.gateway) said = `Registered ${created.name}. Agents reach it at ${created.gateway_url || `/mcp/${created.name}`}.`;
  else if (created.authorization_server) said = `Registered ${created.name}. Agents get identity assertions for it from AgentGov.`;
  toast(said);
  await refresh();
}

async function editToolserver(ts: Server) {
  const saved = await toolserverForm(ts);
  if (!saved) return;
  toast(`Saved ${saved.name}.`);
  await refresh();
}

async function deleteToolserver(ts: Server) {
  const done = await ask({
    title: `Delete ${ts.name}?`,
    text: 'The gateway stops publishing the server and its tool catalog is discarded. Grants that name it stay in blueprints and agents but match nothing. To stop calls but keep the catalog, block the server instead.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete server', busy: 'Deleting…',
    fields: [{ id: 'confirm_name', label: `Type ${ts.name} to confirm`, required: true, mono: true, match: ts.name, mismatch: `Type ${ts.name} exactly to confirm.` }],
    submit: () => api(`v1/toolservers/${encodeURIComponent(ts.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted ${ts.name}.`);
  await refresh();
}

function ServerCard({ ts }: { ts: Server }) {
  const tools: Tool[] = ts.tools || [];
  const poisoned = tools.filter((t) => t.poisoned);
  const changed = tools.filter(isChanged);
  if (!openCatalogs.has(`init:${ts.name}`)) {
    openCatalogs.add(`init:${ts.name}`);
    if (poisoned.length || changed.length) openCatalogs.add(ts.name);
  }
  const [open, setOpen] = useState(() => openCatalogs.has(ts.name));
  const headingId = `server${useId().replace(/:/g, '')}`;
  const catalogId = `catalog-${ts.id}`;
  const toggle = () => {
    if (open) openCatalogs.delete(ts.name);
    else openCatalogs.add(ts.name);
    setOpen(!open);
  };
  const block = <button key="block" type="button" className="btn btn--danger-quiet" onClick={() => serverAction(ts, 'block')}><Icon name="power" />Block server</button>;
  const unblock = <button key="unblock" type="button" className="btn btn--primary" onClick={() => serverAction(ts, 'unblock')}><Icon name="undo" />Unblock</button>;
  const actions = [];
  if (!can('admin') && can('contain') && ts.status !== 'pending') actions.push(ts.status === 'blocked' ? unblock : block);
  if (can('admin')) {
    if (ts.status === 'pending') actions.push(<button key="approve" type="button" className="btn btn--primary" onClick={() => serverAction(ts, 'approve')}><Icon name="check" />Approve</button>);
    actions.push(<button key="edit" type="button" className="btn" onClick={guarded(() => editToolserver(ts))}><Icon name="edit" />Edit</button>);
    actions.push(ts.status === 'blocked' ? unblock : block);
    actions.push(<button key="delete" type="button" className="btn btn--danger-quiet" onClick={() => deleteToolserver(ts)}><Icon name="trash" />Delete</button>);
  }
  const trustChip = ts.trust_level === 'verified'
    ? <PlainChip text="Verified" tone="good" iconName="shield-check" />
    : <PlainChip text={humanize(ts.trust_level || 'unverified')} tone="warning" iconName="shield" />;
  return (
    <section className="card" aria-labelledby={headingId}>
      <div className="card-body">
        <div className="server-head">
          <div className="server-title">
            <div className="title-row">
              <h2 id={headingId} className="tool-name">{ts.name}</h2>
              <Chip kind="server" value={ts.status} />
              {trustChip}
              <PlainChip text={humanize(ts.data_classification || 'unclassified')} iconName="lock" title="Data classification" />
              {ts.developers ? <PlainChip text={ts.gateway ? 'Listed for developers' : 'Developers only'} iconName="developers" title="In the MCP registry developers' MCP clients read" /> : null}
              {ts.authorization_server ? <PlainChip text="Identity assertions" iconName="key" title="Agents reach it outside the gateway, with identity assertions (ID-JAG) AgentGov gives them" /> : null}
            </div>
            {ts.description ? <p style={{ color: 'var(--ink-2)' }}>{ts.description}</p> : null}
          </div>
          <div className="btn-row">{actions}</div>
        </div>
        {poisoned.length ? (
          <Callout tone="critical" icon="octagon">
            <span><strong>{`${plural(poisoned.length, 'tool')} quarantined. `}</strong>Hidden instructions were found in the description, so the tool is hidden from agents and calls to it are denied. Block the server if the definition is malicious.</span>
          </Callout>
        ) : null}
        {changed.length ? (
          <Callout tone="warning" icon="triangle">
            <span><strong>{`${plural(changed.length, 'tool')} changed since approval. `}</strong>Calls are refused until an administrator approves the new definition.</span>
          </Callout>
        ) : null}
        <Facts rows={[
          ts.gateway
            ? ['Gateway URL', ts.gateway_url ? <Copyable text={ts.gateway_url} label="gateway URL" /> : <span className="muted">Gateway public URL not configured</span>]
            : ['Gateway', <span className="muted">{ts.authorization_server ? 'Not published: agents reach it directly' : 'Not published: only for developers'}</span>],
          ts.authorization_server ? ['Authorization server', <code className="break">{ts.authorization_server}</code>] : null,
          ts.authorization_server ? ["Agents' client there", ts.oauth_client_id ? <code>{ts.oauth_client_id}</code> : <span className="muted">Each agent&apos;s own client ID</span>] : null,
          ['Upstream', ts.url ? <code className="break">{ts.url}</code> : null],
          (ts.packages || []).length ? ['Packages', <div className="chip-row">{ts.packages.map((pk: any, i: number) => <PlainChip key={i} text={formatPackages([pk])} mono />)}</div>] : null,
          ['Owner', ts.owner],
          ts.gateway ? ['Catalog', `${plural(tools.length, 'tool')} · ${fmt(poisoned.length)} poisoned · ${fmt(changed.length)} changed`] : null,
          ts.gateway ? ['Catalog synced', <TimeEl iso={ts.tools_synced_at} empty="Not yet observed" />] : null,
        ]} />
        {ts.gateway ? (
          <div>
            <button type="button" className="btn btn--sm" aria-expanded={open} aria-controls={catalogId} onClick={toggle}>
              <Icon name="chevron" />{`${open ? 'Hide' : 'Show'} tool catalog (${tools.length})`}
            </button>
          </div>
        ) : null}
      </div>
      {ts.gateway ? <div id={catalogId} hidden={!open}><ToolTable ts={ts} /></div> : null}
    </section>
  );
}

function ToolTable({ ts }: { ts: Server }) {
  const tools: Tool[] = ts.tools || [];
  if (!tools.length) {
    return (
      <div style={{ borderTop: '1px solid var(--line)' }}>
        <EmptyState title="No tools observed yet" text="The catalog fills in when an agent lists this server's tools through the gateway." />
      </div>
    );
  }
  return (
    <div className="table-wrap" style={{ borderTop: '1px solid var(--line)' }}>
      <table className="data rtable">
        <caption className="sr-only">{`Tool catalog for ${ts.name}`}</caption>
        <thead>
          <tr>{['Tool', 'Description', 'Annotations', 'Status', ''].map((t, i) => <th key={i} scope="col">{t || <span className="sr-only">Actions</span>}</th>)}</tr>
        </thead>
        <tbody>
          {tools.map((t) => {
            const changed = isChanged(t);
            const ann = Object.entries(t.annotations || {}).filter(([, v]) => v === true);
            let status;
            if (t.poisoned) {
              status = (
                <div className="stack" style={{ gap: 6 }}>
                  <span className="chip" data-tone="critical" title="Possible tool poisoning"><Icon name="octagon" />Poisoned</span>
                  <div className="chip-row">{(t.poisoning_reasons || []).map((r: string) => <PlainChip key={r} text={humanize(r)} />)}</div>
                </div>
              );
            } else if (changed) {
              status = (
                <div className="stack" style={{ gap: 4 }}>
                  <PlainChip text="Changed since approval" tone="warning" iconName="triangle" />
                  {t.changed_at ? <span className="xsmall muted">changed <TimeEl iso={t.changed_at} /></span> : null}
                </div>
              );
            } else {
              status = <PlainChip text="Matches approval" tone="good" iconName="check-circle" />;
            }
            const description = t.poisoned ? (
              <div className="quarantine">
                <span className="quarantine-label"><Icon name="octagon" />Hidden instructions found. Shown as plain text.</span>
                <pre>{t.description || ''}</pre>
              </div>
            ) : (
              <p className="tool-desc small">{t.description || <span className="muted">No description</span>}</p>
            );
            return (
              <tr key={t.name}>
                <td data-label="Tool">
                  <div className="tool-name">{t.name}</div>
                  <div className="fp" title={`Fingerprint ${t.fingerprint || ''}`}>{shortHash(t.fingerprint, 8, 4)}</div>
                </td>
                <td data-label="Description" style={{ maxWidth: 420 }}>{description}</td>
                <td data-label="Annotations">
                  {ann.length ? (
                    <div className="chip-row">
                      {ann.map(([k]) => {
                        const [label, tone] = ANNOTATION_LABELS[k] || [humanize(k.replace(/Hint$/, '')), null];
                        return <PlainChip key={k} text={label} tone={tone} iconName={tone ? 'triangle' : undefined} title={k} />;
                      })}
                    </div>
                  ) : <span className="muted small">None</span>}
                </td>
                <td data-label="Status">{status}</td>
                <td data-label="">
                  {changed && can('admin') ? (
                    <button type="button" className="btn btn--sm" onClick={() => approveTool(ts, t)}><Icon name="shield-check" />Approve new definition</button>
                  ) : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** Approve, block or unblock a tool server, after asking. */
export async function serverAction(ts: Server, action: 'approve' | 'block' | 'unblock'): Promise<void> {
  const specs = {
    approve: { title: `Approve ${ts.name}?`, text: 'Agents whose grants cover this server can call its tools through the gateway.', confirm: 'Approve server', tone: 'primary', icon: 'check', done: `Approved ${ts.name}.` },
    block: { title: `Block ${ts.name}?`, text: "Every agent's calls to this server are refused once OPA loads the updated bundle. Its catalog is kept, and you can unblock it later.", confirm: 'Block server', tone: 'danger', icon: 'power', done: `Blocked ${ts.name}. Calls to it are refused.` },
    unblock: { title: `Unblock ${ts.name}?`, text: ts.blocked_from === 'pending' ? 'It goes back to waiting for an administrator’s approval, as it was when it was blocked.' : 'Calls to this server will be evaluated against policy again.', confirm: 'Unblock server', tone: 'primary', icon: 'undo', done: `Unblocked ${ts.name}.` },
  } as const;
  const spec = specs[action];
  const ok = await ask({ title: spec.title, text: spec.text, confirm: spec.confirm, tone: spec.tone, iconName: spec.icon });
  if (!ok) return;
  try {
    await api(`v1/toolservers/${encodeURIComponent(ts.name)}/${action}`, { method: 'POST' });
    toast(spec.done);
    await refresh();
  } catch (err: any) {
    toast(err.message, { tone: 'critical' });
  }
}

async function approveTool(ts: Server, t: Tool) {
  const ok = await ask({
    title: `Approve the new definition of ${t.name}?`,
    text: `Calls to ${ts.name}/${t.name} are refused until you accept its current definition. Read the description and annotations first: a changed definition is how an MCP "rug pull" starts.`,
    iconName: 'shield-check',
    confirm: 'Approve definition',
    extra: <Facts rows={[
      ['Approved', <code className="break">{t.approved_fingerprint || '—'}</code>],
      ['Current', <code className="break">{t.fingerprint || '—'}</code>],
    ]} />,
  });
  if (!ok) return;
  try {
    await api(`v1/toolservers/${encodeURIComponent(ts.name)}/tools/${encodeURIComponent(t.name)}/approve`, { method: 'POST' });
    toast(`Approved the current definition of ${ts.name}/${t.name}.`);
    await refresh();
  } catch (err: any) {
    toast(err.message, { tone: 'critical' });
  }
}
