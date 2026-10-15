// The evidence ledger: every lifecycle change, admin action and policy decision, each entry's
// hash covering the one before it.

import { Fragment, useState, type ReactNode } from 'react';
import { ask } from '../components/dialog';
import { useSynced } from '../components/hooks';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import { AgentLink, Callout, Chip, EmptyState, Facts, JsonBlock, PageHead, TimeEl } from '../components/ui';
import { api, saveDownload } from '../lib/api';
import { cap, clockFmt, fileStamp, fmt, fmtBytes, fullFmt, humanize, plural, shortDayFmt, shortHash } from '../lib/format';
import { refresh, setHashQuiet, type PageDef } from '../lib/router';
import { can, isPerson, isScoped } from '../lib/session';
import { CheckpointsCard } from './compliance';

type Entry = any;

export const LEDGER_TYPES = [
  ['', 'All events'], ['decision.*', 'Policy decisions'], ['approval.*', 'Approvals'], ['agent.*', 'Agent lifecycle'],
  ['toolserver.*', 'Tool servers'], ['policy.*', 'Organisation policies'], ['blueprint.*', 'Blueprints'], ['apikey.*', 'API keys'],
  ['admin.*', 'Sign-ins and sessions'], ['platform.*', 'Platform syncs and imports'], ['connector.*', 'Connector allowlist'],
  ['feature.*', 'Features'], ['model_provider.*', 'Model providers'], ['model.*', 'Model budgets'],
  ['mcp.*', "Developers' MCP servers"], ['identity_issuer.*', 'Identity issuers'],
];
const LEDGER_DECISIONS = [
  ['', 'Any decision'], ['allow', 'Allowed'], ['deny', 'Denied'], ['require_approval', 'Needs approval'],
  ['monitored', 'Monitored: would have been stopped'],
];
const PAGE_SIZE = 100;

// The trace viewer (Langfuse, Jaeger, ...) is another app: open it in a new tab.
export function TraceLink({ e }: { e: Entry }) {
  return (
    <a className="trace-link" href={e.trace_url} target="_blank" rel="noopener noreferrer" title={`Trace ${e.trace_id}`}>
      Open trace<Icon name="external" /><span className="sr-only"> (opens in a new tab)</span>
    </a>
  );
}

// Who handed the work down, from the person at its head to the agent called.
export function ChainView({ chain }: { chain: any[] }) {
  return (
    <span className="break">
      {chain.map((link, i) => (
        <Fragment key={i}>
          {i ? <><span className="muted" aria-hidden="true"> › </span><span className="sr-only">, then </span></> : null}
          {link.type === 'person' ? <PersonLink name={link.name} />
            : String(link.id || '').startsWith('agt_') && !isPerson() ? <AgentLink id={link.id} name={link.name} /> : link.name}
        </Fragment>
      ))}
    </span>
  );
}

function LedgerDetail({ e }: { e: Entry }) {
  const chain = e.details?.chain || [];
  return (
    <div className="stack" style={{ gap: 10, padding: '4px 0 6px' }}>
      <Facts rows={[
        ['Event ID', <code>{e.id}</code>],
        ['Time', <TimeEl iso={e.ts} absolute />],
        ['Severity', humanize(e.severity)],
        ['Action', e.action ? <code>{e.action}</code> : null],
        e.on_behalf_of ? ['On behalf of', <PersonLink name={e.on_behalf_of} />] : null,
        chain.length ? ['Chain', <ChainView chain={chain} />] : null,
        e.trace_id ? ['Trace', <span><code>{e.trace_id}</code>{e.trace_url ? <>{' '}<TraceLink e={e} /></> : null}</span>] : null,
        ['Hash', <code className="hash break">{e.hash}</code>],
        ['Previous hash', <code className="hash break">{e.prev_hash}</code>],
      ]} />
      <ChangesTable changes={e.details?.changes} />
      {Object.keys(e.details || {}).length ? <JsonBlock value={e.details} /> : null}
    </div>
  );
}

// What an edit changed, from what to what (long text by its length and SHA-256).
function ChangedValue({ value }: { value: any }) {
  if (value === null || value === undefined || value === '') return <span className="muted">—</span>;
  if (typeof value === 'object' && value.sha256 && value.length) {
    return <span className="muted" title={`SHA-256 ${value.sha256}`}>{`${fmt(value.length)} characters (${value.sha256.slice(0, 12)}…)`}</span>;
  }
  return <code className="break">{typeof value === 'string' ? value : JSON.stringify(value)}</code>;
}

function ChangesTable({ changes }: { changes?: Record<string, { from: unknown; to: unknown }> }) {
  const rows = Object.entries(changes || {});
  if (!rows.length) return null;
  return (
    <div className="table-wrap">
      <table className="data rtable">
        <caption className="sr-only">What changed</caption>
        <thead><tr>{['Changed', 'From', 'To'].map((t) => <th key={t} scope="col">{t}</th>)}</tr></thead>
        <tbody>
          {rows.map(([field, { from, to }]) => (
            <tr key={field}>
              <td data-label="Changed">{humanize(field)}</td>
              <td data-label="From"><ChangedValue value={from} /></td>
              <td data-label="To"><ChangedValue value={to} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// What agents did for a person: the ledger, filtered to them.
export function PersonLink({ name }: { name: string }) {
  return <a href={`#/ledger?${new URLSearchParams({ user: name })}`} title={`What agents did for ${name}`}>{name}</a>;
}

function LedgerTime({ iso }: { iso: string }) {
  const date = new Date(iso);
  return (
    <time dateTime={iso} title={fullFmt.format(date)}>
      <span className="num">{clockFmt.format(date)}</span><span className="cell-sub">{shortDayFmt.format(date)}</span>
    </time>
  );
}

function LedgerRow({ e, compact }: { e: Entry; compact: boolean }) {
  const [open, setOpen] = useState(false);
  const cols = compact ? 4 : 6;
  const detailId = `ledger-detail-${e.seq}`;
  const dash = <span className="muted">—</span>;
  // The actor is only worth showing when it is not the agent itself (an admin, the system, a service).
  const actorIsAgent = e.agent_name && e.actor === `agent:${e.agent_name}`;
  return (
    <>
      <tr className={open ? 'is-open' : undefined}>
        <td data-label="Seq" className="nowrap">
          <button type="button" className="expander" aria-expanded={open} aria-controls={detailId} onClick={() => setOpen(!open)}>
            <Icon name="chevron" />{`#${e.seq}`}<span className="sr-only"> details</span>
          </button>
        </td>
        <td data-label="Time" className="nowrap"><LedgerTime iso={e.ts} /></td>
        <td data-label="Event" className="break">
          <span className="ledger-type">{e.severity === 'warning' ? <span className="sev-dot" title="Warning" /> : null}{e.type}</span>
          {e.resource ? <div className="cell-sub"><code>{e.resource}</code>{e.trace_url ? <>{' · '}<TraceLink e={e} /></> : null}</div> : null}
          {compact && e.reason ? <div className="cell-sub clamp-2" title={e.reason}>{e.reason}</div> : null}
        </td>
        {compact ? null : (
          <td data-label="Agent" className="break col-agent">
            {e.agent_name ? <AgentLink id={e.agent_id} name={e.agent_name} /> : null}
            {actorIsAgent ? null : <div className={e.agent_name ? 'cell-sub nowrap' : undefined}>{e.agent_name ? `by ${e.actor}` : e.actor}</div>}
            {e.on_behalf_of ? <div className="cell-sub nowrap">for <PersonLink name={e.on_behalf_of} /></div> : null}
          </td>
        )}
        <td data-label="Decision" className={e.decision ? undefined : 'is-empty'}>{e.decision ? <Chip kind="decision" value={e.decision} /> : dash}</td>
        {compact ? null : (
          <td data-label="Reason" className={e.reason ? 'break' : 'is-empty'}>
            {e.reason ? <span className="clamp-2" title={e.reason}>{e.reason}</span> : dash}
          </td>
        )}
      </tr>
      <tr className="row-detail" id={detailId} hidden={!open}>
        <td colSpan={cols} data-label=""><LedgerDetail e={e} /></td>
      </tr>
    </>
  );
}

/** Ledger entries, newest first; each opens to its details. Compact: without the agent and reason columns. */
export function LedgerTable({ entries, compact = false }: { entries: Entry[]; compact?: boolean }) {
  const heads = compact
    ? ['Seq', 'Time', 'Event', 'Decision']
    : ['Seq', 'Time', 'Event and resource', 'Agent / actor', 'Decision', 'Reason'];
  return (
    <div className="table-wrap">
      <table className="data rtable">
        <thead><tr>{heads.map((t) => <th key={t} scope="col">{t}</th>)}</tr></thead>
        <tbody>{entries.map((e) => <LedgerRow key={e.seq} e={e} compact={compact} />)}</tbody>
      </table>
    </div>
  );
}

export function LedgerTabs({ current }: { current: 'entries' | 'compliance' | 'register' }) {
  const tab = (key: string, href: string, label: string) => (
    <a className="tab" href={href} aria-current={current === key ? 'page' : undefined}>{label}</a>
  );
  return (
    <nav className="tabs" aria-label="Ledger views">
      {tab('entries', '#/ledger', 'Entries')}
      {tab('compliance', '#/ledger/compliance', 'Compliance')}
      {tab('register', '#/ledger/register', 'Register')}
    </nav>
  );
}

// The database lost ledger entries AgentGov wrote (a restore): what, and accepting it.
function RewoundCallout({ witness }: { witness: any }) {
  if (!witness?.rewound) return null;
  const accept = guarded(async () => {
    const done = await ask({
      title: 'Accept the restore?',
      text: 'AgentGov writes into the ledger which entries are missing and when they were written, then goes on from the entries the database has. Do it once you know why they are missing: a backup you restored on purpose, say.',
      tone: 'danger', iconName: 'shield-check', confirm: 'Accept and record it',
      submit: () => api('v1/ledger/witness/accept', { method: 'POST' }),
    });
    if (!done) return;
    toast('Recorded in the ledger: entry ledger.rewound.');
    await refresh();
  });
  return (
    <Callout tone="critical" icon="octagon">
      <div className="stack">
        <span>
          <strong>{witness.state === 'behind' ? 'Entries are missing. ' : 'Another history. '}</strong>
          {witness.message}{' The chain still verifies: only the head kept outside the database tells.'}
        </span>
        <span className="small">{`The head is kept in ${witness.file} (docs/backup.md).`}</span>
        {can('admin') ? (
          <div className="btn-row">
            <button type="button" className="btn btn--sm btn--primary" onClick={accept}><Icon name="shield-check" />Accept the restore</button>
          </div>
        ) : null}
      </div>
    </Callout>
  );
}

interface Filters { agent: string; user: string; type: string; decision: string }

function query(filters: Filters, before?: number): Promise<Entry[]> {
  const p = new URLSearchParams({ limit: String(PAGE_SIZE) });
  if (filters.agent) p.set('agent', filters.agent);
  if (filters.user) p.set('user', filters.user);
  if (filters.type) p.set('type', filters.type);
  if (filters.decision) p.set('decision', filters.decision);
  if (before) p.set('before_seq', String(before));
  return api(`v1/ledger?${p}`);
}

interface LedgerData {
  filters: Filters;
  agents: any[];
  entries: Entry[];
  error: any;
  kept: any;
  points: any[] | null;
  witness: any;
}

export const ledgerPage: PageDef<LedgerData> = {
  re: /^\/ledger$/,
  nav: 'ledger',
  title: 'Ledger',
  load: async ({ params }) => {
    const filters = { agent: params.get('agent') || '', user: params.get('user') || '', type: params.get('type') || '', decision: params.get('decision') || '' };
    const agents = await api('v1/agents?include_deleted=true').catch(() => []);
    let entries: Entry[] = [];
    let error = null;
    try {
      entries = await query(filters);
    } catch (err: any) {
      if (err.status === 401) throw err;
      error = err;
    }
    // The whole chain is the organisation's: those with roles for some teams only read their
    // agents' entries.
    const [kept, points, witness] = isScoped() ? [null, null, null] : await Promise.all([
      api('v1/ledger/retention').catch(() => null), api('v1/ledger/checkpoints?limit=10').catch(() => null),
      api('v1/ledger/witness').catch(() => null),
    ]);
    return { filters, agents, entries, error, kept, points, witness };
  },
  View: LedgerView,
};

function LedgerView({ data }: { data: LedgerData }) {
  const [filters, setFilters] = useSynced(data.filters);
  const [drafts, setDrafts] = useSynced({ agent: data.filters.agent, user: data.filters.user }, data);
  const [list, setList] = useSynced<{ entries: Entry[]; error: any; more: boolean }>(
    { entries: data.entries, error: data.error, more: data.entries.length >= PAGE_SIZE }, data,
  );
  const [banner, setBanner] = useState<ReactNode>(null);
  const [verifying, setVerifying] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const scoped = isScoped();

  const apply = async (next: Filters) => {
    setFilters(next);
    setHashQuiet('/ledger', next as unknown as Record<string, unknown>);
    try {
      const entries = await query(next);
      setList({ entries, error: null, more: entries.length >= PAGE_SIZE });
    } catch (error) {
      setList({ entries: [], error, more: false });
    }
  };
  const commit = (key: 'agent' | 'user') => {
    const value = drafts[key].trim();
    if (value !== filters[key]) void apply({ ...filters, [key]: value });
  };

  const verify = async () => {
    setVerifying(true);
    setBanner(<Callout tone="neutral" icon="clock">Recomputing every hash in the database…</Callout>);
    try {
      const v = await api('v1/ledger/verify');
      const origin = v.from ? `the checkpoint at entry #${fmt(v.from)} (the entries before it are archived)` : 'the genesis entry';
      // What doesn't break the chain but limits what its checkpoints prove.
      const warnings = (v.warnings || []).length
        ? <ul className="small">{v.warnings.map((w: string, i: number) => <li key={i}>{`${cap(w)}.`}</li>)}</ul>
        : null;
      const problems = v.problems || [];
      setBanner(v.valid ? (
        <Callout tone={warnings ? 'warning' : 'good'} icon={warnings ? 'triangle' : 'shield-check'}>
          <div className="stack">
            <span>
              <strong>Chain intact. </strong>
              {`Recomputed ${plural(v.checked - (v.from || 0), 'hash', 'hashes')} from ${origin}; nothing was edited, removed or reordered. Head `}
              <code className="hash" title={v.head}>{shortHash(v.head)}</code>.
            </span>
            {warnings}
          </div>
        </Callout>
      ) : (
        <Callout tone="critical" icon="octagon">
          <div className="stack">
            <span>
              <strong>{v.broken_at ? `Chain broken at entry #${v.broken_at}. ` : 'Chain broken. '}</strong>
              {`${plural(problems.length + (v.more_problems || 0), 'problem')}, each checked whatever broke before it: entries from the first on can't be trusted.`}
            </span>
            <ul className="small">{problems.map((p: any, i: number) => <li key={i}>{p.seq ? `#${fmt(p.seq)}: ` : ''}{`${cap(p.problem)}.`}</li>)}</ul>
            {v.more_problems ? <p className="small">{`And ${plural(v.more_problems, 'more problem')}.`}</p> : null}
            {warnings}
          </div>
        </Callout>
      ));
    } catch (err: any) {
      setBanner(<Callout tone="critical" icon="alert-circle">{err.message}</Callout>);
    } finally {
      setVerifying(false);
    }
  };

  const exportAll = async () => {
    setExporting(true);
    try {
      const blob = await saveDownload('v1/ledger/export', `agentgov-ledger-${fileStamp()}.jsonl`);
      toast(`Exported the full ledger as JSON Lines (${fmtBytes(blob.size)}).`);
    } catch (err: any) {
      toast(err.message, { tone: 'critical' });
    } finally {
      setExporting(false);
    }
  };

  const loadMore = async () => {
    setLoadingMore(true);
    try {
      const older = await query(filters, list.entries[list.entries.length - 1].seq);
      setList({ entries: list.entries.concat(older), error: null, more: older.length >= PAGE_SIZE });
    } catch (err: any) {
      toast(err.message, { tone: 'critical' });
    } finally {
      setLoadingMore(false);
    }
  };

  const { entries, error, more } = list;
  const count = error ? '' : more ? `Latest ${fmt(entries.length)} entries` : plural(entries.length, 'entry', 'entries');
  return (
    <div className="page">
      <PageHead
        title="Ledger"
        sub={scoped
          ? "Tamper-evident record of lifecycle changes, admin actions and policy decisions: here, your teams' agents' entries."
          : "Tamper-evident record of lifecycle changes, admin actions and policy decisions. Each entry's SHA-256 hash covers the previous entry's hash, so any edit breaks the chain."}
        actions={scoped ? [] : [
          <button key="verify" type="button" className="btn btn--primary" disabled={verifying} onClick={verify}><Icon name="shield-check" />Verify chain</button>,
          <button key="export" type="button" className="btn" disabled={exporting} onClick={exportAll}><Icon name="download" />Export JSONL</button>,
        ]}
      />
      {scoped ? null : <LedgerTabs current="entries" />}
      <RewoundCallout witness={data.witness} />
      <div className="verify-banner" aria-live="polite">{banner}</div>
      <div className="filters">
        <div className="field">
          <label htmlFor="ledger-agent">Agent</label>
          <input type="text" id="ledger-agent" list="ledger-agent-list" placeholder="Any agent" autoComplete="off" spellCheck={false}
            value={drafts.agent} onChange={(e) => setDrafts({ ...drafts, agent: e.target.value })}
            onBlur={() => commit('agent')} onKeyDown={(e) => { if (e.key === 'Enter') commit('agent'); }} />
          <datalist id="ledger-agent-list">{data.agents.map((a) => <option key={a.id} value={a.name} />)}</datalist>
        </div>
        <div className="field">
          <label htmlFor="ledger-user">On behalf of</label>
          <input type="text" id="ledger-user" placeholder="Anyone" autoComplete="off" spellCheck={false}
            value={drafts.user} onChange={(e) => setDrafts({ ...drafts, user: e.target.value })}
            onBlur={() => commit('user')} onKeyDown={(e) => { if (e.key === 'Enter') commit('user'); }} />
        </div>
        <div className="field">
          <label htmlFor="ledger-type">Event type</label>
          <select id="ledger-type" value={filters.type} onChange={(e) => void apply({ ...filters, type: e.target.value })}>
            {LEDGER_TYPES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </div>
        <div className="field">
          <label htmlFor="ledger-decision">Decision</label>
          <select id="ledger-decision" value={filters.decision} onChange={(e) => void apply({ ...filters, decision: e.target.value })}>
            {LEDGER_DECISIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </div>
        <div className="field" style={{ flex: '0 0 auto', alignSelf: 'flex-end' }}>
          <button type="button" className="btn btn--ghost" onClick={() => {
            setDrafts({ agent: '', user: '' });
            void apply({ agent: '', user: '', type: '', decision: '' });
          }}>Clear filters</button>
        </div>
        <p className="result-count" aria-live="polite">{count}</p>
      </div>
      <section className="card" aria-label="Ledger entries">
        {error ? (
          <div className="card-body"><Callout tone="critical" icon="alert-circle">{error.message}</Callout></div>
        ) : !entries.length ? (
          <EmptyState title="No entries match these filters" />
        ) : (
          <>
            <LedgerTable entries={entries} />
            {more ? (
              <div className="load-more">
                <button type="button" className="btn btn--sm" disabled={loadingMore} onClick={loadMore}>Load older entries</button>
              </div>
            ) : null}
          </>
        )}
      </section>
      {data.kept && data.points ? <CheckpointsCard kept={data.kept} points={data.points} /> : null}
    </div>
  );
}
