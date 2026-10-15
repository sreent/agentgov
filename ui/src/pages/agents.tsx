// The agents: every agent the control plane knows about, found by name, status, where it
// runs, risk and owner, sorted by a column, and chosen several at once for one action.

import { useEffect, useMemo, useRef, type ReactElement } from 'react';
import { manyDone } from '../components/bulk';
import { ask } from '../components/dialog';
import { useSynced } from '../components/hooks';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import { agentHref, Chip, EmptyState, NameList, PageHead, RefreshButton, RiskChip, TimeEl } from '../components/ui';
import { api, saveCsv, type CsvColumns } from '../lib/api';
import { refreshBadges } from '../lib/badges';
import { countBy, cx, fmt, plural } from '../lib/format';
import { parseList } from '../lib/forms';
import { refresh, setHashQuiet, type PageDef } from '../lib/router';
import { can, canSome } from '../lib/session';
import { inTurns, isPlatformAgent, PLATFORM_SOURCES, platformOf } from '../lib/shared';
import { ACTIONS_BY_STATUS, LIFECYCLE, makerLine, registerAgent } from './agent';
import { classifyAgents } from './register';

type Agent = any;

const AGENT_STATUS_FILTERS: [string, string][] = [
  ['all', 'All'], ['active', 'Active'], ['pending', 'Pending'], ['blocked', 'Blocked'],
  ['discovered', 'Unmanaged'], ['deleted', 'Deleted'],
];

// How the agents table sorts: by a column, or by "-" and a column the other way round.
const AGENT_SORTS: Record<string, (a: Agent) => unknown> = {
  name: (a) => a.name,
  status: (a) => AGENT_STATUS_FILTERS.findIndex(([k]) => k === a.status),
  risk: (a) => a.risk?.score ?? 0,
  owner: (a) => a.owner || '',
  blueprint: (a) => a.blueprint || platformOf(a) || '',
  last_seen: (a) => a.last_seen_at || '',
};
// The columns whose first sort puts the most first: the riskiest, the most recently seen.
const SORTS_DOWN = new Set(['risk', 'last_seen']);
const RISK_FILTERS: [string, string][] = [['', 'Any risk'], ['elevated', 'High or critical'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']];
const WHERE_WORDS: Record<string, string> = { registered: 'Registered in AgentGov', discovered: 'Seen at runtime' };

// Rows in the order a sort names, those without a value last either way; ties by name.
function sortRows<T extends { name?: unknown }>(rows: T[], sort: string, keys: Record<string, (row: T) => unknown>): T[] {
  const down = sort.startsWith('-');
  const get = keys[sort.replace(/^-/, '')] || keys.name;
  const blank = (v: unknown) => v === '' || v == null;
  return [...rows].sort((x, y) => {
    const a = get(x);
    const b = get(y);
    if (blank(a) !== blank(b)) return blank(a) ? 1 : -1;
    const c = typeof a === 'number' && typeof b === 'number' ? a - b
      : String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
    return (down ? -c : c) || String(x.name).localeCompare(String(y.name));
  });
}

// The next sort when a column's header is pressed: the other way round if it sorts by it.
function nextSort(sort: string, key: string): string {
  if (sort === key) return `-${key}`;
  if (sort === `-${key}`) return key;
  return SORTS_DOWN.has(key) ? `-${key}` : key;
}

// Where an agent is, for the filter: on a platform, registered here, or discovered at runtime.
function agentWhere(a: Agent): string {
  const source: string = a.source || 'registered';
  return source.startsWith('discovered:') ? 'discovered' : source;
}

const AGENT_CSV: CsvColumns<Agent> = [
  ['Name', (a) => a.name],
  ['Status', (a) => a.status],
  ['Risk', (a) => a.risk?.level],
  ['Risk score', (a) => a.risk?.score],
  ['Owner', (a) => a.owner],
  ['Sponsors', (a) => a.sponsors],
  ['Team', (a) => a.team],
  ['Blueprint', (a) => a.blueprint],
  ['Where', (a) => WHERE_WORDS[agentWhere(a)] || PLATFORM_SOURCES[a.source] || a.source],
  ['Environment', (a) => a.environment],
  ['Named by its platform', (a) => a.maker?.email || a.maker?.name || ''],
  ['Registered', (a) => a.created_at],
  ['Last seen', (a) => a.last_seen_at],
  ['Description', (a) => a.description],
  ['ID', (a) => a.id],
];

interface Filters { status: string; owner: string; risk: string; source: string; q: string; sort: string }
interface AgentsData { state: Filters; agents: Agent[] }

const loadAgents = (q: string): Promise<Agent[]> => api(`v1/agents?include_deleted=true${q ? `&q=${encodeURIComponent(q)}` : ''}`);

export const agentsPage: PageDef<AgentsData> = {
  re: /^\/agents$/,
  nav: 'agents',
  title: 'Agents',
  load: async ({ params }) => {
    const state = {
      status: params.get('status') || 'all',
      owner: params.get('owner') || '',
      risk: params.get('risk') || '',
      source: params.get('source') || '',
      q: params.get('q') || '',
      sort: params.get('sort') || 'name',
    };
    return { state, agents: await loadAgents(state.q) };
  },
  View: AgentsView,
};

function sync(state: Filters): void {
  setHashQuiet('/agents', {
    status: state.status === 'all' ? '' : state.status, owner: state.owner, risk: state.risk,
    source: state.source, q: state.q, sort: state.sort === 'name' ? '' : state.sort,
  });
}

// A filter's choices; the one chosen stays among them even when nothing matches it now.
function withCurrent(choices: [string, string][], current: string, labelOf = (v: string) => v): [string, string][] {
  return current && !choices.some(([v]) => v === current) ? [...choices, [current, labelOf(current)]] : choices;
}

function FilterField({ id, label, choices, value, onChange }: {
  id: string; label: string; choices: [string, string][]; value: string; onChange: (value: string) => void;
}) {
  return (
    <div className="field" style={{ flex: '0 1 220px' }}>
      <label htmlFor={id} className="sr-only">{label}</label>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        {choices.map(([v, l], i) => <option key={i} value={v}>{l}</option>)}
      </select>
    </div>
  );
}

function AgentsView({ data }: { data: AgentsData }) {
  const [state, setState] = useSynced(data.state);
  const [agents, setAgents] = useSynced(data.agents);
  const [search, setSearch] = useSynced(data.state.q, data);
  // Those chosen for an action on many at once, by ID: only ever among those shown.
  const [selected, setSelected] = useSynced<Set<string>>(new Set(), data);
  // The filters as they are now, for what finishes later (a search, clearing the filters).
  const latest = useRef(state);
  latest.current = state;
  const searchBox = useRef<HTMLInputElement>(null);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const searchSeq = useRef(0);
  // Gone (another page shown): what finishes later changes nothing, the address least of all.
  const shown = useRef(true);
  useEffect(() => {
    shown.current = true;
    return () => {
      shown.current = false;
      clearTimeout(timer.current);
    };
  }, []);
  const selecting = canSome('admin') || canSome('contain') || canSome('approve');

  const view = useMemo(() => {
    const counts = countBy(agents, 'status');
    const live = agents.filter((a) => a.status !== 'deleted').length;
    const inStatus = agents.filter((a) => (state.status === 'all' ? a.status !== 'deleted' : a.status === state.status));
    const whereLabel = (w: string) => WHERE_WORDS[w] || PLATFORM_SOURCES[w] || w;
    const wheres = countBy(inStatus, agentWhere);
    const whereChoices = withCurrent([['', 'Anywhere'], ...Object.keys(wheres).sort((x, y) => whereLabel(x).localeCompare(whereLabel(y)))
      .map((w): [string, string] => [w, `${whereLabel(w)} (${fmt(wheres[w])})`])], state.source, whereLabel);
    const riskChoices = withCurrent(RISK_FILTERS, state.risk);
    const owners = countBy(inStatus.filter((a) => a.owner), 'owner');
    const ownerChoices = withCurrent([['', 'Any owner'], ['none', 'Without an owner'],
      ...Object.keys(owners).sort((x, y) => x.localeCompare(y)).map((o): [string, string] => [o, `${o} (${fmt(owners[o])})`])], state.owner);

    let rows = inStatus;
    if (state.owner === 'none') rows = rows.filter((a) => !a.owner && (a.status !== 'discovered' || isPlatformAgent(a)));
    else if (state.owner) rows = rows.filter((a) => a.owner === state.owner);
    if (state.risk === 'elevated') rows = rows.filter((a) => ['high', 'critical'].includes(a.risk?.level));
    else if (state.risk) rows = rows.filter((a) => (a.risk?.level || 'low') === state.risk);
    if (state.source) rows = rows.filter((a) => agentWhere(a) === state.source);
    rows = sortRows(rows, state.sort, AGENT_SORTS);
    return { counts, live, whereChoices, riskChoices, ownerChoices, rows, ids: new Set<string>(rows.map((a) => a.id)) };
  }, [agents, state]);
  const { rows } = view;

  // Those no longer shown are no longer chosen.
  let chosen = selected;
  if ([...selected].some((id) => !view.ids.has(id))) {
    chosen = new Set([...selected].filter((id) => view.ids.has(id)));
    setSelected(chosen);
  }

  const change = (changes: Partial<Filters>) => {
    const next = { ...state, ...changes };
    setState(next);
    sync(next);
  };
  const onSelect = (ids: string[], on: boolean) => {
    const next = new Set(chosen);
    for (const id of ids) {
      if (on) next.add(id);
      else next.delete(id);
    }
    setSelected(next);
  };

  const onSearch = (text: string) => {
    setSearch(text);
    clearTimeout(timer.current);
    timer.current = setTimeout(async () => {
      const mine = ++searchSeq.current;
      // What the box says now (cleared, say, by Clear filters meanwhile).
      const q = (searchBox.current?.value ?? text).trim();
      try {
        const next = await loadAgents(q);
        if (!shown.current || mine !== searchSeq.current) return;
        const s = { ...latest.current, q };
        setState(s);
        setAgents(next);
        sync(s);
      } catch (err: any) {
        if (shown.current) toast(err.message, { tone: 'critical' });
      }
    }, 250);
  };

  // Every agent shown again; a search not yet run is dropped.
  const clearFilters = guarded(async () => {
    clearTimeout(timer.current);
    const mine = ++searchSeq.current;
    setSearch('');
    const next = await loadAgents('');
    if (!shown.current || mine !== searchSeq.current) return;
    const s = { ...latest.current, status: 'all', owner: '', risk: '', source: '', q: '' };
    setState(s);
    setAgents(next);
    sync(s);
  });

  const adoptable = rows.filter((a) => a.status === 'discovered');
  return (
    <div className="page">
      <PageHead
        title="Agents"
        sub="Every agent the control plane knows about: active, pending approval, blocked, and unmanaged ones nobody has adopted yet, found on your platforms or seen at runtime."
        actions={[
          canSome('admin') ? (
            <button key="register" type="button" className="btn btn--primary" onClick={guarded(registerAgent)}>
              <Icon name="plus" />Register agent
            </button>
          ) : null,
          <RefreshButton key="refresh" />,
        ]}
      />
      <div className="filters">
        <div className="field">
          <label htmlFor="agent-search" className="sr-only">Search agents</label>
          <input ref={searchBox} type="search" id="agent-search" placeholder="Search names and descriptions" autoComplete="off"
            value={search} onChange={(e) => onSearch(e.target.value)} />
        </div>
        <div className="seg" role="group" aria-label="Filter by status">
          {AGENT_STATUS_FILTERS.map(([key, label]) => (
            <button key={key} type="button" className="seg-btn" aria-pressed={state.status === key} onClick={() => change({ status: key })}>
              {label}<span className="count">{fmt(key === 'all' ? view.live : view.counts[key] || 0)}</span>
            </button>
          ))}
        </div>
      </div>
      <div className="filters">
        <FilterField id="agent-where" label="Where it runs" choices={view.whereChoices} value={state.source} onChange={(v) => change({ source: v })} />
        <FilterField id="agent-risk" label="Risk" choices={view.riskChoices} value={state.risk} onChange={(v) => change({ risk: v })} />
        <FilterField id="agent-owner" label="Owner" choices={view.ownerChoices} value={state.owner} onChange={(v) => change({ owner: v })} />
        <p className="result-count" aria-live="polite">{plural(rows.length, 'agent')}</p>
        <div>
          {canSome('admin') && adoptable.length > 1 && !chosen.size ? (
            <button type="button" className="btn btn--sm" onClick={guarded(() => adoptMany(adoptable))}>
              <Icon name="user-check" />{`Adopt ${plural(adoptable.length, 'agent')}…`}
            </button>
          ) : null}
        </div>
        <button type="button" className="btn btn--sm btn--ghost" title="The agents shown, as a spreadsheet" disabled={!rows.length}
          onClick={() => saveCsv('agentgov-agents', AGENT_CSV, rows)}>
          <Icon name="download" />Download CSV
        </button>
      </div>
      <div>
        {selecting && rows.length ? <AgentBulkBar rows={rows} selected={chosen} onSelect={onSelect} clear={() => setSelected(new Set())} /> : null}
      </div>
      <section className="card" aria-label="Agent list">
        <div>
          {rows.length ? (
            <AgentsTable
              rows={rows}
              sort={state.sort}
              onSort={(key) => change({ sort: nextSort(state.sort, key) })}
              selected={selecting ? chosen : null}
              onSelect={onSelect}
            />
          ) : (
            <EmptyState
              title="No agents match these filters"
              text={state.q ? `Nothing matches "${state.q}".` : 'Try another status, or clear the filters.'}
              action={<button type="button" className="btn btn--sm" onClick={clearFilters}>Clear filters</button>}
            />
          )}
        </div>
      </section>
    </div>
  );
}

const AGENTS_AT_ONCE: Record<string, { verb: string; text: string }> = {
  approve: { verb: 'Approved', text: 'Each becomes active and can call the tools its blueprint and grants allow. Each needs a sponsor at least: those without one stay pending.' },
  block: { verb: 'Blocked', text: 'This is the kill switch. The gateway refuses every call from them as soon as OPA loads the updated policy bundle, usually within seconds. You can unblock them later.' },
  unblock: { verb: 'Unblocked', text: 'Each goes back to what it was when it was blocked: active, with its calls evaluated against policy again, waiting for approval, or unmanaged.' },
  delete: { verb: 'Deleted', text: 'They leave the inventory and policy denies all of their calls. Deleted agents can be restored.' },
  restore: { verb: 'Restored', text: 'They come back as pending approval. Approve them to make them active again.' },
};

// The actions on the agents chosen: each offered when it fits some of them, and done to those.
// With none chosen, on a narrow screen (where the table has no header), a box to choose all.
function AgentBulkBar({ rows, selected, onSelect, clear }: {
  rows: Agent[]; selected: Set<string>; onSelect: (ids: string[], on: boolean) => void; clear: () => void;
}) {
  const chosen = rows.filter((a) => selected.has(a.id));
  if (!chosen.length) {
    return (
      <div className="bulk-bar bulk-bar--idle bulk-bar--narrow">
        <label className="check">
          <input type="checkbox" checked={false} onChange={(e) => onSelect(rows.map((a) => a.id), e.target.checked)} />
          {`Choose all ${plural(rows.length, 'agent')} shown`}
        </label>
      </div>
    );
  }
  // Each one by the roles held where it is.
  const fits = (action: string, kind: string) => chosen.filter((a) => (ACTIONS_BY_STATUS[a.status] || []).includes(action) && can(kind, a));
  const buttons: ReactElement[] = [];
  const offer = (action: string, label: string, iconName: string, cls = '', kind = 'admin') => {
    const n = fits(action, kind).length;
    if (!n) return;
    buttons.push(
      <button key={action} type="button" className={`btn btn--sm ${cls}`} onClick={guarded(() => agentsAtOnce(chosen, action))}>
        <Icon name={iconName} />{n === chosen.length ? label : `${label} ${fmt(n)}`}
      </button>,
    );
  };
  offer('approve', 'Approve', 'check', 'btn--primary');
  offer('adopt', 'Adopt', 'user-check');
  if (chosen.some((a) => a.status !== 'deleted' && can('admin', a))) {
    buttons.push(
      <button key="edit" type="button" className="btn btn--sm" onClick={guarded(() => agentsAtOnce(chosen, 'edit'))}>
        <Icon name="edit" />Edit…
      </button>,
    );
  }
  if (chosen.some((a) => a.status !== 'deleted' && can('approve', a))) {
    buttons.push(
      <button key="classify" type="button" className="btn btn--sm" onClick={guarded(() => agentsAtOnce(chosen, 'classify'))}>
        <Icon name="shield-check" />Classify…
      </button>,
    );
  }
  offer('block', 'Block', 'power', 'btn--danger', 'contain');
  offer('unblock', 'Unblock', 'undo', '', 'contain');
  offer('delete', 'Delete', 'trash', 'btn--danger-quiet');
  offer('restore', 'Restore', 'undo');
  return (
    <div className="bulk-bar" role="region" aria-label="Chosen agents">
      <strong className="bulk-count" aria-live="polite">{`${plural(chosen.length, 'agent')} chosen`}</strong>
      <div className="btn-row">{buttons}</div>
      <button type="button" className="btn btn--sm btn--ghost" onClick={clear}><Icon name="x" />Clear</button>
    </div>
  );
}

async function agentsAtOnce(chosen: Agent[], action: string): Promise<void> {
  const fits = chosen.filter((a) => (ACTIONS_BY_STATUS[a.status] || []).includes(action));
  if (action === 'adopt') return adoptMany(fits);
  if (action === 'edit') return editMany(chosen.filter((a) => a.status !== 'deleted'));
  if (action === 'classify') {
    if (await classifyAgents(chosen.filter((a) => a.status !== 'deleted'))) await refresh();
    return undefined;
  }
  const spec = LIFECYCLE[action];
  const verb = spec.label.replace(' (kill switch)', '');
  let text = AGENTS_AT_ONCE[action].text;
  const elsewhere = [...new Set(fits.map(platformOf).filter(Boolean))];
  const onPlatforms = fits.filter(platformOf).length;
  if (onPlatforms && ['block', 'unblock', 'delete'].includes(action)) {
    text += ` ${onPlatforms === fits.length ? 'They run' : `${fmt(onPlatforms)} of them run`} on ${elsewhere.join(', ')}: this changes AgentGov's registry, not ${elsewhere.length > 1 ? 'those platforms' : elsewhere[0]}.`;
    if (action === 'block') text += ' For each one its platform still runs, an issue asks its people to stop it there.';
  }
  if (fits.length < chosen.length) {
    text += ` ${plural(chosen.length - fits.length, 'other agent')} chosen ${chosen.length - fits.length === 1 ? 'isn\'t' : 'aren\'t'} in a state for it, and ${chosen.length - fits.length === 1 ? 'stays as it is' : 'stay as they are'}.`;
  }
  const result = await ask({
    title: `${verb} ${plural(fits.length, 'agent')}?`,
    text, tone: spec.tone, iconName: spec.icon, confirm: `${verb} ${plural(fits.length, 'agent')}`, busy: 'Working…',
    extra: <NameList names={fits.map((a) => a.name)} />,
    fields: [{ id: 'reason', label: 'Reason', type: 'textarea', hint: 'Recorded in the evidence ledger, for each of them.' }],
    submit: (v) => inTurns('v1/agents/bulk', { action, agents: fits.map((a) => a.id), ...(v.reason ? { reason: v.reason } : {}) }, 'agents'),
  });
  if (!result) return;
  await manyDone(result, AGENTS_AT_ONCE[action].verb, 'agent');
  void refreshBadges();
  await refresh();
}

// Change several agents' owner, team, sponsors or blueprint at once: only what is filled in.
async function editMany(chosen: Agent[]): Promise<void> {
  const [teamList, blueprints] = await Promise.all([api<any[]>('v1/teams').catch(() => []), api<any[]>('v1/blueprints').catch(() => [])]);
  const KEEP = '__keep';
  const result = await ask({
    title: `Edit ${plural(chosen.length, 'agent')}`,
    text: 'Only what you fill in changes: the rest of each agent stays as it is.',
    iconName: 'edit', confirm: 'Save', busy: 'Saving…', wide: true,
    extra: <NameList names={chosen.map((a) => a.name)} />,
    fields: [
      { id: 'owner', label: 'Owner', placeholder: 'A team or a person', hint: 'Accountable for each of them.' },
      {
        id: 'team', label: 'Team', type: 'select', value: KEEP, options: [
          { value: KEEP, label: 'Leave each one\'s as it is' }, { value: '', label: 'None: their blueprint\'s' },
          ...teamList.map((t) => ({ value: t.name, label: t.name }))],
      },
      {
        type: 'row', fields: [
          { id: 'add', label: 'Add sponsors', placeholder: 'dana@example.com', hint: 'Separate people with commas.' },
          { id: 'remove', label: 'Remove sponsors', placeholder: 'alice@example.com', hint: 'Someone who left, say.' },
        ],
      },
      {
        id: 'blueprint', label: 'Blueprint', type: 'select', value: KEEP, options: [
          { value: KEEP, label: 'Leave each one\'s as it is' }, { value: '', label: 'No blueprint' },
          ...blueprints.map((b) => ({ value: b.name, label: `${b.name} (${b.risk_tier} risk tier)` }))],
      },
      { id: 'reason', label: 'Reason', type: 'textarea', hint: 'Recorded in the evidence ledger, for each of them.' },
    ],
    // Async: the dialog disables Save only while it waits for submit, so that refusing at once
    // (nothing filled in) takes the focus off Save, as it always did.
    submit: async (v) => {
      const fields: Record<string, unknown> = {};
      if (v.owner) fields.owner = v.owner;
      if (v.team !== KEEP) fields.team = v.team || null;
      const add = parseList(v.add);
      const remove = parseList(v.remove);
      if (add.length) fields.add_sponsors = add;
      if (remove.length) fields.remove_sponsors = remove;
      if (v.blueprint !== KEEP) fields.blueprint = v.blueprint || null;
      if (!Object.keys(fields).length) throw new Error('Fill in what to change.');
      return inTurns('v1/agents/bulk', { action: 'update', agents: chosen.map((a) => a.id), fields, ...(v.reason ? { reason: v.reason } : {}) }, 'agents');
    },
  });
  if (!result) return;
  await manyDone(result, 'Updated', 'agent');
  await refresh();
}

// Adopt several discovered agents at once: each with its maker on its platform as owner and
// sponsor where AgentGov knows them, or with one owner for all.
async function adoptMany(candidates: Agent[]): Promise<void> {
  // The boxes cleared in the list: those left out.
  const cleared = new Set<string>();
  const known = candidates.filter((a) => a.maker?.email && a.maker.known && !a.maker.left).length;
  const list = (
    <ul className="adopt-list" role="list">
      {candidates.map((a) => (
        <li key={a.id}>
          <label className="check">
            <input type="checkbox" defaultChecked value={a.id} aria-label={`Adopt ${a.name}`} onChange={(e) => {
              if (e.target.checked) cleared.delete(a.id);
              else cleared.add(a.id);
            }} />
            <span>
              <span className="cell-title">{a.name}</span>
              <span className="cell-sub">{a.maker ? makerLine(a.maker) : 'Who made it isn\'t known'}</span>
            </span>
          </label>
        </li>
      ))}
    </ul>
  );
  const result = await ask({
    title: `Adopt ${plural(candidates.length, 'agent')}`,
    text: `Each becomes pending approval, with an owner and sponsors; approve them afterwards. AgentGov knows who made ${fmt(known)} of them.`,
    iconName: 'user-check', confirm: 'Adopt', busy: 'Adopting…', wide: true,
    extra: list,
    fields: [
      { id: 'makers', type: 'checkbox', value: known > 0, label: 'Make each one\'s maker its owner and sponsor, where AgentGov knows them' },
      { id: 'owner', label: 'Owner', placeholder: 'A team or a person', hint: 'For the agents whose maker AgentGov doesn\'t know, or for all of them if the box above is clear.' },
      { id: 'sponsors', label: 'Sponsors', placeholder: 'alice@example.com, bob@example.com', hint: 'Separate people with commas: for the agents that have no maker to sponsor them.' },
      { id: 'reason', label: 'Reason', type: 'textarea', hint: 'Recorded in the evidence ledger.' },
    ],
    submit: async (v) => {
      const chosen = candidates.filter((a) => !cleared.has(a.id)).map((a) => a.id);
      if (!chosen.length) throw new Error('Choose one agent at least.');
      if (!v.makers && !v.owner) throw new Error('Give them an owner, or make their makers their owners.');
      const body: Record<string, unknown> = { agents: chosen, makers: v.makers };
      if (v.owner) body.owner = v.owner;
      const sponsors = parseList(v.sponsors);
      if (sponsors.length) body.sponsors = sponsors;
      if (v.reason) body.reason = v.reason;
      return api('v1/agents/adopt', { method: 'POST', body });
    },
  });
  if (!result) return;
  const left: any[] = result.left || [];
  toast(left.length
    ? `Adopted ${plural(result.adopted.length, 'agent')}; ${fmt(left.length)} left: ${left.slice(0, 3).map((x) => `${x.agent} (${x.why})`).join('; ')}${left.length > 3 ? '…' : ''}`
    : `Adopted ${plural(result.adopted.length, 'agent')}. They are pending approval.`, left.length ? { tone: 'critical' } : undefined);
  void refreshBadges();
  await refresh();
}

const AGENT_COLUMNS: [string, string][] = [['name', 'Agent'], ['status', 'Status'], ['risk', 'Risk'], ['owner', 'Owner'], ['blueprint', 'Blueprint'], ['last_seen', 'Last seen']];

// The agents table: sorted by the header pressed (onSort); with ``selected``, a box on each
// row to choose it for an action on many at once (onSelect(ids, chosen)).
function AgentsTable({ rows, sort = 'name', onSort = null, selected = null, onSelect = null }: {
  rows: Agent[];
  sort?: string;
  onSort?: ((key: string) => void) | null;
  selected?: Set<string> | null;
  onSelect?: ((ids: string[], on: boolean) => void) | null;
}) {
  const all = selected ? rows.every((a) => selected.has(a.id)) : false;
  const some = selected ? !all && rows.some((a) => selected.has(a.id)) : false;
  return (
    <div className="table-wrap">
      <table className="data rtable">
        <thead>
          <tr>
            {selected ? (
              <th scope="col" className="select-cell">
                <input type="checkbox" checked={all} aria-label={`Choose all ${plural(rows.length, 'agent')} shown`}
                  ref={(box) => {
                    if (box) box.indeterminate = some;
                  }}
                  onChange={(e) => onSelect?.(rows.map((a) => a.id), e.target.checked)} />
              </th>
            ) : null}
            {AGENT_COLUMNS.map(([key, label]) => {
              if (!onSort) return <th key={key} scope="col">{label}</th>;
              const current = sort.replace(/^-/, '') === key;
              const down = sort.startsWith('-');
              return (
                <th key={key} scope="col" aria-sort={current ? (down ? 'descending' : 'ascending') : undefined}>
                  <button type="button" className="th-sort" onClick={() => onSort(key)}>
                    {label}<Icon name="chevron" cls={current ? (down ? 'sort-down' : 'sort-up') : 'sort-none'} />
                  </button>
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.map((a) => {
            const href = agentHref(a.id);
            const platform = platformOf(a);
            return (
              <tr key={a.id} className={cx('is-link', selected?.has(a.id) && 'is-chosen')} onClick={(e) => {
                if ((e.target as Element).closest('a, button, input, label, .select-cell') || getSelection()?.toString()) return;
                window.location.hash = href;
              }}>
                {selected ? (
                  <td data-label="Choose" className="select-cell">
                    <label className="select-hit">
                      <input type="checkbox" checked={selected.has(a.id)} aria-label={`Choose ${a.name}`}
                        onChange={(e) => onSelect?.([a.id], e.target.checked)} />
                    </label>
                  </td>
                ) : null}
                <td data-label="Agent">
                  <a className="cell-title break" href={href}>{a.name}</a>
                  {a.description ? <div className="cell-sub clamp-2">{a.description}</div> : null}
                </td>
                <td data-label="Status"><Chip kind="agent" value={a.status} /></td>
                <td data-label="Risk"><RiskChip risk={a.risk} /></td>
                <td data-label="Owner" className="break">
                  {a.owner || <span className="muted">{a.status === 'discovered' ? 'Unassigned' : 'No owner'}</span>}
                  {!a.owner && a.maker ? <div className="cell-sub">{makerLine(a.maker)}</div> : null}
                </td>
                <td data-label="Blueprint">
                  {a.blueprint || (platform
                    ? <span className="muted" title="Blueprints grant gateway tools; this agent runs on another platform">{`${platform} agent`}</span>
                    : <span className="muted">None</span>)}
                </td>
                <td data-label="Last seen" className="nowrap"><TimeEl iso={a.last_seen_at} empty="Never" /></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
