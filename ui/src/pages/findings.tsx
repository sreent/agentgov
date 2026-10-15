// Issues: posture gaps from scheduled scans and threats detected at runtime, each sent to the
// people responsible for it. The list, what can be done to one or to many at once, and the
// answers that take a few words first (shared with an issue's own page).

import { useRef, type ReactNode } from 'react';
import { flushSync } from 'react-dom';
import { manyDone } from '../components/bulk';
import { ask, type FieldSpec } from '../components/dialog';
import { useSynced } from '../components/hooks';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import { AgentLink, Callout, Chip, EmptyState, NameList, PageHead, PlainChip, RefreshButton, TimeEl } from '../components/ui';
import { api, apiRaw, saveCsv, type CsvColumns } from '../lib/api';
import { refreshBadges } from '../lib/badges';
import { cap, countBy, cx, fmt, humanize, plural } from '../lib/format';
import { setHashQuiet, type PageDef, type PageProps } from '../lib/router';
import { can, canSome, isPerson, isScoped } from '../lib/session';
import { inTurns, PLATFORM_SOURCES, type ManyResult } from '../lib/shared';
import { SEVERITY_ORDER, statusMeta, toneOf } from '../lib/status';

type Finding = any;
/** Do something to an issue: acknowledge, resolve, accept... */
type Act = (action: string) => unknown;

const FINDING_STATUS = [
  ['open', 'Open'], ['mine', 'Yours'], ['asked', 'Risk acceptance asked'], ['accepted', 'Risk accepted'], ['resolved', 'Resolved'], ['dismissed', 'Dismissed'], ['all', 'All'],
];
const LEVEL_WORDS: Record<string, string> = { owner: 'its owner', sponsors: 'its sponsors', team: 'its team' };
export const FINDING_DONE: Record<string, string> = { resolve: 'Resolved', dismiss: 'Dismissed', reopen: 'Reopened', acknowledge: 'Acknowledged' };

// What the signed-in person may do to findings: approvers, administrators and (from triage)
// the secops role act on all of them; the people an issue reached acknowledge it.
export function mayTriage(f: Finding): boolean {
  return can('approve', f) || can('triage', f);
}

// Whether they triage some issues: for every team, or their teams'.
function mayTriageSome(): boolean {
  return canSome('approve') || canSome('triage');
}

export function findingTabs(current: 'findings' | 'types'): ReactNode {
  if (isPerson() || isScoped()) return null;
  return (
    <nav className="tabs" aria-label="Issue views">
      <a className="tab" href="#/findings" aria-current={current === 'findings' ? 'page' : undefined}>Issues</a>
      <a className="tab" href="#/findings/types" aria-current={current === 'types' ? 'page' : undefined}>Types</a>
    </nav>
  );
}

interface Filters { status: string; severity: string; category: string; type: string; group: boolean }
interface Loaded { list: Finding[]; total: number }
interface FindingsData extends Loaded { filters: Filters; agentsById: Map<string, any>; types: any[] }

// Findings come a page at a time, newest first; the control plane says how many there are in all.
const PAGE = 500;

function statusesFor(person: boolean): string[][] {
  return person ? FINDING_STATUS.filter(([k]) => !['mine', 'asked', 'dismissed'].includes(k)) : FINDING_STATUS;
}

// People without a role see the issues sent to them; everyone else, every finding, or theirs.
function source(status: string, offset: number, type: string): string {
  return isPerson() ? `v1/me/issues?status=${encodeURIComponent(status)}`
    : status === 'mine' ? 'v1/me/issues?status=open'
      : status === 'asked' ? `v1/findings?status=open&asked=true&limit=${PAGE}&offset=${offset}`
        : `v1/findings?status=${encodeURIComponent(status)}&limit=${PAGE}&offset=${offset}${type ? `&type=${encodeURIComponent(type)}` : ''}`;
}

async function fetchPage(status: string, type: string, offset = 0): Promise<Loaded> {
  const res = await apiRaw(source(status, offset, type));
  const rows = await res.json();
  const counted = res.headers.get('X-Total-Count');
  return { list: rows, total: counted === null ? offset + rows.length : Number(counted) };
}

// The page may hold only the newest of them: the badge counts them all.
function badge(status: string): void {
  if (status === 'open') void refreshBadges();
}

// Those of the issues loaded the filters show: the most severe first, then the latest seen.
function inCategory(list: Finding[], category: string): Finding[] {
  return list.filter((f) => !category || f.category === category);
}

function shownOf(list: Finding[], s: Filters): Finding[] {
  return inCategory(list, s.category)
    .filter((f) => !s.severity || f.severity === s.severity)
    .sort((x, y) => SEVERITY_ORDER.indexOf(x.severity) - SEVERITY_ORDER.indexOf(y.severity) || String(y.last_seen).localeCompare(String(x.last_seen)));
}

export const findingsPage: PageDef<FindingsData> = {
  re: /^\/findings$/,
  nav: 'findings',
  title: 'Issues',
  load: async ({ params }) => {
    const person = isPerson();
    const statuses = statusesFor(person);
    const filters: Filters = {
      status: statuses.some(([k]) => k === params.get('status')) ? params.get('status')! : 'open',
      severity: params.get('severity') || '',
      category: params.get('category') || '',
      type: params.get('type') || '',
      group: params.get('group') === 'agent',
    };
    const [initial, agents, types] = await Promise.all([
      fetchPage(filters.status, filters.type),
      person ? [] : api<any[]>('v1/agents?include_deleted=true').catch(() => []),
      person || isScoped() ? [] : api<any[]>('v1/finding-types').catch(() => []),
    ]);
    badge(filters.status);
    return { ...initial, filters, agentsById: new Map(agents.map((a: any) => [a.id, a])), types };
  },
  View: FindingsView,
  titleOf: () => (isPerson() ? 'Your issues' : 'Issues'),
};

interface Choose {
  selected: Set<string>;
  onSelect: (ids: string[], on: boolean) => void;
}

function FindingsView({ data }: PageProps<FindingsData>) {
  const person = isPerson();
  const statuses = statusesFor(person);
  const { agentsById } = data;
  const [state, setState] = useSynced(data.filters);
  const [loaded, setLoaded] = useSynced<Loaded>({ list: data.list, total: data.total }, data);
  // Those chosen for an action on many at once, by ID: only ever among those shown. Those
  // who triage do anything to them; the people an issue reached acknowledge theirs.
  const [selected, setSelected] = useSynced<Set<string>>(new Set(), data);
  const listHost = useRef<HTMLDivElement>(null);
  const listTitle = useRef<HTMLHeadingElement>(null);
  const { list, total } = loaded;

  const sync = (s: Filters) => setHashQuiet('/findings', {
    status: s.status === 'open' ? '' : s.status, severity: s.severity, category: s.category, type: s.type, group: s.group ? 'agent' : '',
  });
  const reload = async (s: Filters): Promise<Loaded> => {
    const next = await fetchPage(s.status, s.type);
    badge(s.status);
    return next;
  };
  // Show these filters over this list; those chosen stay chosen only while shown.
  const show = (s: Filters, l: Loaded) => {
    setState(s);
    setLoaded(l);
    const ids = new Set(shownOf(l.list, s).map((f) => f.id));
    setSelected((prev) => ([...prev].every((id) => ids.has(id)) ? prev : new Set([...prev].filter((id) => ids.has(id)))));
  };
  const filter = (s: Filters) => {
    show(s, loaded);
    sync(s);
  };

  const pickStatus = async (key: string) => {
    const next = { ...state, status: key };
    sync(next);
    let fetched = loaded;
    try {
      fetched = await reload(next);
    } catch (err: any) {
      toast(err.message, { tone: 'critical' });
    }
    show(next, fetched);
  };

  const pickType = async (type: string) => {
    const next = { ...state, type };
    setState(next);
    sync(next);
    let fetched = loaded;
    try {
      fetched = await reload(next);
    } catch (err: any) {
      toast(err.message, { tone: 'critical' });
    }
    show(next, fetched);
  };

  const showMore = async () => {
    try {
      const page = await fetchPage(state.status, state.type, list.length);
      show(state, { list: list.concat(page.list), total: page.total });
    } catch (err: any) {
      toast(err.message, { tone: 'critical' });
    }
  };

  async function act(f: Finding, action: string, rows: Finding[]) {
    try {
      const answered = await answerIssue(f, action);
      if (answered === false) return;
      if (answered === null) {
        await api(`v1/findings/${encodeURIComponent(f.id)}/${action}`, { method: 'POST' });
        toast(`${FINDING_DONE[action]}: ${f.title}`);
      }
      const index = rows.indexOf(f);
      const next = await reload(state);
      flushSync(() => show(state, next));
      const host = listHost.current;
      const cards = host ? host.querySelectorAll<HTMLElement>('.finding') : [];
      const target = host?.querySelector<HTMLElement>(`[aria-labelledby="finding-title-${CSS.escape(f.id)}"]`)
        || cards[Math.min(index, cards.length - 1)]
        || listTitle.current;
      target?.focus();
      void refreshBadges();
    } catch (err: any) {
      toast(err.message, { tone: 'critical' });
    }
  }

  const scoped = inCategory(list, state.category);
  const bySev = countBy(scoped, 'severity');
  const rows = shownOf(list, state);
  const which = ['all', 'mine', 'asked'].includes(state.status) ? '' : `${statusMeta('finding', state.status)[2].toLowerCase()} `;
  // One whose people asked for its risk to be accepted is counted as such.
  const many = (n: number) => (state.status === 'asked' ? plural(n, 'issue with risk acceptance asked', 'issues with risk acceptance asked') : plural(n, `${which}issue`));
  // Counted among those loaded: say so when there are more.
  const capped = total > list.length;
  const count = !capped ? many(rows.length)
    : rows.length === list.length ? `The newest ${fmt(list.length)} of ${many(total)}`
      : `${many(rows.length)} among the newest ${fmt(list.length)} of ${fmt(total)}`;
  const yours = person || state.status === 'mine';
  const selecting = mayTriageSome() || person || state.status === 'mine';
  const choose: Choose | null = selecting && rows.length ? {
    selected,
    onSelect: (ids, on) => setSelected((prev) => {
      const next = new Set(prev);
      for (const id of ids) {
        if (on) next.add(id);
        else next.delete(id);
      }
      return next;
    }),
  } : null;
  const run = async (action: string) => {
    const done = await findingsAtOnce(rows.filter((f) => selected.has(f.id)), action);
    if (!done) return;
    let next = loaded;
    try {
      next = await reload(state);
    } catch (err: any) {
      toast(err.message, { tone: 'critical' });
    }
    flushSync(() => {
      setSelected(new Set());
      show(state, next);
    });
    listTitle.current?.focus();
    void refreshBadges();
  };
  const card = (f: Finding) => (
    <FindingCard key={f.id} f={f} agentsById={agentsById} act={(action) => act(f, action, rows)} yours={yours} choose={choose} />
  );

  return (
    <div className="page">
      <PageHead
        title={person ? 'Your issues' : 'Issues'}
        sub={person
          ? 'Issues about agents you own or sponsor, and those sent to your teams. Acknowledge one to take it on: it then goes no further. Fix what it says and it closes by itself.'
          : 'Posture gaps from scheduled scans and threats detected at runtime, most severe first. Each goes to the people responsible: the agent\'s owner, then its sponsors, then its team.'}
        actions={[<RefreshButton key="refresh" />]}
      />
      {findingTabs('findings')}
      <div className="filters">
        <div className="seg" role="group" aria-label="Issue status">
          {statuses.map(([key, label]) => (
            <button key={key} type="button" className="seg-btn" aria-pressed={state.status === key} onClick={() => void pickStatus(key)}>{label}</button>
          ))}
        </div>
        <div className="field" style={{ flex: '0 1 180px' }}>
          <label htmlFor="finding-category" className="sr-only">Category</label>
          <select id="finding-category" value={state.category} onChange={(e) => filter({ ...state, category: e.target.value })}>
            {[['', 'All categories'], ['threat', 'Threats'], ['posture', 'Posture']].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </div>
        {person ? null : (
          <div className="field" style={{ flex: '0 1 260px' }}>
            <label htmlFor="finding-type" className="sr-only">Type</label>
            <select id="finding-type" value={state.type} onChange={(e) => void pickType(e.target.value)}>
              <option value="">All types</option>
              {data.types.filter((t) => t.total || t.type === data.filters.type).map((t) => (
                <option key={t.type} value={t.type}>{t.open ? `${t.type} (${fmt(t.open)} open)` : t.type}</option>
              ))}
            </select>
          </div>
        )}
      </div>
      <div className="filters">
        <div className="seg" role="group" aria-label="Severity">
          <button type="button" className="seg-btn" aria-pressed={!state.severity} onClick={() => filter({ ...state, severity: '' })}>
            Any severity<span className="count">{fmt(scoped.length)}</span>
          </button>
          {SEVERITY_ORDER.filter((k) => bySev[k] || state.severity === k).map((k) => {
            const [tone, ic, label] = statusMeta('severity', k);
            return (
              <button key={k} type="button" className="seg-btn" aria-pressed={state.severity === k} onClick={() => filter({ ...state, severity: k })}>
                <Icon name={ic} cls={`t-${tone}`} />{label}<span className="count">{fmt(bySev[k] || 0)}</span>
              </button>
            );
          })}
        </div>
        <p className="result-count" aria-live="polite">{count}</p>
        <button type="button" className="btn btn--sm btn--ghost" hidden={!capped} onClick={showMore}>
          {`Show ${fmt(Math.min(PAGE, total - list.length))} more`}
        </button>
        <label className="check" htmlFor="finding-group">
          <input type="checkbox" id="finding-group" checked={state.group} onChange={(e) => filter({ ...state, group: e.target.checked })} />
          Group by agent
        </label>
        <button type="button" className="btn btn--sm btn--ghost" title="The issues shown, as a spreadsheet" disabled={!rows.length}
          onClick={() => saveCsv('agentgov-issues', findingCsv(agentsById), rows)}>
          <Icon name="download" />Download CSV
        </button>
      </div>
      <div>
        {choose ? <FindingBulkBar rows={rows} choose={choose} clear={() => setSelected(new Set())} run={run} /> : null}
      </div>
      <h2 className="sr-only" tabIndex={-1} id="finding-list-title" ref={listTitle}>Issues</h2>
      <div className="finding-list" ref={listHost}>
        {!rows.length ? <section className="card">{emptyFindings(state.status, person)}</section>
          : state.group ? findingGroups(rows, agentsById, card, choose) : rows.map(card)}
      </div>
    </div>
  );
}

// A box that chooses several at once: half checked while only some of them are chosen.
function ChooseBox({ id, label, checked, mixed, onChoose }: {
  id?: string; label?: string; checked: boolean; mixed: boolean; onChoose: (on: boolean) => void;
}) {
  return (
    <input type="checkbox" id={id} aria-label={label} checked={checked}
      ref={(el) => {
        if (el) el.indeterminate = mixed;
      }}
      onChange={(e) => onChoose(e.target.checked)} />
  );
}

// The findings shown, by agent: the agents with the most severe first, then those with more.
function findingGroups(rows: Finding[], agentsById: Map<string, any>, card: (f: Finding) => ReactNode, choose: Choose | null): ReactNode[] {
  const groups = new Map<string, Finding[]>();
  for (const f of rows) {
    const key = f.agent_id || `subject:${f.subject}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(f);
  }
  // Not about one agent: about a platform, say.
  const nameOf = (list: Finding[]): string => agentsById.get(list[0].agent_id)?.name || list[0].agent_name
    || PLATFORM_SOURCES[list[0].subject] || list[0].subject || '';
  const worst = (list: Finding[]) => Math.min(...list.map((f) => SEVERITY_ORDER.indexOf(f.severity)));
  return [...groups.entries()]
    .sort(([, a], [, b]) => worst(a) - worst(b) || b.length - a.length || nameOf(a).localeCompare(nameOf(b)))
    .map(([key, list], i) => {
      const first = list[0];
      const headingId = `finding-group-${i}`;
      let box: ReactNode = null;
      if (choose) {
        const all = list.every((f) => choose.selected.has(f.id));
        box = (
          <ChooseBox checked={all} mixed={!all && list.some((f) => choose.selected.has(f.id))}
            label={`Choose the ${plural(list.length, 'issue')} ${nameOf(list) ? `about ${nameOf(list)}` : 'not about an agent'}`}
            onChoose={(on) => choose.onSelect(list.map((f) => f.id), on)} />
        );
      }
      return (
        <section key={key} className="finding-group" aria-labelledby={headingId}>
          <div className="finding-group-head">
            {box ? <label className="check finding-choose">{box}</label> : null}
            <h2 id={headingId} className="finding-group-title break">
              {first.agent_id && !isPerson() ? <AgentLink id={first.agent_id} name={nameOf(list)} /> : nameOf(list) || 'Not about an agent'}
            </h2>
            <Chip kind="severity" value={SEVERITY_ORDER[worst(list)]} />
            <span className="muted small">{plural(list.length, 'issue')}</span>
          </div>
          <div className="finding-list">{list.map(card)}</div>
        </section>
      );
    });
}

// Who an issue is with, in a few words, for a spreadsheet.
function withWhom(f: Finding): string {
  if (f.status === 'accepted') return `risk accepted until ${String(f.accepted_until).slice(0, 10)}`;
  if (f.status !== 'open' || !f.level) return '';
  const who = (f.assignees || []).join(', ');
  return `${who}${who ? ' ' : ''}(${LEVEL_WORDS[f.level] || f.level})${f.acknowledged_at ? ', acknowledged' : ''}`;
}

function findingCsv(agentsById: Map<string, any>): CsvColumns<Finding> {
  return [
    ['Severity', (f) => f.severity],
    ['Status', (f) => f.status],
    ['Agent', (f) => agentsById.get(f.agent_id)?.name || f.agent_name || f.subject],
    ['Title', (f) => f.title],
    ['Type', (f) => f.type],
    ['Category', (f) => f.category],
    ['With', withWhom],
    ['Times seen', (f) => f.occurrences],
    ['First seen', (f) => f.first_seen],
    ['Last seen', (f) => f.last_seen],
    ['Verified', (f) => (f.verified === false ? 'no' : 'yes')],
    ['Closed by', (f) => f.resolved_by],
    ['Closed', (f) => f.resolved_at],
    ['ID', (f) => f.id],
  ];
}

interface ManySpec {
  label: string;
  icon: string;
  verb: string;
  done: string;
  fits: (f: Finding) => unknown;
  triage?: boolean;
}

// What can be done to many findings at once, and to which of them.
const FINDINGS_AT_ONCE: Record<string, ManySpec> = {
  acknowledge: { label: 'Acknowledge', icon: 'user-check', verb: 'Acknowledged', done: 'acknowledged', fits: (f) => f.status === 'open' && f.level && !f.acknowledged_at },
  resolve: { label: 'Resolve', icon: 'check', verb: 'Resolved', done: 'resolved', fits: (f) => f.status === 'open', triage: true },
  accept: { label: 'Accept risk', icon: 'shield-check', verb: 'Accepted the risk of', done: 'accepted', fits: (f) => f.status === 'open', triage: true },
  dismiss: { label: 'Dismiss', icon: 'minus', verb: 'Dismissed', done: 'dismissed', fits: (f) => f.status === 'open', triage: true },
  reopen: { label: 'Reopen', icon: 'undo', verb: 'Reopened', done: 'reopened', fits: (f) => f.status !== 'open', triage: true },
};

function FindingBulkBar({ rows, choose, clear, run }: {
  rows: Finding[]; choose: Choose; clear: () => void; run: (action: string) => Promise<void>;
}) {
  const chosen = rows.filter((f) => choose.selected.has(f.id));
  const all = chosen.length === rows.length;
  const buttons: ReactNode[] = [];
  if (chosen.length) {
    const triage = mayTriageSome();
    for (const [action, spec] of Object.entries(FINDINGS_AT_ONCE)) {
      if (spec.triage && !triage) continue;
      const n = chosen.filter(spec.fits).length;
      if (!n) continue;
      buttons.push(
        <button key={action} type="button" className="btn btn--sm" onClick={guarded(() => run(action))}>
          <Icon name={spec.icon} />{n === chosen.length ? spec.label : `${spec.label} ${fmt(n)}`}{['accept', 'dismiss'].includes(action) ? '…' : ''}
        </button>,
      );
    }
  }
  return (
    <div className={cx('bulk-bar', !chosen.length && 'bulk-bar--idle')} role="region" aria-label="Chosen issues">
      <label className="check" htmlFor="choose-all-findings">
        <ChooseBox id="choose-all-findings" checked={all} mixed={!all && chosen.length > 0}
          onChoose={(on) => choose.onSelect(rows.map((f) => f.id), on)} />
        {chosen.length ? <strong aria-live="polite">{`${fmt(chosen.length)} of ${fmt(rows.length)} chosen`}</strong> : `Choose all ${fmt(rows.length)} shown`}
      </label>
      {buttons.length ? <div className="btn-row">{buttons}</div> : null}
      {chosen.length ? <button type="button" className="btn btn--sm btn--ghost" onClick={clear}><Icon name="x" />Clear</button> : null}
    </div>
  );
}

// Do one thing to the findings chosen; resolves to whether it was done.
async function findingsAtOnce(chosen: Finding[], action: string): Promise<boolean> {
  const spec = FINDINGS_AT_ONCE[action];
  const fits = chosen.filter(spec.fits);
  const fields: FieldSpec[] = [];
  let text = ({
    acknowledge: 'Take them on: they go no further up their chains.',
    resolve: 'Mark them resolved. A check that finds one again opens it again.',
    reopen: 'They open again, and go to the people responsible for them.',
    accept: 'They go to nobody until the date you choose, then each opens again if it still holds. A year at most: then someone decides again. Those about agents you own or sponsor are left to someone else.',
    dismiss: 'Dismiss what is wrong: to live with real risks, accept them. They go to nobody; given a date, each opens again then if it still holds. A threat opens again when it happens again.',
  } as Record<string, string>)[action];
  if (action === 'accept') {
    fields.push(
      { id: 'reason', label: 'Why their risk is acceptable', type: 'textarea', required: true, hint: 'Recorded in the evidence ledger, and shown with each of them.' },
      { id: 'until', label: 'Until', required: true, value: new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10), mono: true, hint: 'A date (YYYY-MM-DD), or a number of days.' },
    );
  } else if (action === 'dismiss') {
    fields.push(
      { id: 'reason', label: 'Why they are wrong', type: 'textarea', required: true, hint: 'Recorded in the evidence ledger, and shown with each of them.' },
      { id: 'until', label: 'Until', mono: true, hint: 'A date (YYYY-MM-DD) or a number of days. Empty: for good.' },
    );
  }
  const others = chosen.length - fits.length;
  if (others) text += ` ${plural(others, 'other issue')} chosen can't be ${spec.done}, and ${others === 1 ? 'stays as it is' : 'stay as they are'}.`;
  const result = await ask<ManyResult>({
    title: `${spec.label} ${plural(fits.length, 'issue')}?`,
    text, iconName: spec.icon, confirm: `${spec.label} ${plural(fits.length, 'issue')}`, busy: 'Working…',
    extra: <NameList names={fits.map((f) => f.title)} />,
    fields,
    submit: (v) => {
      const body: Record<string, any> = { action, findings: fits.map((f) => f.id) };
      if (v.reason) body.reason = v.reason;
      if (v.until) body.until = /^\d+$/.test(v.until) ? Number(v.until) : v.until;
      return inTurns('v1/findings/bulk', body, 'findings');
    },
  });
  if (!result) return false;
  await manyDone(result, spec.verb, 'issue');
  return true;
}

function emptyFindings(status: string, person: boolean): ReactNode {
  if (status === 'mine' || (person && status === 'open')) {
    return <EmptyState title="Nothing is waiting for you" text="Issues about agents you own or sponsor, and those sent to your teams, appear here." />;
  }
  if (status === 'open') return <EmptyState title="No open issues" text="Posture scans and runtime detections raise issues here." />;
  return <EmptyState title="No issues match these filters" />;
}

// Who an issue is with, and what they did about it.
function issueLine(f: Finding): ReactNode {
  if (f.status === 'accepted') {
    return (
      <p className="finding-issue">
        <Icon name="shield-check" />
        <span><strong>{'Risk accepted '}</strong>{'until '}<TimeEl iso={f.accepted_until} absolute />{f.accepted_reason ? `: ${f.accepted_reason}` : ''}</span>
      </p>
    );
  }
  if (f.status !== 'open') return null;
  if (!f.level) return null;
  const who = (f.assignees || []).join(', ');
  if (f.acknowledged_at) {
    return (
      <p className="finding-issue">
        <Icon name="user-check" />
        <span><strong>{`${f.acknowledged_by?.replace(/^[a-z]+:/, '') || 'Someone'} took it on `}</strong><TimeEl iso={f.acknowledged_at} /></span>
      </p>
    );
  }
  return (
    <p className="finding-issue">
      <Icon name="user" />
      <span>
        {'With '}<strong>{LEVEL_WORDS[f.level] || f.level}</strong>{who ? ` (${who})` : ''}
        {f.escalate_at ? <>{', goes further '}<TimeEl iso={f.escalate_at} />{' unless someone acknowledges it'}</> : ''}
      </span>
    </p>
  );
}

/** What can be done to an issue, as buttons: in the list, or (detail) on its own page. */
export function findingActions(f: Finding, act: Act, { yours = false, detail = false }: { yours?: boolean; detail?: boolean } = {}): ReactNode[] {
  const triage = mayTriage(f);
  const buttons: ReactNode[] = [];
  if (!detail) {
    buttons.push(<a key="details" className="btn btn--sm btn--ghost" href={`#/findings/${encodeURIComponent(f.id)}`}>Details<Icon name="arrow" /></a>);
  }
  if (f.status === 'open') {
    if (f.level && !f.acknowledged_at && (triage || yours)) {
      buttons.push(<button key="acknowledge" type="button" className="btn btn--sm" onClick={() => act('acknowledge')}><Icon name="user-check" />Acknowledge</button>);
    }
    // The people it reached answer it: on its page, all the ways they can.
    if (yours && detail && f.level) {
      buttons.push(<button key="not-mine" type="button" className="btn btn--sm" onClick={() => act('not-mine')}><Icon name="arrow" />Not mine</button>);
    }
    if (yours && detail && !f.details?.exception_request) {
      buttons.push(<button key="exception" type="button" className="btn btn--sm" onClick={() => act('exception')}><Icon name="shield-check" />Ask to accept the risk</button>);
    }
    if (yours || triage) {
      buttons.push(
        <button key="recheck" type="button" className="btn btn--sm" title="Say you fixed it: AgentGov checks it again now, where it can" onClick={() => act('recheck')}>
          <Icon name="refresh" />I fixed it
        </button>,
      );
    }
    if (triage) {
      buttons.push(
        <button key="accept" type="button" className="btn btn--sm" onClick={() => act('accept')}><Icon name="shield-check" />Accept risk</button>,
        <button key="dismiss" type="button" className="btn btn--sm" onClick={() => act('dismiss')}><Icon name="minus" />Dismiss</button>,
        <button key="resolve" type="button" className="btn btn--sm btn--primary" onClick={() => act('resolve')}><Icon name="check" />Resolve</button>,
      );
    }
  } else if (triage) {
    buttons.push(<button key="reopen" type="button" className="btn btn--sm" onClick={() => act('reopen')}><Icon name="undo" />Reopen</button>);
  }
  return buttons;
}

/** Accept an issue's risk until a date, after asking why; resolves to the issue, or null. */
export async function acceptRisk(f: Finding): Promise<any> {
  // What its people asked for, if they asked for its risk to be accepted: to agree to or change.
  const asked = f.details?.exception_request;
  const later = asked?.until?.slice(0, 10) || new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10);
  const done = await ask<any>({
    title: 'Accept the risk?',
    text: `${f.title}. It goes to nobody until the date you choose, then opens again if it still holds. A year at most: then someone decides again.`,
    iconName: 'shield-check', confirm: 'Accept risk',
    fields: [
      { id: 'reason', label: 'Why it is acceptable', type: 'textarea', required: true, value: asked?.reason || null, hint: 'Recorded in the evidence ledger, and shown with the issue.' },
      { id: 'until', label: 'Until', required: true, value: later, mono: true, hint: 'A date (YYYY-MM-DD), or a number of days.' },
    ],
    submit: (v) => api(`v1/findings/${encodeURIComponent(f.id)}/accept`, {
      method: 'POST', body: { reason: v.reason, until: /^\d+$/.test(v.until) ? Number(v.until) : v.until },
    }),
  });
  if (done) toast(`Risk accepted until ${done.accepted_until.slice(0, 10)}: ${f.title}`);
  return done;
}

// The answers that take a few words first: accepting the risk, saying an issue isn't
// yours, asking for its risk to be accepted, declining that, and saying you fixed it. Resolves to
// whether something was done, or null for the other actions.
export async function answerIssue(f: Finding, action: string): Promise<boolean | null> {
  const path = `v1/findings/${encodeURIComponent(f.id)}`;
  if (action === 'accept') return Boolean(await acceptRisk(f));
  if (action === 'not-mine') {
    const done = await ask<any>({
      title: 'Not yours?',
      text: `${f.title}. It goes on to the next people responsible for it at once, and they see why.`,
      iconName: 'arrow', confirm: 'Pass it on',
      fields: [{ id: 'reason', label: 'Why it isn\'t yours', type: 'textarea', required: true, hint: 'Whose it is, if you know. Recorded in the evidence ledger.' }],
      submit: (v) => api(`${path}/not-mine`, { method: 'POST', body: { reason: v.reason } }),
    });
    if (done) toast(done.went_to?.length ? `Passed on to ${done.went_to.join(', ')}.` : 'Recorded. Nobody comes after you in its chain, so it stays where it is.');
    return Boolean(done);
  }
  if (action === 'exception') {
    const later = new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10);
    const done = await ask<any>({
      title: 'Ask to accept the risk?',
      text: `${f.title}. An approver decides whether its risk is acceptable until the date you ask for. It stays with you meanwhile.`,
      iconName: 'shield-check', confirm: 'Ask',
      fields: [
        { id: 'reason', label: 'Why its risk is acceptable', type: 'textarea', required: true, hint: 'What makes it safe enough for now, and what you will do by then.' },
        { id: 'until', label: 'Until', required: true, value: later, mono: true, hint: 'A date (YYYY-MM-DD), or a number of days: a year at most.' },
      ],
      submit: (v) => api(`${path}/exception`, { method: 'POST', body: { reason: v.reason, until: /^\d+$/.test(v.until) ? Number(v.until) : v.until } }),
    });
    if (done) toast('Asked. An approver decides.');
    return Boolean(done);
  }
  if (action === 'decline-exception') {
    const done = await ask<any>({
      title: 'Decline the request?',
      text: `${f.title}. Its risk isn't accepted: it stays with whoever asked, to fix.`,
      iconName: 'x', confirm: 'Decline',
      fields: [{ id: 'reason', label: 'Why not', type: 'textarea', required: true, hint: 'Recorded in the evidence ledger, and shown with the issue.' }],
      submit: (v) => api(`${path}/exception/decline`, { method: 'POST', body: { reason: v.reason } }),
    });
    if (done) toast('Declined.');
    return Boolean(done);
  }
  if (action === 'dismiss') {
    const done = await ask<any>({
      title: 'Dismiss it?',
      text: `${f.title}. Dismiss what is wrong: to live with a real risk, accept it. It goes to nobody; given a date, it opens again then if it still holds. A threat opens again when it happens again.`,
      iconName: 'minus', confirm: 'Dismiss',
      fields: [
        { id: 'reason', label: 'Why it is wrong', type: 'textarea', required: true, hint: 'Recorded in the evidence ledger, and shown with the issue.' },
        { id: 'until', label: 'Until', mono: true, hint: 'A date (YYYY-MM-DD) or a number of days. Empty: for good.' },
      ],
      submit: (v) => api(`${path}/dismiss`, {
        method: 'POST', body: { reason: v.reason, ...(v.until ? { until: /^\d+$/.test(v.until) ? Number(v.until) : v.until } : {}) },
      }),
    });
    if (done) toast(`Dismissed: ${f.title}`);
    return Boolean(done);
  }
  if (action === 'recheck') {
    const out = await api(`${path}/recheck`, { method: 'POST' });
    toast(out.fixed ? `Checked again, and it is gone: ${f.title}` : `Checked again, and it is still there.${out.note ? ` ${out.note}` : ''}`,
      out.fixed ? undefined : { tone: 'critical' });
    return true;
  }
  return null;
}

// Someone it reached asks for its risk to be accepted: approvers decide here.
export function exceptionAsked(f: Finding, act: Act): ReactNode {
  const asked = f.details?.exception_request;
  if (!asked || f.status !== 'open') return null;
  return (
    <Callout tone="warning" icon="shield-check">
      <div className="stack" style={{ gap: 8 }}>
        <span><strong>{`${asked.by} asks for its risk to be accepted until ${String(asked.until).slice(0, 10)}: `}</strong>{asked.reason}</span>
        {mayTriage(f) ? (
          <div className="btn-row">
            <button type="button" className="btn btn--sm btn--primary" onClick={() => act('accept')}><Icon name="shield-check" />Accept risk</button>
            <button type="button" className="btn btn--sm" onClick={() => act('decline-exception')}><Icon name="x" />Decline</button>
          </div>
        ) : null}
      </div>
    </Callout>
  );
}

function FindingCard({ f, agentsById, act, yours = false, choose = null }: {
  f: Finding; agentsById: Map<string, any>; act: Act; yours?: boolean; choose?: Choose | null;
}) {
  const tone = toneOf('severity', f.severity);
  const agent = f.agent_id ? agentsById.get(f.agent_id) : null;
  const headingId = `finding-title-${f.id}`;
  // People without a role can't list agents: their issues come with the agent's name.
  const name = agent?.name || f.agent_name || f.subject;
  const subject = f.agent_id && !isPerson() ? <AgentLink id={f.agent_id} name={name} /> : <code>{name}</code>;
  const asked = f.details?.exception_request;
  return (
    <article className="card finding" data-tone={tone} aria-labelledby={headingId} tabIndex={-1}>
      <div className="finding-stripe" aria-hidden="true" />
      <div className="finding-main">
        <div className="finding-top">
          {choose ? (
            <label className="check finding-choose">
              <input type="checkbox" checked={choose.selected.has(f.id)} aria-label={`Choose: ${f.title}`}
                onChange={(e) => choose.onSelect([f.id], e.target.checked)} />
            </label>
          ) : null}
          <Chip kind="severity" value={f.severity} />
          <PlainChip text={humanize(f.category)} />
          {f.status !== 'open' ? <Chip kind="finding" value={f.status} /> : null}
          {f.verified === false ? (
            <PlainChip text="Unverified" tone="warning" iconName="triangle" title={`${cap(f.unverified_reason || 'the sync that checks it failed')}: it may no longer hold.`} />
          ) : null}
          {f.status === 'open' && asked ? (
            <PlainChip text="Risk acceptance asked" tone="warning" iconName="shield-check" title={`${asked.by}: ${asked.reason}`} />
          ) : null}
          <span className="ledger-type muted">{f.type}</span>
        </div>
        <h3 id={headingId} className="break">{f.title}</h3>
        {f.description ? <p className="finding-desc small">{f.description}</p> : null}
        {f.remediation ? <p className="finding-fix"><strong>{'How to fix: '}</strong>{f.remediation}</p> : null}
        {issueLine(f)}
        <div className="finding-actions">
          <div className="finding-meta">
            <span>{'Subject: '}{subject}</span>
            <span>{`Seen ${f.occurrences === 1 ? 'once' : `${fmt(f.occurrences)} times`}`}</span>
            <span>{'First '}<TimeEl iso={f.first_seen} /></span>
            <span>{'Last '}<TimeEl iso={f.last_seen} /></span>
            {f.resolved_at ? (
              <span>
                {`${f.status === 'dismissed' ? 'Dismissed' : f.status === 'accepted' ? 'Accepted' : 'Resolved'} by ${f.resolved_by || 'unknown'} `}
                <TimeEl iso={f.resolved_at} />
              </span>
            ) : null}
          </div>
          <div className="btn-row">{findingActions(f, act, { yours })}</div>
        </div>
      </div>
    </article>
  );
}
