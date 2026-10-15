// Each agent's classification under the EU AI Act (docs/evidence.md#a-classification-register).

import { manyDone } from '../components/bulk';
import { ask } from '../components/dialog';
import { useSynced } from '../components/hooks';
import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import { AgentLink, Card, Chip, EmptyState, Facts, NameList, PageHead, TimeEl } from '../components/ui';
import { api, saveCsv, type CsvColumns } from '../lib/api';
import { countBy, fmt, humanize, plural } from '../lib/format';
import { refresh, setHashQuiet, type PageDef } from '../lib/router';
import { can } from '../lib/session';
import { inTurns, PLATFORM_SOURCES } from '../lib/shared';
import { statusMeta } from '../lib/status';
import { LedgerTabs } from './ledger';

const CLASSIFICATION_CATEGORIES = [
  ['high-risk', 'High-risk (Art. 6: Annex I or Annex III)'],
  ['transparency', 'Transparency obligations (Art. 50)'],
  ['minimal', 'Minimal risk'],
  ['prohibited', 'A prohibited practice (Art. 5)'],
  ['not-ai-system', 'Not an AI system (Art. 3(1))'],
];
const CLASSIFICATION_ROLES = [['deployer', 'Deployer'], ['provider', 'Provider'], ['provider-and-deployer', 'Provider and deployer']];
const roleWord = (role: string | null | undefined) => (CLASSIFICATION_ROLES.find(([k]) => k === role) || [])[1] || role || '';

/** Classify one agent, or several alike at once; resolves to whether it was done. */
export async function classifyAgents(list: any[]): Promise<boolean> {
  if (!list.length) return false;
  const one = list.length === 1 ? list[0] : null;
  const c = one?.classification || {};
  const result = await ask({
    title: one ? `Classify ${one.name}` : `Classify ${plural(list.length, 'agent')}`,
    text: 'Under the EU AI Act. Whether it is high-risk, and whether you are its provider or its deployer, decides which obligations apply to it. AgentGov keeps what you decide, who decided and when.',
    iconName: 'shield-check', confirm: 'Classify', busy: 'Saving…', wide: !one,
    extra: one ? null : <NameList names={list.map((a) => a.name)} />,
    fields: [
      {
        type: 'row',
        fields: [
          {
            id: 'category', label: 'Category', type: 'select', required: true, value: c.category || '',
            options: [{ value: '', label: 'Choose one' }, ...CLASSIFICATION_CATEGORIES.map(([value, label]) => ({ value, label }))],
          },
          {
            id: 'role', label: 'Your role for it', type: 'select', required: true, value: c.role || 'deployer',
            options: CLASSIFICATION_ROLES.map(([value, label]) => ({ value, label })),
          },
        ],
      },
      { id: 'basis', label: 'Why', type: 'textarea', value: c.basis || null, hint: 'Needed for high-risk or prohibited: the Annex III area (4(a), recruitment, say) or the Article 5 practice.' },
      { id: 'purpose', label: 'What it is for', type: 'textarea', value: c.purpose || null, hint: 'Its intended purpose, as you would put it to an assessor.' },
    ],
    submit: (v) => {
      const fields = { category: v.category, role: v.role, basis: v.basis, purpose: v.purpose };
      return one
        ? api(`v1/agents/${encodeURIComponent(one.id)}/classification`, { method: 'PUT', body: fields })
        : inTurns('v1/agents/bulk', { action: 'classify', agents: list.map((a) => a.id), fields }, 'agents');
    },
  });
  if (!result) return false;
  if (one) toast(`Classified ${one.name}.`);
  else await manyDone(result, 'Classified', 'agent');
  return true;
}

/** An agent's classification, on its page. */
export function ClassificationCard({ a }: { a: any }) {
  const c = a.classification;
  const change = can('approve', a) && a.status !== 'deleted' ? (
    <button key="classify" type="button" className="btn btn--sm" onClick={guarded(async () => { if (await classifyAgents([a])) await refresh(); })}>
      <Icon name="shield-check" />{c ? 'Change' : 'Classify'}
    </button>
  ) : null;
  return (
    <Card title="Classification" sub="Under the EU AI Act" actions={change ? [change] : null}>
      {c ? (
        <>
          <div className="chip-row"><Chip kind="classification" value={c.category} /></div>
          <Facts rows={[
            ['Your role', roleWord(c.role)],
            c.basis ? ['Why', c.basis] : null,
            c.purpose ? ['What it is for', c.purpose] : null,
            ['Classified by', <span>{`${(c.by || 'unknown').replace(/^[a-z]+:/, '')} `}<TimeEl iso={c.at} /></span>],
          ]} />
        </>
      ) : (
        <p className="muted">Not classified yet: whether it is high-risk, and your role for it, decide which obligations apply to it.</p>
      )}
    </Card>
  );
}

const REGISTER_CSV: CsvColumns<any> = [
  ['Agent', (r) => r.agent],
  ['Status', (r) => r.status],
  ['Category', (r) => r.category || 'not classified'],
  ['Role', (r) => r.role],
  ['Why', (r) => r.basis],
  ['What it is for', (r) => r.purpose],
  ['Owner', (r) => r.owner],
  ['Where', (r) => PLATFORM_SOURCES[r.source] || r.source],
  ['Classified by', (r) => r.classified_by],
  ['Classified', (r) => r.classified_at],
  ['ID', (r) => r.id],
];

export const registerPage: PageDef<{ rows: any[]; category: string }> = {
  re: /^\/ledger\/register$/,
  nav: 'register',
  title: 'Register',
  load: async ({ params }) => ({ rows: await api('v1/evidence/register'), category: params.get('category') || '' }),
  View: ({ data }) => {
    const { rows } = data;
    const [category, setCategory] = useSynced(data.category);
    const counts = countBy(rows, (r: any) => r.category || 'none');
    const shown = rows.filter((r) => !category || (category === 'none' ? !r.category : r.category === category));
    const options = [['', `Every agent (${fmt(rows.length)})`], ['none', `Not classified (${fmt(counts.none || 0)})`],
      ...CLASSIFICATION_CATEGORIES.map(([k]) => [k, `${statusMeta('classification', k)[2]} (${fmt(counts[k] || 0)})`])];
    return (
      <div className="page">
        <PageHead
          title="Classification register"
          sub={'Each agent’s classification under the EU AI Act: whether it is an AI system and at which level of risk, your role for it, why, and what it is for, with who classified it and when. It goes in the evidence pack.'}
        />
        <LedgerTabs current="register" />
        <div className="chip-row">{Object.entries(counts).map(([k, n]) => <Chip key={k} kind="classification" value={k} extra={n} />)}</div>
        <div className="filters">
          <div className="field" style={{ flex: '0 1 300px' }}>
            <label htmlFor="register-category" className="sr-only">Category</label>
            <select id="register-category" value={category} onChange={(e) => {
              setCategory(e.target.value);
              setHashQuiet('/ledger/register', { category: e.target.value });
            }}>
              {options.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
          </div>
          <p className="result-count" aria-live="polite">{plural(shown.length, 'agent')}</p>
          <button type="button" className="btn btn--sm btn--ghost" disabled={!shown.length} onClick={() => saveCsv('agentgov-register', REGISTER_CSV, shown)}>
            <Icon name="download" />Download CSV
          </button>
        </div>
        <section className="card" aria-label="Classification register">
          {shown.length ? <RegisterTable rows={shown} /> : <EmptyState title="No agents here" text="Try another category." />}
        </section>
      </div>
    );
  },
};

function RegisterTable({ rows }: { rows: any[] }) {
  const classify = can('approve');
  const heads = ['Agent', 'Category', 'Your role', 'What it is for', 'Classified', ...(classify ? [''] : [])];
  return (
    <div className="table-wrap">
      <table className="data rtable">
        <thead><tr>{heads.map((t, i) => <th key={i} scope="col">{t}</th>)}</tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td data-label="Agent">
                <AgentLink id={r.id} name={r.agent} />
                <div className="cell-sub">{humanize(r.status)}{r.owner ? ` · ${r.owner}` : ''}</div>
              </td>
              <td data-label="Category"><Chip kind="classification" value={r.category || 'none'} /></td>
              <td data-label="Your role">{roleWord(r.role) || <span className="muted">{'—'}</span>}</td>
              <td data-label="What it is for" className="break">
                {r.purpose ? <div className="clamp-2">{r.purpose}</div> : <span className="muted">{'—'}</span>}
                {r.basis ? <div className="cell-sub clamp-2">{r.basis}</div> : null}
              </td>
              <td data-label="Classified" className="nowrap">
                {r.classified_at
                  ? <><TimeEl iso={r.classified_at} /><div className="cell-sub">{(r.classified_by || '').replace(/^[a-z]+:/, '')}</div></>
                  : <span className="muted">Not yet</span>}
              </td>
              {classify ? (
                <td data-label="">
                  {r.status === 'deleted' ? null : (
                    <button type="button" className="btn btn--sm" onClick={guarded(async () => {
                      const agent = { id: r.id, name: r.agent, classification: r.category ? { category: r.category, role: r.role, basis: r.basis, purpose: r.purpose } : null };
                      if (await classifyAgents([agent])) await refresh();
                    })}>{r.category ? 'Change' : 'Classify'}</button>
                  )}
                </td>
              ) : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
