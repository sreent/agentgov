// What AgentGov does towards each control of a framework, how far it is set up, and the
// evidence it holds; and the ledger's checkpoints and retention.

import { Icon } from '../components/Icon';
import { guarded, toast } from '../components/toast';
import { Callout, Card, Chip, EmptyState, Facts, PageHead, PlainChip, TimeEl } from '../components/ui';
import { api, saveDownload } from '../lib/api';
import { fileStamp, fmt, fmtBytes, plural, shortHash } from '../lib/format';
import { refresh, type PageDef } from '../lib/router';
import { can } from '../lib/session';
import { TONE_COLOR, type Tone } from '../lib/status';
import { LedgerTabs } from './ledger';

const COMPLIANCE_PERIODS: [number, string][] = [[30, 'Last 30 days'], [90, 'Last 90 days'], [365, 'Last year']];

interface ComplianceData { frameworks: any[]; framework: string; days: number; report: any }

export const compliancePage: PageDef<ComplianceData> = {
  re: /^\/ledger\/compliance$/,
  nav: 'compliance',
  title: 'Compliance',
  load: async ({ params }) => {
    const frameworks = await api<any[]>('v1/evidence/frameworks');
    const framework = frameworks.some((f) => f.key === params.get('framework')) ? params.get('framework')! : frameworks[0].key;
    const days = Number(params.get('days')) || 90;
    const report = await api(`v1/evidence/report?framework=${encodeURIComponent(framework)}&days=${days}`);
    return { frameworks, framework, days, report };
  },
  View: ({ data: { frameworks, framework, days, report } }) => {
    const go = (f: string, d: number) => {
      window.location.hash = `#/ledger/compliance?framework=${encodeURIComponent(f)}&days=${d}`;
    };
    const pack = guarded(async () => {
      const blob = await saveDownload(`v1/evidence/pack?days=${days}`, `agentgov-evidence-${fileStamp()}.zip`);
      toast(`Downloaded the evidence pack (${fmtBytes(blob.size)}).`);
    });
    const l = report.ledger;
    const counts = Object.entries(report.summary as Record<string, number>).filter(([, n]) => n);
    return (
      <div className="page">
        <PageHead
          title="Compliance"
          sub="What AgentGov does towards each control, how far it is set up here, and the evidence it holds. It doesn’t say that your organisation complies: that is for its assessors, and the evidence pack is for them."
          actions={[<button key="pack" type="button" className="btn btn--primary" onClick={pack}><Icon name="download" />Evidence pack</button>]}
        />
        <LedgerTabs current="compliance" />
        <div className="filters">
          <div className="field">
            <label htmlFor="compliance-framework">Framework</label>
            <select id="compliance-framework" value={framework} onChange={(e) => go(e.target.value, days)}>
              {frameworks.map((f) => <option key={f.key} value={f.key}>{f.title}</option>)}
            </select>
          </div>
          <div className="field" style={{ flex: '0 1 200px' }}>
            <label htmlFor="compliance-days">Period</label>
            <select id="compliance-days" value={days} onChange={(e) => go(framework, Number(e.target.value))}>
              {COMPLIANCE_PERIODS.map(([d, label]) => <option key={d} value={d}>{label}</option>)}
            </select>
          </div>
        </div>
        <Callout tone="neutral" icon="info">
          <span>{report.framework.note}{' '}<a href={report.framework.url} target="_blank" rel="noopener">The framework</a>.</span>
        </Callout>
        <div className="chip-row">{counts.map(([status, n]) => <Chip key={status} kind="compliance" value={status} extra={n} />)}</div>
        <p className="muted">
          {l.valid
            ? `The ledger verifies: ${plural(l.checked - (l.from || 0), 'entry', 'entries')} in the database; ${plural(l.checkpoints, 'checkpoint')}, ${fmt(l.timestamped)} time-stamped${l.last_timestamp ? ` (last on ${l.last_timestamp.slice(0, 10)})` : ''}.`
            : 'The ledger’s chain is broken: see the Entries tab.'}
        </p>
        <CoverageCard c={report.coverage} />
        <div className="bp-grid">{report.controls.map((c: any) => <ComplianceCard key={c.id} c={c} />)}</div>
      </div>
    );
  },
};

// What AgentGov saw of the agents in the period, each counted once by the most it saw.
const COVERAGE: [key: string, label: string, tone: Tone, icon: string][] = [
  ['calls_checked', 'Calls checked by AgentGov', 'good', 'shield-check'],
  ['activity_only', 'Seen at work, calls not checked', 'warning', 'eye'],
  ['inventory_only', 'In their platform’s inventory only', 'neutral', 'platforms'],
  ['not_seen', 'Not seen', 'critical', 'alert-circle'],
];

function CoverageCard({ c }: { c: any }) {
  if (!c) return null;
  if (!c.agents) {
    return (
      <Card title="What AgentGov saw">
        <EmptyState title="No agents yet" text="Register agents, or connect the platforms they run on." />
      </Card>
    );
  }
  const rows = COVERAGE.map(([key, label, tone, iconName]) => ({ label, tone, iconName, count: c[key] || 0, color: TONE_COLOR[tone] }));
  const pct = (n: number) => `${Math.round((n / c.agents) * 100)}%`;
  const more = c.not_seen - (c.not_seen_names || []).length;
  return (
    <Card title="What AgentGov saw" sub="In the period. A control only works for the agents AgentGov sees: the rest of this report is about them.">
      <div><div className="hero-figure">{fmt(c.agents)}</div><p className="hero-caption">agents in the inventory</p></div>
      <div className="chart">
        <div className="splitbar" role="img" aria-label={rows.map((r) => `${r.label}: ${r.count}`).join(', ')}>
          {rows.filter((r) => r.count).map((r) => <span key={r.label} style={{ flex: `${r.count} 1 0px`, background: r.color }} title={`${r.label}: ${fmt(r.count)}`} />)}
        </div>
      </div>
      <ul className="split-legend" role="list">
        {rows.map((r) => (
          <li key={r.label}>
            <Icon name={r.iconName} cls={`t-${r.tone}`} /><span>{r.label}</span>
            <span className="count">{fmt(r.count)}</span><span className="pct">{pct(r.count)}</span>
          </li>
        ))}
      </ul>
      {c.not_seen ? (
        <p className="small"><strong>Not seen: </strong>{(c.not_seen_names || []).join(', ')}{more > 0 ? ` and ${fmt(more)} more` : ''}.</p>
      ) : null}
      {c.platforms_not_read?.length ? (
        <Callout tone="warning" icon="triangle">
          {`Not read in the period, or the last read failed: ${c.platforms_not_read.join(', ')}. What AgentGov holds about their agents may be out of date.`}
        </Callout>
      ) : null}
    </Card>
  );
}

function ComplianceCard({ c }: { c: any }) {
  const value = (e: any) => (e.link ? <a href={e.link}>{String(e.value)}</a> : String(e.value));
  return (
    <Card title={`${c.id} ${c.title}`} level="h3" sub={c.asks} actions={[<Chip key="status" kind="compliance" value={c.status} />]}>
      <p>{c.agentgov}</p>
      {c.evidence.length ? <Facts rows={c.evidence.map((e: any) => [e.label, value(e)])} /> : null}
      {c.gaps.length ? (
        <Callout tone={c.status === 'attention' ? 'critical' : 'warning'} icon="triangle">
          <div>{c.gaps.map((g: string, i: number) => <div key={i}>{g}</div>)}</div>
        </Callout>
      ) : null}
    </Card>
  );
}

// Checkpoints of the chain, their time-stamps and archives, and how long things are kept.
export function CheckpointsCard({ kept, points }: { kept: any; points: any[] }) {
  const make = guarded(async () => {
    const point = await api('v1/ledger/checkpoints', { method: 'POST' });
    const done = [point.timestamped ? 'time-stamped' : null, point.log?.logged ? 'in the transparency log' : null].filter(Boolean);
    toast(`Checkpoint at entry #${fmt(point.seq)}${done.length ? `, ${done.join(' and ')}` : ''}.`);
    await refresh();
  });
  const stamp = (c: any) => {
    if (c.timestamped) {
      return (
        <span>
          <PlainChip text="Time-stamped" tone="good" iconName="shield-check" />{' '}<TimeEl iso={c.timestamped_at} />{' '}
          <button type="button" className="btn btn--sm btn--ghost"
            onClick={guarded(async () => { await saveDownload(`v1/ledger/checkpoints/${c.seq}/timestamp`, `checkpoint-${c.seq}.tsr`); })}>
            <Icon name="download" />Time-stamp
          </button>
        </span>
      );
    }
    if (c.timestamp_error) return <PlainChip text="Not time-stamped" tone="warning" iconName="triangle" title={c.timestamp_error} />;
    return <span className="muted">{kept.tsa_url ? 'Waiting for its time-stamp' : 'Not time-stamped'}</span>;
  };
  // Its entry in the transparency log: where, whether its proof was checked, and the
  // Sigstore bundle that checks it offline.
  const logged = (c: any) => {
    const log = c.log || {};
    if (log.logged) {
      const [tone, label] = log.checked === false ? ['warning', 'Logged, proof failed']
        : log.checked ? ['good', `In the log, #${fmt(log.index)}`] : [null, `In the log, #${fmt(log.index)} (unchecked)`];
      return (
        <span>
          <PlainChip text={label} tone={tone} iconName={log.checked === false ? 'triangle' : 'shield-check'} title={log.error || log.url} />{' '}
          <button type="button" className="btn btn--sm btn--ghost"
            onClick={guarded(async () => { await saveDownload(`v1/ledger/checkpoints/${c.seq}/log-entry`, `checkpoint-${c.seq}.sigstore.json`); })}>
            <Icon name="download" />Log entry
          </button>
        </span>
      );
    }
    if (log.error) return <PlainChip text="Not in the log" tone="warning" iconName="triangle" title={log.error} />;
    return kept.rekor_url ? <span className="muted">Waiting for the log</span> : null;
  };
  return (
    <Card
      title="Checkpoints and retention"
      sub="Points of the chain kept for good, time-stamped by an authority and added to a transparency log when they are set; what leaves the database is archived first."
      actions={can('admin') ? [<button key="make" type="button" className="btn btn--sm" onClick={make}><Icon name="plus" />Make a checkpoint</button>] : null}
    >
      <Facts rows={[
        ['Ledger', kept.ledger_retention_days ? `${plural(kept.ledger_retention_days, 'day')} in the database, then archived` : 'Every entry kept in the database'],
        ['Chain in the database', kept.chain_from ? `From the checkpoint at entry #${fmt(kept.chain_from)}` : 'From the genesis entry'],
        ['Checkpoints', kept.checkpoint_hours ? `Every ${plural(kept.checkpoint_hours, 'hour')}` : 'On demand'],
        ['Time-stamping authority', kept.tsa_url ? (
          <span>
            <code>{kept.tsa_url}</code>
            {kept.tsa_ca
              ? ' · its signature checked against its certificates'
              : <span className="muted"> · its certificates not given (AGENTGOV_LEDGER_TSA_CA_FILE): each time-stamp is checked against the one it carries</span>}
          </span>
        ) : <span className="muted">None</span>],
        ['Head kept outside the database', kept.witness_file
          ? <code>{kept.witness_file}</code>
          : <span className="muted">Nowhere: a database restored from an older backup goes unnoticed (AGENTGOV_LEDGER_WITNESS_FILE)</span>],
        ['Transparency log', kept.rekor_url ? <code>{kept.rekor_url}</code> : <span className="muted">None</span>],
        ['Operational records', kept.data_retention_days ? `${plural(kept.data_retention_days, 'day')}` : 'Kept'],
      ]} />
      {points.length ? (
        <ul className="access-list" role="list">
          {points.map((c) => (
            <li key={c.seq} className="access-row">
              <div className="access-main">
                <div className="cell-title">{`Entry #${fmt(c.seq)} `}<code className="hash" title={c.hash}>{shortHash(c.hash)}</code></div>
                <div className="cell-sub break">
                  Kept <TimeEl iso={c.created_at} />
                  {c.archive ? <>{' · entries '}{fmt(c.archived_from)}–{fmt(c.seq)}{' archived to '}<code>{c.archive}</code></> : ''}
                </div>
              </div>
              <div className="stack" style={{ gap: 4 }}>{stamp(c)}{logged(c)}</div>
            </li>
          ))}
        </ul>
      ) : <EmptyState title="No checkpoints yet" text="The first is kept within the hour." />}
    </Card>
  );
}
