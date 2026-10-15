// The overview: where to start, the key figures, what the gateway's policy decided, the
// agents most at risk, and the control plane's health.

import { Fragment, useId, useRef, useState, type ReactNode } from 'react';
import { ask } from '../components/dialog';
import { Icon } from '../components/Icon';
import { guarded } from '../components/toast';
import {
  AgentLink, Card, Chip, Copyable, EmptyState, PageHead, RefreshButton, TimeEl, TipRow, agentHref, useTooltip, useWidth,
} from '../components/ui';
import { api, getInfo } from '../lib/api';
import { updateBadges } from '../lib/badges';
import { dayFmt, dayLongFmt, fmt, humanize, plural, shortHash } from '../lib/format';
import { refresh, type PageDef } from '../lib/router';
import { can } from '../lib/session';
import { featureSummary } from '../lib/shared';
import { SEVERITY_ORDER, TONE_COLOR, statusMeta, toneOf, type Tone } from '../lib/status';

type Overview = any;
type Feature = any;
interface Day { day: string; tool_calls: number; denied: number; model_calls: number }

interface OverviewData {
  ov: Overview;
  info: any;
  features: Feature[] | null;
  start: any;
  inbox: any;
}

// What the unmanaged agents are: found on platforms, seen in traffic, or both.
function unmanagedNote(all: number, onPlatforms: number): string {
  if (!all) return 'None on your platforms or seen at runtime';
  if (onPlatforms === all) return 'Found on your platforms, not reviewed yet';
  if (!onPlatforms) return 'Seen at runtime, never registered';
  return `${fmt(onPlatforms)} found on your platforms, ${fmt(all - onPlatforms)} seen at runtime`;
}

export const overviewPage: PageDef<OverviewData> = {
  re: /^\/overview$/,
  nav: 'overview',
  title: 'Overview',
  load: async () => {
    const [ov, info, features, start, inbox] = await Promise.all([
      api('v1/overview'), getInfo(), api('v1/features').then((v) => v.features).catch(() => null),
      api('v1/start').catch(() => null), api('v1/inbox').catch(() => null),
    ]);
    // The menu's count of open issues, in step with the figures shown.
    updateBadges({ findings: ov.findings });
    return { ov, info, features, start, inbox };
  },
  View: OverviewView,
};

function OverviewView({ data }: { data: OverviewData }) {
  const { ov, info, features, start, inbox } = data;
  // The gateway's panels once agents may call through it, or have: until then they would
  // show nothing but zeros.
  const gateway = (features || []).some((f) => f.key === 'mcp-gateway' && f.mode !== 'off')
    || (ov.activity || []).some((d: Day) => d.tool_calls || d.model_calls) || (ov.recent_blocks || []).length > 0;
  return (
    <div className="page">
      <PageHead
        title="Overview"
        sub={gateway ? 'Agent inventory, policy decisions and evidence for this control plane.' : 'Your agents, what to look at, and the evidence for this control plane.'}
        actions={[<LedgerBadge key="ledger" lg={ov.ledger} />, <RefreshButton key="refresh" />]}
      />
      <StartCard st={start} />
      <KpiTiles ov={ov} inbox={inbox} />
      {gateway ? (
        <div className="grid-2 grid-2--even">
          <ActivityCard days={ov.activity || []} />
          <DecisionsCard decisions={ov.decisions_24h || {}} />
        </div>
      ) : null}
      {gateway ? (
        <div className="grid-2 grid-2--even">
          <RecentBlocksCard entries={ov.recent_blocks || []} />
          <RiskyCard list={ov.top_risky || []} />
        </div>
      ) : <RiskyCard list={ov.top_risky || []} />}
      <ControlPlaneCard ov={ov} info={info} features={features} gateway={gateway} />
    </div>
  );
}

// Where to look for each place's agents, from the checklist.
const START_LINKS: Record<string, string> = { gateway: '#/agents' };

// Until it is done or hidden: where the organisation's agents are, then each step to a
// first useful day (docs/administration.md#start-here).
function StartCard({ st }: { st: any }) {
  if (!st || st.hidden || st.done) return null;
  const admin = can('admin');
  const choose = guarded(async () => {
    const done = await ask({
      title: 'Where are your agents?',
      text: 'AgentGov turns on what reads these places and turns off what reads the others. Change it here any time.',
      iconName: 'platforms', confirm: 'Save',
      fields: st.choices.map((c: any) => ({ id: c.place, type: 'checkbox', label: c.name, value: st.places.includes(c.place) })),
      submit: (v) => api('v1/start', { method: 'PUT', body: { places: st.choices.map((c: any) => c.place).filter((p: string) => v[p]) } }),
    });
    if (done) await refresh();
  });
  const hide = guarded(async () => {
    await api('v1/start', { method: 'PUT', body: { hidden: true } });
    await refresh();
  });
  if (!st.places.length) {
    return (
      <Card title="Start here" cls="start-card">
        <div className="stack">
          <p>Tell AgentGov where your agents are: Copilot Studio, Microsoft 365, AWS, Google Cloud, Salesforce, Databricks, Microsoft Foundry, or your own agents through its gateway. It turns on only what reads those places.</p>
          {admin ? (
            <div className="btn-row"><button type="button" className="btn btn--primary" onClick={choose}>Where are your agents?</button></div>
          ) : <p className="muted">An administrator answers this.</p>}
        </div>
      </Card>
    );
  }
  const links: Record<string, string> = {
    team: '#/findings/teams', review: '#/agents?status=discovered', owners: '#/agents?owner=none',
  };
  const next = st.steps.find((x: any) => !x.done);
  const rows = st.steps.map((x: any, i: number) => {
    const how = x.key === 'agents' && !x.done ? (
      <ul className="start-how">
        {(x.how || []).map((w: any, j: number) => (
          <li key={j}><a href={START_LINKS[w.place] || '#/platforms'}>{w.name}</a>{`: ${w.how}`}</li>
        ))}
      </ul>
    ) : null;
    const target = links[x.key];
    return (
      <li key={i} className="start-step" data-done={String(x.done)} aria-current={x === next ? 'step' : undefined}>
        <Icon name={x.done ? 'check-circle' : x === next ? 'arrow' : 'minus'} cls={x.done ? 't-good' : x === next ? undefined : 'muted'} />
        <div>
          <strong>{!x.done && target ? <a href={target}>{x.title}</a> : x.title}</strong>
          {x.detail ? <span className="muted">{` · ${x.detail}`}</span> : null}
          {how}
        </div>
      </li>
    );
  });
  return (
    <Card
      title="Start here"
      cls="start-card"
      sub={`${st.steps.filter((x: any) => x.done).length} of ${st.steps.length} done`}
      actions={admin ? [
        <button key="where" type="button" className="btn btn--sm btn--ghost" onClick={choose}>Change where</button>,
        <button key="hide" type="button" className="btn btn--sm btn--ghost" onClick={hide}>Hide</button>,
      ] : null}
    >
      <ol className="start-steps">{rows}</ol>
    </Card>
  );
}

function LedgerBadge({ lg }: { lg: any }) {
  if (!lg) {
    return (
      <a className="ledger-badge" data-tone="neutral" href="#/ledger">
        <Icon name="ledger" /><span><strong>Ledger not checked</strong>{' · verify it on the Ledger page'}</span>
      </a>
    );
  }
  if (lg.valid) {
    return (
      <a className="ledger-badge" data-tone="good" href="#/ledger" title={`Chain head ${lg.head}`}>
        <Icon name="shield-check" />
        <span>
          <strong>Ledger intact</strong>{` · ${plural(lg.checked, 'entry', 'entries')} · `}
          <span className="hash">{shortHash(lg.head, 6, 4)}</span>
        </span>
      </a>
    );
  }
  return (
    <a className="ledger-badge" data-tone="critical" href="#/ledger">
      <Icon name="octagon" /><span><strong>{`Ledger broken at #${lg.broken_at}`}</strong>{` · ${lg.problem}`}</span>
    </a>
  );
}

// What waits for a decision, in a few words: the kinds with the most first.
const INBOX_WORDS: Record<string, [one: string, many: string]> = {
  calls: ['held call', 'held calls'],
  access: ['access request', 'access requests'],
  risks: ['risk to accept', 'risks to accept'],
  agents: ['agent to approve', 'agents to approve'],
  toolservers: ['tool server to approve', 'tool servers to approve'],
  definitions: ['changed tool', 'changed tools'],
  platform_agents: ['agent found on a platform', 'agents found on platforms'],
};

function inboxNote(inbox: any): string {
  const parts = inbox.kinds.filter((k: any) => k.count).sort((a: any, b: any) => b.count - a.count)
    .map((k: any) => {
      const [one, many] = INBOX_WORDS[k.kind] || [k.title, k.title];
      return plural(k.count, one, many);
    });
  return parts.length > 2 ? `${parts.slice(0, 2).join(' · ')} · more` : parts.join(' · ');
}

interface Tile { label: string; value: number | null | undefined; note: ReactNode; href: string; tone?: Tone | null }

function KpiTiles({ ov, inbox = null }: { ov: Overview; inbox?: any }) {
  const agents = ov.agents || {};
  const findings = ov.findings || {};
  const byStatus = agents.by_status || {};
  const statusNote = ['active', 'pending', 'blocked', 'discovered']
    .filter((k) => byStatus[k]).map((k) => `${fmt(byStatus[k])} ${statusMeta('agent', k)[2].toLowerCase()}`).join(' · ') || 'No agents registered yet';
  const bySev = findings.by_severity || {};
  const topSeverity = SEVERITY_ORDER.find((k) => bySev[k]);
  const sevNote = SEVERITY_ORDER.filter((k) => bySev[k]).map((k) => {
    const [tone, ic, label] = statusMeta('severity', k);
    return <span key={k} className="sev-count"><Icon name={ic} cls={`t-${tone}`} />{`${fmt(bySev[k])} ${label.toLowerCase()}`}</span>;
  });
  // Everything waiting for a decision of the signed-in person's, else the held calls.
  const pending = inbox ? inbox.total : ov.approvals?.pending ?? 0;
  const waitingNote = !pending ? 'Nothing waiting for a decision'
    : inbox ? inboxNote(inbox) : 'Tool calls waiting for a decision';
  const tiles: Tile[] = [
    { label: 'Total agents', value: agents.total, note: statusNote, href: '#/agents' },
    {
      label: 'Agents without owners', value: agents.without_owner, href: '#/agents?owner=none',
      note: agents.without_owner ? 'Assign an owning team or person' : 'Every agent has an owner',
      tone: agents.without_owner ? 'warning' : null,
    },
    {
      label: 'Unmanaged agents', value: agents.unmanaged, href: '#/agents?status=discovered',
      note: unmanagedNote(agents.unmanaged || 0, agents.on_platforms || 0),
      // Agents seen acting outside governance are serious; found on a platform, to review.
      tone: agents.unmanaged > (agents.on_platforms || 0) ? 'serious' : agents.unmanaged ? 'warning' : null,
    },
    {
      label: 'Agents at risk', value: agents.at_risk, href: '#/agents?risk=elevated',
      note: 'High or critical risk score', tone: agents.at_risk ? 'serious' : null,
    },
    {
      label: 'Waiting for a decision', value: pending, href: '#/approvals',
      note: waitingNote, tone: pending ? 'warning' : null,
    },
    {
      label: 'Open issues', value: findings.open, href: '#/findings',
      note: sevNote.length ? sevNote : 'No open issues', tone: topSeverity ? toneOf('severity', topSeverity) : null,
    },
  ];
  const flags: Record<string, string> = { warning: 'alert-circle', serious: 'triangle', critical: 'octagon' };
  return (
    <section className="kpis" aria-label="Key figures">
      {tiles.map((t) => {
        const tone = t.tone === 'neutral' ? null : t.tone;
        return (
          <a key={t.label} className="kpi" href={t.href} data-tone={tone || undefined}>
            <span className="kpi-label">{t.label}</span>
            {tone ? <span className="kpi-flag"><Icon name={flags[tone] || 'info'} label="Needs attention" /></span> : null}
            <span className="kpi-value">{fmt(t.value ?? 0)}</span>
            <span className="kpi-note">{t.note}</span>
          </a>
        );
      })}
    </section>
  );
}

function niceScale(max: number, ticks = 4): { top: number; step: number } {
  if (max <= 0) return { top: 4, step: 1 };
  const raw = max / ticks;
  const mag = Math.max(1, 10 ** Math.floor(Math.log10(raw)));
  const step = [1, 2, 5, 10].map((f) => f * mag).find((st) => st >= raw) || mag * 10;
  return { top: Math.ceil(max / step) * step, step };
}

function barPath(x: number, y: number, w: number, height: number, r: number): string {
  if (height <= 0) return '';
  const rr = Math.min(r, w / 2, height);
  return `M${x},${y + height}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + height}Z`;
}

function ActivityChart({ days }: { days: Day[] }) {
  const box = useRef<HTMLDivElement>(null);
  const width = useWidth(box);
  const tip = useTooltip(box);
  const [active, setActive] = useState(-1);
  // The day shown, as the handlers read it: at once, whether or not the chart has been drawn
  // again since (several events can come between two renders).
  const shown = useRef(-1);
  const [live, setLive] = useState('');
  // The day the hover band was last moved to, and the width the chart was drawn at: hidden,
  // the band stays where it was until the chart is drawn again.
  const [hover, setHover] = useState({ at: -1, width: 0 });
  const totals = days.reduce((acc, d) => ({ calls: acc.calls + d.tool_calls, denied: acc.denied + d.denied }), { calls: 0, denied: 0 });

  const height = 214;
  const m = { t: 22, r: 6, b: 26, l: 36 };
  const pw = Math.max(40, width - m.l - m.r);
  const ph = height - m.t - m.b;
  const peak = Math.max(0, ...days.map((d) => d.tool_calls));
  const { top, step } = niceScale(peak);
  const y = (v: number) => m.t + ph - (v / top) * ph;
  const band = pw / Math.max(1, days.length);
  const bw = Math.min(24, Math.max(4, band * 0.6));

  const showTip = (i: number) => {
    const d = days[i];
    const date = new Date(`${d.day}T00:00:00Z`);
    tip.show(
      <>
        <div className="tooltip-title">{dayLongFmt.format(date)}</div>
        <TipRow color="var(--chart-context)" value={d.tool_calls} label={d.tool_calls === 1 ? 'tool call' : 'tool calls'} />
        <TipRow color="var(--critical)" value={d.denied} label="denied" />
        <TipRow color={null} value={d.model_calls} label={d.model_calls === 1 ? 'model call' : 'model calls'} />
      </>,
      m.l + band * i + band / 2, y(d.tool_calls),
    );
    return date;
  };

  // Drawn again, at a new width: the band back at the start, or at the day shown.
  if (hover.width !== width) {
    setHover({ at: active, width });
    if (width && days[active]) showTip(active);
  }

  const show = (i: number) => {
    if (!width || !days[i]) return;
    shown.current = i;
    setActive(i);
    setHover({ at: i, width });
    const d = days[i];
    const date = showTip(i);
    setLive(`${dayLongFmt.format(date)}: ${plural(d.tool_calls, 'tool call')}, ${fmt(d.denied)} denied.`);
  };

  const hide = () => {
    shown.current = -1;
    setActive(-1);
    tip.hide();
  };

  let svg = null;
  if (width) {
    const ticks: number[] = [];
    for (let v = 0; v <= top; v += step) ticks.push(v);
    let peakIndex = -1;
    days.forEach((d, i) => {
      if (d.tool_calls > 0 && d.tool_calls >= (days[peakIndex]?.tool_calls ?? 0)) peakIndex = i;
    });
    const every = band < 34 ? 2 : 1;
    let prevMonth: number | null = null;
    const base = y(0);
    svg = (
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true" focusable="false">
        <rect x={hover.at >= 0 ? m.l + band * hover.at : m.l} y={m.t - 4} width={band} height={ph + 4} rx={4}
          style={{ fill: 'var(--chart-hover)' }} visibility={active >= 0 ? 'visible' : 'hidden'} />
        {ticks.map((v) => {
          const yy = Math.round(y(v)) + 0.5;
          return (
            <Fragment key={v}>
              <line x1={m.l} x2={width - m.r} y1={yy} y2={yy} style={{ stroke: `var(${v === 0 ? '--chart-axis' : '--chart-grid'})`, strokeWidth: 1 }} />
              <text x={m.l - 8} y={yy + 4} textAnchor="end" className="axis-label">{fmt(v)}</text>
            </Fragment>
          );
        })}
        {days.map((d, i) => {
          const x = m.l + band * i + (band - bw) / 2;
          const calls = d.tool_calls;
          const denied = Math.min(d.denied, calls);
          const marks: ReactNode[] = [];
          if (calls > 0) {
            const yt = y(calls);
            if (denied > 0) {
              const yd = y(denied);
              const all = denied >= calls;
              marks.push(<path key="denied" d={barPath(x, yd, bw, base - yd, all ? 4 : 0)} style={{ fill: 'var(--critical)' }} />);
              const gapBottom = yd - 2; // 2px surface gap between the stacked segments
              if (!all && gapBottom - yt > 0.5) marks.push(<path key="calls" d={barPath(x, yt, bw, gapBottom - yt, 4)} style={{ fill: 'var(--chart-context)' }} />);
            } else {
              marks.push(<path key="calls" d={barPath(x, yt, bw, base - yt, 4)} style={{ fill: 'var(--chart-context)' }} />);
            }
          }
          if ((days.length - 1 - i) % every === 0) {
            const date = new Date(`${d.day}T00:00:00Z`);
            const month = date.getUTCMonth();
            const label = month !== prevMonth ? dayFmt.format(date) : String(date.getUTCDate());
            prevMonth = month;
            marks.push(<text key="day" x={m.l + band * i + band / 2} y={height - 8} textAnchor="middle" className="axis-label">{label}</text>);
          }
          return <Fragment key={d.day}>{marks}</Fragment>;
        })}
        {peakIndex >= 0 ? (
          <text x={m.l + band * peakIndex + band / 2} y={y(days[peakIndex].tool_calls) - 7} textAnchor="middle" className="data-label">
            {fmt(days[peakIndex].tool_calls)}
          </text>
        ) : (
          <text x={m.l + pw / 2} y={m.t + ph / 2} textAnchor="middle" className="chart-note">No tool calls in the last 14 days</text>
        )}
      </svg>
    );
  }

  return (
    <div
      ref={box}
      className="chart"
      tabIndex={0}
      role="group"
      aria-label={`Tool calls per day for the last 14 days: ${plural(totals.calls, 'call')}, ${fmt(totals.denied)} denied. Use the left and right arrow keys to read each day.`}
      onPointerMove={(e) => {
        if (!width) return;
        const rect = e.currentTarget.getBoundingClientRect();
        const i = Math.floor((e.clientX - rect.left - m.l) / band);
        if (i >= 0 && i < days.length) {
          if (i !== shown.current) show(i);
        } else hide();
      }}
      onPointerLeave={() => {
        if (document.activeElement !== box.current) hide();
      }}
      onFocus={() => show(shown.current >= 0 ? shown.current : days.length - 1)}
      onBlur={hide}
      onKeyDown={(e) => {
        const moves: Record<string, number> = { ArrowLeft: -1, ArrowRight: 1, Home: -Infinity, End: Infinity };
        if (e.key === 'Escape') {
          hide();
          return;
        }
        if (!(e.key in moves)) return;
        e.preventDefault();
        const current = shown.current >= 0 ? shown.current : days.length - 1;
        show(Math.max(0, Math.min(days.length - 1, current + moves[e.key])));
      }}
    >
      {svg}
      {tip.node}
      <p className="sr-only" aria-live="polite">{live}</p>
    </div>
  );
}

function ActivityCard({ days }: { days: Day[] }) {
  const total = days.reduce((sum, d) => sum + d.tool_calls, 0);
  const denied = days.reduce((sum, d) => sum + d.denied, 0);
  const tableId = `activity-table${useId().replace(/:/g, '')}`;
  const [open, setOpen] = useState(false);
  return (
    <Card
      title="Tool calls"
      sub={`Last 14 days, all agents · ${plural(total, 'call')}, ${fmt(denied)} denied`}
      actions={[
        <button key="table" type="button" className="btn btn--sm btn--ghost" aria-expanded={open} aria-controls={tableId} onClick={() => setOpen(!open)}>
          {open ? 'Hide table' : 'Show table'}
        </button>,
      ]}
    >
      <div className="legend" aria-hidden="true">
        <span className="legend-item"><span className="swatch" style={{ background: 'var(--chart-context)' }} />Tool calls</span>
        <span className="legend-item"><span className="swatch" style={{ background: 'var(--critical)' }} />Denied (part of tool calls)</span>
      </div>
      <ActivityChart days={days} />
      <div className="table-wrap chart-table" id={tableId} hidden={!open}>
        <table className="data">
          <caption>Tool calls per day (UTC)</caption>
          <thead>
            <tr>{['Day', 'Tool calls', 'Denied', 'Model calls'].map((t, i) => <th key={t} scope="col" className={i ? 'num' : undefined}>{t}</th>)}</tr>
          </thead>
          <tbody>
            {days.slice().reverse().map((d) => (
              <tr key={d.day}>
                <td>{dayLongFmt.format(new Date(`${d.day}T00:00:00Z`))}</td>
                <td className="num">{fmt(d.tool_calls)}</td>
                <td className="num">{fmt(d.denied)}</td>
                <td className="num">{fmt(d.model_calls)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

const DECISION_META: Record<string, { tone: Tone; icon: string; label: string }> = {
  allow: { tone: 'good', icon: 'check-circle', label: 'Allowed' },
  require_approval: { tone: 'warning', icon: 'user-check', label: 'Held for approval' },
  deny: { tone: 'critical', icon: 'ban', label: 'Denied' },
};

function DecisionsCard({ decisions }: { decisions: Record<string, number> }) {
  const holder = useRef<HTMLDivElement>(null);
  const tip = useTooltip(holder);
  const keys = ['allow', 'require_approval', 'deny', ...Object.keys(decisions).filter((k) => !(k in DECISION_META))];
  const rows = keys.map((key) => {
    const meta = DECISION_META[key] || { tone: 'neutral' as Tone, icon: 'minus', label: key === 'none' ? 'No effect recorded' : humanize(key) };
    return { key, count: decisions[key] || 0, ...meta, color: TONE_COLOR[meta.tone] };
  });
  const total = rows.reduce((sum, r) => sum + r.count, 0);
  const pct = (n: number) => `${total ? Math.round((n / total) * 100) : 0}%`;
  let body;
  if (!total) {
    body = <EmptyState title="No decisions in the last 24 hours" text="Policy decisions appear here as agents call tools through the gateway." />;
  } else {
    body = (
      <>
        <div><div className="hero-figure">{fmt(total)}</div><p className="hero-caption">tool calls decided by policy</p></div>
        <div ref={holder} className="chart">
          <div className="splitbar" role="img" aria-label={rows.map((r) => `${r.label}: ${r.count}`).join(', ')}>
            {rows.filter((r) => r.count).map((r) => (
              <span
                key={r.key}
                style={{ flex: `${r.count} 1 0px`, background: r.color }}
                onPointerEnter={(e) => {
                  const seg = e.currentTarget;
                  tip.show(<TipRow color={r.color} value={r.count} label={`${r.label.toLowerCase()} · ${pct(r.count)}`} />, seg.offsetLeft + seg.offsetWidth / 2, 0);
                }}
                onPointerLeave={() => tip.hide()}
              />
            ))}
          </div>
          {tip.node}
        </div>
        <ul className="split-legend" role="list">
          {rows.map((r) => (
            <li key={r.key}>
              <Icon name={r.icon} cls={`t-${r.tone}`} /><span>{r.label}</span>
              <span className="count">{fmt(r.count)}</span><span className="pct">{pct(r.count)}</span>
            </li>
          ))}
        </ul>
      </>
    );
  }
  return <Card title="Decisions" sub="Last 24 hours">{body}</Card>;
}

function RecentBlocksCard({ entries }: { entries: any[] }) {
  // The ledger records both the approval request and the gateway decision for one held call.
  const seen = new Set();
  const items = entries.filter((e) => {
    const key = e.details?.approval_id;
    if (!key) return true;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 6);
  const body = items.length ? (
    <ul className="feed" role="list">
      {items.map((e) => (
        <li key={e.seq}>
          <div className="feed-top">
            <Chip kind="decision" value={e.decision} />
            <span className="resource">{e.resource || e.type}</span>
            {e.agent_name ? <AgentLink id={e.agent_id} name={e.agent_name} /> : null}
            <span className="feed-meta"><TimeEl iso={e.ts} /></span>
          </div>
          {e.reason ? <p className="feed-reason clamp-2">{e.reason}</p> : null}
        </li>
      ))}
    </ul>
  ) : <EmptyState title="No blocked calls yet" text="Denied calls and calls held for approval show up here." />;
  return (
    <Card
      title="Recent blocks"
      sub="Latest denied calls and calls held for approval"
      actions={[<a key="ledger" className="btn btn--sm btn--ghost" href="#/ledger?decision=deny">Open ledger<Icon name="arrow" /></a>]}
      flush={Boolean(items.length)}
    >
      {body}
    </Card>
  );
}

function RiskyCard({ list }: { list: any[] }) {
  const body = list.length ? (
    <ul className="risk-list" role="list">
      {list.map((a) => {
        const tone = toneOf('risk', a.risk_level);
        return (
          <li key={a.id}>
            <a href={agentHref(a.id)} className="cell-title break">{a.name}</a>
            <Chip kind="risk" value={a.risk_level} extra={a.risk_score} />
            <div className="meter" role="img" aria-label={`Risk score ${a.risk_score} of 100`} style={{ background: `var(--${tone}-tint)` }}>
              <span style={{ width: `${Math.min(100, a.risk_score)}%`, background: TONE_COLOR[tone] }} />
            </div>
          </li>
        );
      })}
    </ul>
  ) : <EmptyState title="No agents at risk" text="No agent has a high or critical risk score right now." />;
  return (
    <Card
      title="Agents at risk"
      sub="Highest risk scores first (out of 100)"
      actions={[<a key="all" className="btn btn--sm btn--ghost" href="#/agents?risk=elevated">View all<Icon name="arrow" /></a>]}
      flush={Boolean(list.length)}
    >
      {body}
    </Card>
  );
}

function ControlPlaneCard({ ov, info, features, gateway = true }: { ov: Overview; info: any; features: Feature[] | null; gateway?: boolean }) {
  const ts = ov.toolservers || {};
  const cell = (title: string, value: ReactNode, note: ReactNode, href?: string) => (
    <div>
      <span className="cp-title">{title}</span>
      {href ? <a className="cp-value" href={href}>{value}</a> : <span className="cp-value">{value}</span>}
      {note ? <span className="small muted">{note}</span> : null}
    </div>
  );
  return (
    <section className="card" aria-labelledby="cp-title">
      <div className="card-head">
        <div className="card-head-text">
          <h2 id="cp-title">Control plane</h2>
          <p className="card-sub">Where policy is enforced and evidence is kept</p>
        </div>
      </div>
      <div className="cp-grid" style={{ marginTop: 12, borderTop: '1px solid var(--line)' }}>
        {/* Tool servers and the gateway, once agents may call through it. */}
        {gateway ? cell('Tool servers', plural(ts.total || 0, 'server'),
          `${plural(ts.tools || 0, 'tool')} in catalogs · ${fmt(ts.pending)} pending · ${fmt(ts.blocked)} blocked`, '#/toolservers') : null}
        {cell('Policy bundle', ov.opa?.bundle_revision
          ? <span className="hash" title={`Bundle revision ${ov.opa.bundle_revision}`}>{`rev ${String(ov.opa.bundle_revision).slice(0, 12)}`}</span>
          : 'Not built',
        opaNote(ov.opa))}
        {cell('Replicas', replicasValue(ov.replicas), replicasNote(ov.replicas))}
        {cell('Evidence ledger', ov.ledger ? plural(ov.ledger.checked, 'entry', 'entries') : 'Not verified',
          ov.witness?.rewound
            ? <span style={{ color: 'var(--critical-ink)' }}>Entries are missing: the database was restored</span>
            : ov.ledger?.head ? <>{'Head '}<span className="hash" title={ov.ledger.head}>{shortHash(ov.ledger.head)}</span></> : null, '#/ledger')}
        {gateway ? cell('Gateway', info?.gateway_url ? <Copyable text={info.gateway_url} label="gateway URL" /> : 'Not configured',
          features ? (
            <>
              {features.find((f) => f.key === 'unknown-callers')?.mode === 'monitor' ? 'Unknown callers let through' : 'Unknown callers refused'}
              {' · '}<a href="#/features">{featureSummary(features)}</a>
            </>
          ) : null)
          : cell('Features', features ? <a href="#/features">{featureSummary(features)}</a> : 'Unknown', 'No gateway: AgentGov reads your platforms')}
      </div>
    </section>
  );
}

// The control plane's replicas, and the one that runs the scheduled work.
function replicasValue(replicas: any[] | null | undefined): string {
  return replicas?.length ? plural(replicas.length, 'replica') : 'Unknown';
}

function replicasNote(replicas: any[] | null | undefined): ReactNode {
  if (!replicas?.length) return null;
  if (replicas[0].database === 'sqlite') return 'One process, on SQLite';
  const leader = replicas.find((r) => r.leader);
  // The replica answering has lost its connection for hearing the others' changes.
  const apart = replicas.some((r) => r.this && r.listening === false);
  return (
    <>
      {leader ? <>{'Leader '}<code>{leader.name}</code></> : 'No leader at the moment'}
      {apart ? <span className="tone-text-warning">{' · this replica is out of touch with the others'}</span> : null}
    </>
  );
}

// When the OPA instances last reported, and whether they all run the current bundle.
function opaNote(opa: any): ReactNode {
  const instances: any[] = opa?.instances || [];
  if (!opa?.last_status_at) return 'No OPA instance has reported yet';
  const behind = instances.filter((i) => i.revision && i.revision !== opa.bundle_revision).length;
  return (
    <>
      {instances.length > 1 ? `${instances.length} OPA instances; the last reported ` : 'OPA reported '}
      <TimeEl iso={opa.last_status_at} />
      {behind ? <span className="tone-text-warning">{` · ${plural(behind, 'instance')} on an earlier bundle`}</span> : null}
    </>
  );
}
