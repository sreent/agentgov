// The agent map: who is accountable for each agent, and which tool servers and other agents
// each agent can reach or has used in the last 30 days; and the same graph as a table.

import { useEffect, useMemo, useRef, useState, type CSSProperties, type Dispatch, type ReactNode, type SetStateAction } from 'react';
import { Icon } from '../components/Icon';
import { AgentLink, Card, Chip, EmptyState, Facts, PageHead, PlainChip, RefreshButton, agentHref, useWidth } from '../components/ui';
import { api } from '../lib/api';
import { countBy, cx, fmt, humanize, initials, plural } from '../lib/format';
import type { PageDef } from '../lib/router';
import { TONE_COLOR, statusMeta, toneOf, type Tone } from '../lib/status';

interface MapNode {
  id: string;
  kind: string;
  label: string;
  status?: string;
  risk_level?: string | null;
  blueprint?: string | null;
  classification?: string | null;
  trust?: string | null;
  // Its row in its column.
  slot: number;
}
interface MapEdge { from: string; to: string; kind: string; calls?: number; denied?: number }
interface Graph { nodes?: Omit<MapNode, 'slot'>[]; edges?: MapEdge[] }
type Column = 'person' | 'agent' | 'server';
interface Model {
  nodes: Map<string, MapNode>;
  edges: MapEdge[];
  cols: Record<Column, MapNode[]>;
  maxLen: number;
  neighbours: Map<string, string[]>;
}
// The node pointed at or focused (preview), and the one selected (pinned).
interface MapFocus { preview: string | null; pinned: string | null }

// Edges that count calls: agents' use of tool servers, and agents calling other agents.
const USAGE_EDGES = new Set(['granted', 'ungranted', 'calls', 'calls-ungranted']);
const isUsage = (e: MapEdge) => USAGE_EDGES.has(e.kind);
const isAgentCall = (e: MapEdge) => e.kind === 'calls' || e.kind === 'calls-ungranted';
const isUngranted = (e: MapEdge) => e.kind === 'ungranted' || e.kind === 'calls-ungranted';

function buildGraph(graph: Graph): Model {
  const nodes = new Map<string, MapNode>((graph.nodes || []).map((n) => [n.id, { ...n, slot: 0 }]));
  const edges = (graph.edges || []).filter((e) => nodes.has(e.from) && nodes.has(e.to));
  const cols: Record<Column, MapNode[]> = { person: [], agent: [], server: [] };
  for (const n of nodes.values()) (cols[n.kind as Column] || cols.agent).push(n);
  const statusRank: Record<string, number> = { active: 0, pending: 1, blocked: 2, discovered: 3 };
  const byLabel = (x: MapNode, y: MapNode) => String(x.label).localeCompare(String(y.label));
  cols.agent.sort((x, y) => (statusRank[x.status!] ?? 9) - (statusRank[y.status!] ?? 9) || byLabel(x, y));
  cols.person.sort(byLabel);
  cols.server.sort(byLabel);
  const maxLen = Math.max(1, cols.person.length, cols.agent.length, cols.server.length);
  const place = () => {
    for (const list of Object.values(cols)) list.forEach((n, i) => { n.slot = (maxLen - list.length) / 2 + i; });
  };
  place();
  const neighbours = new Map<string, string[]>();
  for (const e of edges) {
    if (!neighbours.has(e.from)) neighbours.set(e.from, []);
    if (!neighbours.has(e.to)) neighbours.set(e.to, []);
    neighbours.get(e.from)!.push(e.to);
    neighbours.get(e.to)!.push(e.from);
  }
  const bary = (n: MapNode) => {
    const ns = neighbours.get(n.id) || [];
    return ns.length ? ns.reduce((sum, id) => sum + nodes.get(id)!.slot, 0) / ns.length : n.slot;
  };
  // Deterministic barycentre sweeps reduce edge crossings without any randomness.
  for (let pass = 0; pass < 4; pass++) {
    for (const kind of ['person', 'server', 'agent'] as Column[]) {
      // Connected nodes first (ordered by barycentre); unconnected ones keep their order at the end.
      cols[kind] = cols[kind]
        .map((n) => [neighbours.has(n.id) ? 0 : 1, bary(n), n.slot, n] as const)
        .sort((x, y) => x[0] - y[0] || x[1] - y[1] || x[2] - y[2])
        .map((x) => x[3]);
      place();
    }
  }
  // Final placement: the longest column fills rows 0..n-1; every other node sits at the
  // average row of its neighbours, pushed down just enough to keep one row between nodes.
  const settle = (list: MapNode[], anchorKinds: string[]) => {
    let prev = -1;
    for (const n of list) {
      const ns = (neighbours.get(n.id) || []).map((id) => nodes.get(id)!).filter((m) => anchorKinds.includes(m.kind));
      const want = ns.length ? ns.reduce((sum, m) => sum + m.slot, 0) / ns.length : prev + 1;
      n.slot = Math.max(want, prev + 1);
      prev = n.slot;
    }
    let next = Infinity;
    for (let i = list.length - 1; i >= 0; i--) {
      list[i].slot = Math.max(0, Math.min(list[i].slot, next - 1));
      next = list[i].slot;
    }
    prev = -1;
    for (const n of list) { n.slot = Math.max(n.slot, prev + 1); prev = n.slot; }
  };
  const kinds: Column[] = ['person', 'agent', 'server'];
  const anchor = kinds.reduce<Column>((best, k) => (cols[k].length > cols[best].length ? k : best), 'agent');
  cols[anchor].forEach((n, i) => { n.slot = i; });
  if (anchor === 'agent') {
    settle(cols.person, ['agent']);
    settle(cols.server, ['agent']);
  } else {
    settle(cols.agent, [anchor]);
    settle(cols[anchor === 'person' ? 'server' : 'person'], ['agent']);
  }
  const rows = Math.max(1, ...Object.values(cols).flat().map((n) => n.slot + 1));
  return { nodes, edges, cols, maxLen: rows, neighbours };
}

function nodeSubLabel(model: Model, n: MapNode): string {
  if (n.kind === 'person') {
    const rel = model.edges.filter((e) => e.from === n.id);
    const owns = rel.filter((e) => e.kind === 'owner').length;
    const sponsors = rel.filter((e) => e.kind === 'sponsor').length;
    return [owns ? `owns ${owns}` : null, sponsors ? `sponsors ${sponsors}` : null].filter(Boolean).join(' · ') || 'person';
  }
  if (n.kind === 'server') {
    const [, , label] = statusMeta('server', n.status);
    return [label.toLowerCase(), n.classification, n.trust === 'unverified' ? 'unverified' : null].filter(Boolean).join(' · ');
  }
  const [, , label] = statusMeta('agent', n.status);
  return `${label.toLowerCase()} · ${n.risk_level || 'low'} risk`;
}

function describeNode(model: Model, n: MapNode): string {
  const kind = ({ person: 'Person', agent: 'Agent', server: 'Tool server' } as Record<string, string>)[n.kind] || 'Node';
  return `${kind} ${n.label}: ${nodeSubLabel(model, n)}`;
}

function bezierPoint(p0: number, p1: number, p2: number, p3: number, t: number): number {
  const u = 1 - t;
  return u * u * u * p0 + 3 * u * u * t * p1 + 3 * u * t * t * p2 + t * t * t * p3;
}

const NODE_H = 46;
const PITCH = 62;
const TOP = 34;
const REL_TEXT: Record<string, string> = {
  owner: 'owns', sponsor: 'sponsors', granted: 'is granted', ungranted: 'used without a grant', calls: 'may call', 'calls-ungranted': 'called without a grant',
};

// The map drawn at a width: where each node, edge and edge's tag goes.
function layout(model: Model, width: number) {
  const W = Math.max(620, width);
  const height = TOP + model.maxLen * PITCH + 2;
  const nodeW = Math.min(210, Math.max(150, Math.floor((W - 8 - 2 * 76) / 3)));
  const xs: Record<string, number> = { person: 4, agent: Math.round((W - nodeW) / 2), server: W - 4 - nodeW };
  const pos = new Map<string, { x: number; y: number }>();
  for (const [kind, list] of Object.entries(model.cols)) {
    for (const n of list) pos.set(n.id, { x: xs[kind], y: TOP + n.slot * PITCH });
  }
  const maxCalls = Math.max(0, ...model.edges.map((e) => e.calls || 0));
  const gap = xs.agent - (xs.person + nodeW);
  const edges = model.edges.map((e) => {
    const a = pos.get(e.from)!;
    const b = pos.get(e.to)!;
    const usage = isUsage(e);
    const widthPx = usage ? (e.calls! > 0 && maxCalls > 0 ? 1.5 + 4.5 * (Math.log1p(e.calls!) / Math.log1p(maxCalls)) : 1.25) : null;
    const from = model.nodes.get(e.from)!;
    const to = model.nodes.get(e.to)!;
    const relText = REL_TEXT[e.kind] || e.kind;
    const tipText = `${from.label} ${relText} ${to.label}${usage ? ` · ${plural(e.calls || 0, 'call')} in 30 days, ${fmt(e.denied || 0)} denied` : ''}`;
    let x1;
    let y1;
    let x2;
    let y2;
    let c1;
    let c2;
    if (isAgentCall(e)) {
      // Both ends in the agent column: an arc out to its left, from the caller's box
      // (upper half) into the called agent's (lower half), with an arrowhead. Calls
      // back the other way bulge further, so the two arcs stay apart.
      const rows = Math.abs(from.slot - to.slot);
      const bulge = Math.min(gap - 12, 20 + 14 * rows + (from.slot > to.slot ? 10 : 0));
      x1 = a.x;
      y1 = a.y + NODE_H / 2 - 7;
      x2 = b.x;
      y2 = b.y + NODE_H / 2 + 7;
      c1 = [x1 - bulge, y1];
      c2 = [x2 - bulge, y2];
    } else {
      x1 = a.x + nodeW;
      y1 = a.y + NODE_H / 2;
      x2 = b.x;
      y2 = b.y + NODE_H / 2;
      const dx = (x2 - x1) / 2;
      c1 = [x1 + dx, y1];
      c2 = [x2 - dx, y2];
    }
    const path = `M${x1},${y1} C${c1[0]},${c1[1]} ${c2[0]},${c2[1]} ${x2},${y2}`;
    let head = null;
    if (isAgentCall(e)) {
      const half = Math.max(4.5, (widthPx || 1.25) + 1.5);
      head = `M${(x2 - half * 1.8).toFixed(1)},${(y2 - half).toFixed(1)} L${x2},${y2} L${(x2 - half * 1.8).toFixed(1)},${(y2 + half).toFixed(1)} Z`;
    }
    let tag = null;
    if (usage && e.calls! > 0) {
      const full = e.denied ? `${fmt(e.calls)} calls · ${fmt(e.denied)} denied` : plural(e.calls!, 'call');
      const text = full.length * 6 + 16 <= gap - 8 ? full : fmt(e.calls);
      const tw = text.length * 6 + 16;
      let px = bezierPoint(x1, c1[0], c2[0], x2, 0.5);
      const py = bezierPoint(y1, c1[1], c2[1], y2, 0.5);
      // An arc's tag stays clear of the agent column.
      if (isAgentCall(e)) px = Math.min(px, x1 - tw / 2 - 4);
      tag = { text, tw, transform: `translate(${px.toFixed(1)},${py.toFixed(1)})` };
    }
    return { e, path, head, tag, tipText, strokeWidth: widthPx ? widthPx.toFixed(2) : null };
  });
  const clip = (t: string, x0: number, px: number) => {
    const max = Math.max(4, Math.floor((nodeW - x0 - 10) / px));
    return t.length > max ? `${t.slice(0, max - 1)}…` : t;
  };
  const ordered = (['person', 'agent', 'server'] as Column[]).flatMap((k) => model.cols[k].slice().sort((x, y) => x.slot - y.slot));
  return { W, height, nodeW, xs, pos, edges, clip, ordered };
}

const nodeOf = (target: EventTarget | null) => (target as Element | null)?.closest?.('.node') as SVGGElement | null;

function MapView({ model, focus, setFocus }: { model: Model; focus: MapFocus; setFocus: Dispatch<SetStateAction<MapFocus>> }) {
  const holder = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const width = useWidth(holder);
  const drawn = useMemo(() => (width ? layout(model, width) : null), [model, width]);
  const id = focus.preview || focus.pinned;
  const related = new Set(id ? [id, ...(model.neighbours.get(id) || [])] : []);
  const isRelated = (e: MapEdge) => Boolean(id) && (e.from === id || e.to === id);

  // The focus is listened for on the svg element itself, as today: Chromium then takes the
  // svg for focusable (Tab stops on it, and a click on its background focuses it, so the
  // node pointed at stays shown).
  const hasSvg = drawn !== null;
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return undefined;
    const focusin = (e: FocusEvent) => {
      const g = nodeOf(e.target);
      const nid = g?.dataset.id ?? null;
      if (g) setFocus((f) => ({ ...f, preview: nid }));
    };
    const focusout = (e: FocusEvent) => {
      if (!svg.contains(e.relatedTarget as Node | null)) setFocus((f) => ({ ...f, preview: null }));
    };
    svg.addEventListener('focusin', focusin);
    svg.addEventListener('focusout', focusout);
    return () => {
      svg.removeEventListener('focusin', focusin);
      svg.removeEventListener('focusout', focusout);
    };
  }, [hasSvg, setFocus]);

  let svg = null;
  if (drawn) {
    const { W, height, nodeW, xs, pos, edges, clip, ordered } = drawn;
    svg = (
      <svg
        ref={svgRef}
        className={cx('map-svg', id && 'has-active')}
        width={W}
        height={height}
        viewBox={`0 0 ${W} ${height}`}
        role="group"
        aria-label="Agent map: people, agents and tool servers"
        onPointerOver={(e) => {
          const g = nodeOf(e.target);
          const nid = g?.dataset.id ?? null;
          if (g) setFocus((f) => (f.preview === nid ? f : { ...f, preview: nid }));
        }}
        onPointerLeave={() => setFocus((f) => ({ ...f, preview: null }))}
        onClick={(e) => {
          const g = nodeOf(e.target);
          const nid = g?.dataset.id ?? null;
          setFocus((f) => ({ ...f, pinned: g ? (f.pinned === nid ? null : nid) : null }));
        }}
        onKeyDown={(e) => {
          const g = nodeOf(e.target);
          if (!g) return;
          const nid = g.dataset.id ?? null;
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setFocus((f) => ({ ...f, pinned: f.pinned === nid ? null : nid }));
          } else if (e.key === 'Escape') {
            setFocus((f) => ({ ...f, pinned: null }));
          }
        }}
      >
        <text x={xs.person + 2} y={14} className="col-label">PEOPLE</text>
        <text x={xs.agent + 2} y={14} className="col-label">AGENTS</text>
        <text x={xs.server + 2} y={14} className="col-label">TOOL SERVERS</text>
        <g>
          {edges.flatMap(({ e, path, head, tipText, strokeWidth }, i) => [
            <path key={`e${i}`} d={path} className={cx(`edge edge-${e.kind}`, isRelated(e) && 'is-related')} data-from={e.from} data-to={e.to}
              style={strokeWidth ? { strokeWidth } : undefined}>
              <title>{tipText}</title>
            </path>,
            ...(head ? [
              <path key={`h${i}`} d={head} className={cx(`edge edge-head edge-head-${e.kind}`, isRelated(e) && 'is-related')} data-from={e.from} data-to={e.to} />,
            ] : []),
          ])}
        </g>
        <g>
          {edges.map(({ e, tag, tipText }, i) => (tag ? (
            <g key={i} className={cx('edge-tag', isRelated(e) && 'is-related')} data-from={e.from} data-to={e.to} transform={tag.transform}>
              <title>{tipText}</title>
              <rect x={-tag.tw / 2} y={-9} width={tag.tw} height={18} rx={9} className="edge-label-bg" style={e.denied ? { stroke: 'var(--critical)' } : undefined} />
              <text x={0} y={4} textAnchor="middle" className="edge-label">{tag.text}</text>
            </g>
          ) : null))}
        </g>
        <g>
          {ordered.map((n) => {
            const p = pos.get(n.id)!;
            const label = describeNode(model, n);
            let boxStyle: CSSProperties | undefined;
            if (n.kind === 'agent' && (n.risk_level === 'high' || n.risk_level === 'critical')) {
              boxStyle = { stroke: TONE_COLOR[toneOf('risk', n.risk_level)], strokeWidth: 1.75 };
            }
            let marks: ReactNode;
            if (n.kind === 'person') {
              marks = (
                <>
                  <circle className="node-avatar" cx={22} cy={NODE_H / 2} r={13} />
                  <text className="node-initial" x={22} y={NODE_H / 2 + 4} textAnchor="middle">{initials(n.label)}</text>
                  <text className="node-label" x={42} y={20}>{clip(n.label, 42, 7.6)}</text>
                  <text className="node-sub" x={42} y={36}>{clip(nodeSubLabel(model, n), 42, 6.2)}</text>
                </>
              );
            } else {
              const tone = n.kind === 'server' ? toneOf('server', n.status) : toneOf('agent', n.status);
              marks = (
                <>
                  <path d={`M8,0 H4 A4,4 0 0 0 0,4 V${NODE_H - 4} A4,4 0 0 0 4,${NODE_H} H8 Z`} style={{ fill: TONE_COLOR[tone] }} />
                  <text className="node-label" x={16} y={20}>{clip(n.label, 16, 7.6)}</text>
                  <text className="node-sub" x={16} y={36}>{clip(nodeSubLabel(model, n), 16, 6.2)}</text>
                </>
              );
            }
            return (
              <g key={n.id} className={cx('node', related.has(n.id) && 'is-related', n.id === id && 'is-active')} tabIndex={0} role="button"
                data-id={n.id} aria-label={label} transform={`translate(${p.x},${p.y})`}>
                <title>{label}</title>
                <rect className="node-focus" x={-3} y={-3} width={nodeW + 6} height={NODE_H + 6} rx={10} />
                <rect className="node-box" width={nodeW} height={NODE_H} rx={8} style={boxStyle} />
                {marks}
              </g>
            );
          })}
        </g>
      </svg>
    );
  }

  return (
    <>
      <p className="map-hint" hidden={!drawn || width >= drawn.W}>The map is wider than this screen: scroll it sideways, or use the Connections table below.</p>
      <div ref={holder} className="map-scroll">{svg}</div>
    </>
  );
}

function NodeDetail({ model, id }: { model: Model; id: string | null }) {
  const all = [...model.nodes.values()];
  if (!id) {
    const counts = countBy(all, 'kind');
    const usage = model.edges.filter(isUsage);
    const ungranted = usage.filter(isUngranted);
    const calls = usage.filter(isAgentCall);
    const busiest = usage.slice().sort((x, y) => (y.calls || 0) - (x.calls || 0))[0];
    return (
      <>
        <Facts rows={[
          ['People', fmt(counts.person || 0)],
          ['Agents', fmt(counts.agent || 0)],
          ['Tool servers', fmt(counts.server || 0)],
          calls.length ? ['Agents calling agents', plural(calls.length, 'connection')] : null,
          ['Ungranted use', ungranted.length ? <span className="tone-text-critical">{plural(ungranted.length, 'connection')}</span> : 'None'],
          busiest && busiest.calls
            ? ['Busiest link', `${model.nodes.get(busiest.from)!.label} → ${model.nodes.get(busiest.to)!.label}: ${plural(busiest.calls, 'call')}, ${fmt(busiest.denied)} denied`]
            : null,
        ]} />
        <p className="hint">Point at, focus or select a node to trace its connections. Edge width follows call volume over the last 30 days.</p>
      </>
    );
  }
  const n = model.nodes.get(id);
  if (!n) return null;
  const rel = model.edges.filter((e) => e.from === id || e.to === id);
  const other = (e: MapEdge) => model.nodes.get(e.from === id ? e.to : e.from)!;
  const relLabel = (e: MapEdge) => ({
    owner: e.from === id ? 'owns' : 'owned by', sponsor: e.from === id ? 'sponsors' : 'sponsored by',
    granted: e.from === id ? 'granted' : 'granted to', ungranted: e.from === id ? 'used without grant' : 'used without grant by',
    calls: e.from === id ? 'may call' : 'may be called by', 'calls-ungranted': e.from === id ? 'called without grant' : 'called without grant by',
  } as Record<string, string>)[e.kind] || e.kind;
  const conns = rel.length ? (
    <ul className="conn-list" role="list">
      {rel.map((e, i) => {
        const o = other(e);
        return (
          <li key={i}>
            <span className="muted">{relLabel(e)}</span>
            {o.kind === 'agent' ? <AgentLink id={o.id.slice(6)} name={o.label} /> : <strong>{o.label}</strong>}
            {isUsage(e) ? <span className="muted">{`· ${plural(e.calls || 0, 'call')}, ${fmt(e.denied || 0)} denied`}</span> : null}
            {isUngranted(e) ? <PlainChip text="no grant" tone="critical" iconName="ban" /> : null}
          </li>
        );
      })}
    </ul>
  ) : <p className="muted small">No connections.</p>;
  let head;
  let action = null;
  if (n.kind === 'agent') {
    head = (
      <>
        <div className="chip-row"><Chip kind="agent" value={n.status} /><Chip kind="risk" value={n.risk_level || 'low'} /></div>
        <Facts rows={[['Blueprint', n.blueprint || <span className="muted">None</span>]]} />
      </>
    );
    action = <a className="btn btn--sm" href={agentHref(n.id.slice(6))}>Open agent<Icon name="arrow" /></a>;
  } else if (n.kind === 'server') {
    head = (
      <>
        <div className="chip-row"><Chip kind="server" value={n.status} /></div>
        <Facts rows={[['Classification', n.classification ? humanize(n.classification) : null], ['Trust', n.trust ? humanize(n.trust) : null]]} />
      </>
    );
    action = n.status === 'unregistered' ? null : <a className="btn btn--sm" href="#/toolservers">Open tool servers<Icon name="arrow" /></a>;
  } else {
    head = <p className="muted small">Owner or sponsor</p>;
  }
  return (
    <>
      <h3 className="break">{n.label}</h3>
      {head}
      <div className="field-label">Connections</div>
      {conns}
      {action}
    </>
  );
}

function MapLegend({ model }: { model: Model }) {
  const line = (cls: string, extra?: CSSProperties) => (
    <svg width={28} height={10} aria-hidden="true"><path d="M1,5 H27" className={`edge ${cls}`} style={extra} /></svg>
  );
  const arc = (kind: string) => (
    <svg width={28} height={16} aria-hidden="true">
      <path d="M25,3 C9,3 9,12 25,12" className={`edge edge-${kind}`} style={{ strokeWidth: 2 }} />
      <path d="M19,8 L26,12 L19,16 Z" className={`edge edge-head edge-head-${kind}`} />
    </svg>
  );
  const stripe = (tone: Tone) => <span className="swatch" style={{ background: TONE_COLOR[tone], width: 6, height: 14 }} />;
  const item = (mark: ReactNode, label: string) => <span className="legend-item">{mark}{label}</span>;
  const agentCalls = model.edges.filter(isAgentCall);
  return (
    <div className="map-legend">
      {item(line('edge-owner'), 'Owner')}
      {item(line('edge-sponsor'), 'Sponsor')}
      {item(line('edge-granted', { strokeWidth: 3 }), 'Granted (width = calls)')}
      {item(line('edge-ungranted', { strokeWidth: 2 }), 'Used without a grant')}
      {agentCalls.length ? item(arc('calls'), 'May call another agent') : null}
      {agentCalls.some(isUngranted) ? item(arc('calls-ungranted'), 'Called an agent without a grant') : null}
      {item(stripe('good'), 'Active / approved')}
      {item(stripe('warning'), 'Pending approval')}
      {item(stripe('critical'), 'Blocked')}
      {item(stripe('serious'), 'Unmanaged / unregistered')}
      {item(
        <span className="swatch" style={{ background: 'transparent', border: '2px solid var(--serious)', width: 14, height: 12, borderRadius: 3 }} />,
        'High-risk agent (outline)',
      )}
    </div>
  );
}

export const mapPage: PageDef<Graph> = {
  re: /^\/map$/,
  nav: 'map',
  title: 'Agent map',
  load: () => api('v1/graph'),
  View: MapPageView,
};

function MapPageView({ data: graph }: { data: Graph }) {
  const model = useMemo(() => buildGraph(graph), [graph]);
  const [focus, setFocus] = useState<MapFocus>({ preview: null, pinned: null });
  // Loaded again (refresh), the map keeps the node selected, unless it is no longer there.
  const gone = (nid: string | null) => nid !== null && !model.nodes.has(nid);
  if (gone(focus.preview) || gone(focus.pinned)) {
    setFocus({ preview: gone(focus.preview) ? null : focus.preview, pinned: gone(focus.pinned) ? null : focus.pinned });
  }
  const id = focus.preview || focus.pinned;
  const agentCalls = model.edges.some(isAgentCall);
  return (
    <div className="page">
      <PageHead
        title="Agent map"
        sub="Who is accountable for each agent, and which tool servers and other agents each agent can reach or has used in the last 30 days."
        actions={[<RefreshButton key="refresh" />]}
      />
      <div className="map-layout">
        <Card
          title="People, agents and tool servers"
          sub={agentCalls
            ? 'Columns are fixed: accountable people on the left, tool servers on the right. Arcs beside the agents point from an agent to the agents it calls.'
            : 'Columns are fixed: accountable people on the left, tool servers on the right.'}
        >
          <MapLegend model={model} />
          {model.nodes.size
            ? <MapView model={model} focus={focus} setFocus={setFocus} />
            : <EmptyState title="Nothing to map yet" text="Register agents and tool servers to see who owns what and which tools each agent reaches." />}
        </Card>
        <section className="card map-detail" aria-labelledby="map-detail-title" aria-live="polite">
          <div className="card-head">
            <div className="card-head-text"><h2 id="map-detail-title">{id ? (id === focus.pinned ? 'Selected' : 'Details') : 'Summary'}</h2></div>
          </div>
          <div className="card-body"><NodeDetail model={model} id={id} /></div>
        </section>
      </div>
      <ConnectionsTable model={model} />
    </div>
  );
}

function ConnectionsTable({ model }: { model: Model }) {
  if (!model.edges.length) return null;
  const order: Record<string, number> = { owner: 0, sponsor: 1, granted: 2, ungranted: 3, calls: 4, 'calls-ungranted': 5 };
  const rows = model.edges.slice().sort((x, y) => String(model.nodes.get(x.from)!.label).localeCompare(String(model.nodes.get(y.from)!.label)) || order[x.kind] - order[y.kind]);
  const label: Record<string, string> = {
    owner: 'Owner of', sponsor: 'Sponsor of', granted: 'Granted', ungranted: 'Used without a grant', calls: 'May call', 'calls-ungranted': 'Called without a grant',
  };
  const nameCell = (n: MapNode) => (n.kind === 'agent' ? <AgentLink id={n.id.slice(6)} name={n.label} /> : n.label);
  return (
    <Card title="Connections" sub="The same graph as a table" flush>
      <div className="table-wrap">
        <table className="data rtable">
          <thead>
            <tr>{['From', 'Relation', 'To', 'Calls (30 days)', 'Denied'].map((t, i) => <th key={t} scope="col" className={i > 2 ? 'num' : undefined}>{t}</th>)}</tr>
          </thead>
          <tbody>
            {rows.map((e, i) => {
              const usage = isUsage(e);
              return (
                <tr key={i}>
                  <td data-label="From" className="break">{nameCell(model.nodes.get(e.from)!)}</td>
                  <td data-label="Relation">{isUngranted(e) ? <PlainChip text={label[e.kind]} tone="critical" iconName="ban" /> : label[e.kind]}</td>
                  <td data-label="To" className="break">{nameCell(model.nodes.get(e.to)!)}</td>
                  <td data-label="Calls" className="num">{usage ? fmt(e.calls || 0) : '—'}</td>
                  <td data-label="Denied" className="num">{usage ? fmt(e.denied || 0) : '—'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
