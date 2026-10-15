// The pieces pages are made of. Values from the API are only ever rendered as text: tool
// descriptions and ledger reasons are attacker-influenced data.

import {
  useEffect, useId, useLayoutEffect, useRef, useState,
  type ReactNode, type RefObject,
} from 'react';
import { cx, fmt, fullFmt, relTime, stampFmt } from '../lib/format';
import { refresh } from '../lib/router';
import { statusMeta } from '../lib/status';
import { Icon } from './Icon';
import { toast } from './toast';

/** A status, in its tone and with its icon: chip('agent', 'active'). */
export function Chip({ kind, value, extra, title }: { kind: string; value: string | null | undefined; extra?: ReactNode; title?: string | null }) {
  const [tone, ic, label] = statusMeta(kind, value);
  return (
    <span className="chip" data-tone={tone} title={title || undefined}>
      <Icon name={ic} />{label}{extra != null ? <span className="risk-score">{extra}</span> : null}
    </span>
  );
}

export function RiskChip({ risk }: { risk: { level?: string; score?: number } | null | undefined }) {
  const level = risk?.level || 'low';
  return <Chip kind="risk" value={level} extra={risk?.score ?? 0} title={`Risk score ${risk?.score ?? 0} of 100`} />;
}

/** A chip of plain text, or of a tone and icon of its own. */
export function PlainChip({ text, mono = false, title, tone, iconName }: { text: ReactNode; mono?: boolean; title?: string | null; tone?: string | null; iconName?: string }) {
  return (
    <span className={cx('chip', !iconName && 'chip--plain', mono && 'chip--mono')} data-tone={tone || undefined} title={title || undefined}>
      {iconName ? <Icon name={iconName} /> : null}{text}
    </span>
  );
}

/** The page's own heading: its title, what it is, and what can be done on it. */
export function PageHead({ title, sub, actions, crumbs }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode[] | ReactNode; crumbs?: ReactNode }) {
  const list = Array.isArray(actions) ? actions.filter(Boolean) : actions ? [actions] : [];
  return (
    <header className="page-head">
      <div className="page-head-text">
        {crumbs || null}
        <h1 tabIndex={-1}>{title}</h1>
        {sub ? <p>{sub}</p> : null}
      </div>
      {list.length ? <div className="page-actions">{list}</div> : null}
    </header>
  );
}

export function RefreshButton() {
  return <button type="button" className="btn" onClick={() => refresh()}><Icon name="refresh" />Refresh</button>;
}

/** A card: a region of the page, named by its title. */
export function Card({
  title, sub, actions, children, foot, cls, flush = false, level = 'h2', id,
}: {
  title: ReactNode; sub?: ReactNode; actions?: ReactNode; children?: ReactNode; foot?: ReactNode;
  cls?: string | null; flush?: boolean; level?: 'h2' | 'h3'; id?: string;
}) {
  const auto = useId();
  const headingId = id || `card${auto.replace(/:/g, '')}`;
  const Heading = level;
  const acts = Array.isArray(actions) ? actions.filter(Boolean) : actions;
  return (
    <section className={cx('card', cls)} aria-labelledby={headingId}>
      <div className="card-head">
        <div className="card-head-text">
          <Heading id={headingId}>{title}</Heading>
          {sub ? <p className="card-sub">{sub}</p> : null}
        </div>
        {acts && (!Array.isArray(acts) || acts.length) ? <div className="btn-row">{acts}</div> : null}
      </div>
      <div className={flush ? 'card-body card-body--flush' : 'card-body'}>{children}</div>
      {foot ? <div className="card-foot">{foot}</div> : null}
    </section>
  );
}

export function EmptyState({ title, text, action }: { title: ReactNode; text?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {text ? <span>{text}</span> : null}
      {action ? <div style={{ marginTop: 10 }}>{action}</div> : null}
    </div>
  );
}

export function Callout({ tone, icon, children, role }: { tone: string; icon: string; children?: ReactNode; role?: string }) {
  return (
    <div className="callout" data-tone={tone} role={role}>
      <Icon name={icon} />
      <div className="callout-body">{children}</div>
    </div>
  );
}

export type FactRow = [label: ReactNode, value: ReactNode] | null | false | undefined;

/** Terms and what they are; a missing value shows as a dash. */
export function Facts({ rows }: { rows: FactRow[] }) {
  return (
    <dl className="facts">
      {(rows.filter(Boolean) as [ReactNode, ReactNode][]).map(([k, v], i) => [
        <dt key={`t${i}`}>{k}</dt>,
        <dd key={`d${i}`}>{v ?? <span className="muted">—</span>}</dd>,
      ])}
    </dl>
  );
}

export function JsonBlock({ value }: { value: unknown }) {
  return <pre className="kv-pre" tabIndex={0}>{JSON.stringify(value, null, 2)}</pre>;
}

export function agentHref(ref: string): string {
  return `#/agents/${encodeURIComponent(ref)}`;
}

export function AgentLink({ id, name }: { id?: string | null; name?: string | null }) {
  if (id) return <a href={agentHref(id)}>{name || id}</a>;
  return name ? <span>{name}</span> : <span className="muted">Unknown agent</span>;
}

/** A time: how long ago (or when, absolute), with the full date on hover. */
export function TimeEl({ iso, empty = '—', absolute = false }: { iso: string | null | undefined; empty?: ReactNode; absolute?: boolean }) {
  if (!iso) return <span className="muted">{empty}</span>;
  const date = new Date(iso);
  return <time dateTime={iso} title={fullFmt.format(date)}>{absolute ? stampFmt.format(date) : relTime(iso)}</time>;
}

/** Text with a button that copies it. */
export function Copyable({ text, label }: { text: string; label: string }) {
  const code = useRef<HTMLElement>(null);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      toast(`Copied ${label}.`, { timeout: 2500 });
    } catch {
      const range = document.createRange();
      range.selectNodeContents(code.current!);
      const sel = getSelection()!;
      sel.removeAllRanges();
      sel.addRange(range);
      toast('The text is selected. Press Ctrl+C or Cmd+C to copy it.', { tone: 'neutral' });
    }
  };
  return (
    <span className="copyable">
      <code ref={code}>{text}</code>
      <button type="button" className="icon-btn copy-btn" aria-label={`Copy ${label}`} title={`Copy ${label}`} onClick={copy}>
        <Icon name="copy" />
      </button>
    </span>
  );
}

/** Names, in a list that scrolls when there are many. */
export function NameList({ names }: { names: string[] }) {
  return <ul className="adopt-list" role="list">{names.map((n, i) => <li key={i} className="break">{n}</li>)}</ul>;
}

/** The width of an element, as it changes (for charts drawn to fit). */
export function useWidth(ref: RefObject<HTMLElement | null>): number {
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return undefined;
    const ro = new ResizeObserver((entries) => {
      const w = Math.floor(entries[0].contentRect.width);
      if (w > 0) setWidth(w);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [ref]);
  return width;
}

/** A chart's tooltip, inside container (which is positioned): show(content, x, y), hide(). */
export function useTooltip(container: RefObject<HTMLElement | null>) {
  const [tip, setTip] = useState<{ content: ReactNode; x: number; y: number } | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!tip || !el || !container.current) return;
    const cw = container.current.clientWidth;
    const left = Math.max(0, Math.min(cw - el.offsetWidth, tip.x - el.offsetWidth / 2));
    let top = tip.y - el.offsetHeight - 10;
    if (top < 0) top = tip.y + 14;
    el.style.left = `${left}px`;
    el.style.top = `${top}px`;
  }, [tip, container]);
  return {
    node: <div ref={ref} className="tooltip" hidden={!tip} aria-hidden="true">{tip?.content}</div>,
    show: (content: ReactNode, x: number, y: number) => setTip({ content, x, y }),
    hide: () => setTip(null),
  };
}

export function TipRow({ color, value, label }: { color?: string | null; value: number; label: ReactNode }) {
  return (
    <div className="tooltip-row">
      <span className="tooltip-key" style={{ borderColor: color || 'transparent' }} />
      <strong>{fmt(value)}</strong>{label}
    </div>
  );
}
