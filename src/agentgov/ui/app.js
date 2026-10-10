/* AgentGov admin center.
 *
 * A dependency-free ES module: no build step, no CDN, no web fonts, so it works
 * air-gapped. Values from the API are only ever inserted as text (textContent /
 * createTextNode), never parsed as HTML: tool descriptions and ledger reasons are
 * attacker-influenced data.
 */

const API_ROOT = new URL('../', location.href); // the UI is served at <control plane>/ui/
const TOKEN_KEY = 'agentgov.token';
const THEME_KEY = 'agentgov.theme';
const SVG_NS = 'http://www.w3.org/2000/svg';

/* ------------------------------------------------------------------ storage */

function readStore(area, key) {
  try { return window[area].getItem(key); } catch { return null; }
}

function writeStore(area, key, value) {
  try {
    if (value == null) window[area].removeItem(key);
    else window[area].setItem(key, value);
  } catch { /* storage blocked: the app still works for this page view */ }
}

/* -------------------------------------------------------------------- theme */

const THEMES = ['system', 'light', 'dark'];

function applyTheme(mode) {
  const root = document.documentElement;
  if (mode === 'light' || mode === 'dark') root.dataset.theme = mode;
  else delete root.dataset.theme;
}
applyTheme(readStore('localStorage', THEME_KEY));

/* --------------------------------------------------------------- DOM helpers */

function setProps(el, props, isSvg) {
  if (!props) return;
  for (const [key, value] of Object.entries(props)) {
    if (value == null || value === false) continue;
    if (key === 'class') el.setAttribute('class', Array.isArray(value) ? value.filter(Boolean).join(' ') : value);
    else if (key === 'text') el.textContent = value;
    else if (key === 'dataset') Object.assign(el.dataset, value);
    else if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2), value);
    else if (key === 'value' && !isSvg) el.value = value;
    else el.setAttribute(key, value === true ? '' : String(value));
  }
}

function addKids(el, kids) {
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false || kid === true) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  setProps(el, props, false);
  return addKids(el, kids);
}

function s(tag, props, ...kids) {
  const el = document.createElementNS(SVG_NS, tag);
  setProps(el, props, true);
  return addKids(el, kids);
}

const $ = (sel, root = document) => root.querySelector(sel);

/** Replace an element's children, skipping null/false entries (replaceChildren would print "null"). */
function fill(el, ...kids) {
  el.replaceChildren();
  return addKids(el, kids);
}
let uid = 0;
const nextId = (prefix) => `${prefix}-${++uid}`;

/* -------------------------------------------------------------------- icons */

const ICONS = {
  overview: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
  agents: 'M7 9h10a3 3 0 0 1 3 3v5a3 3 0 0 1-3 3H7a3 3 0 0 1-3-3v-5a3 3 0 0 1 3-3zM12 9V5M9.5 14.5v.01M14.5 14.5v.01',
  map: 'M4 12a2 2 0 1 0 4 0a2 2 0 1 0-4 0M16 6a2 2 0 1 0 4 0a2 2 0 1 0-4 0M16 18a2 2 0 1 0 4 0a2 2 0 1 0-4 0M7.8 11.1l8.4-4.2M7.8 12.9l8.4 4.2',
  approvals: 'M9 4h6v3H9zM8 5.5H6V20h12V5.5h-2M9 13.5l2 2 4-4',
  toolservers: 'M4 4h16v7H4zM4 13h16v7H4zM8 7.5v.01M8 16.5v.01',
  findings: 'M12 3.5l9 16H3zM12 10v4M12 17v.01',
  policies: 'M12 3l7.5 3v6c0 4.4-3.2 7.9-7.5 9-4.3-1.1-7.5-4.6-7.5-9V6zM9 12l2 2 4-4',
  ledger: 'M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 1 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 1 0 5.7 5.7l1-1',
  check: 'M5 12.5l4.5 4.5L19 7',
  'check-circle': 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M8 12.5l2.7 2.7L16 9.5',
  'check-double': 'M2 12.5l4.5 4.5L16 7M12 15.5l1.5 1.5L22 8',
  x: 'M6 6l12 12M18 6L6 18',
  ban: 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M5.7 5.7l12.6 12.6',
  clock: 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M12 7v5l3 2',
  'user-check': 'M5 8a4 4 0 1 0 8 0a4 4 0 1 0-8 0M3 21c0-3.3 2.7-6 6-6s6 2.7 6 6M16 11l2 2 4-4',
  user: 'M8 7a4 4 0 1 0 8 0a4 4 0 1 0-8 0M4 21c0-4 3.6-7 8-7s8 3 8 7',
  eye: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM9 12a3 3 0 1 0 6 0a3 3 0 1 0-6 0',
  trash: 'M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3',
  power: 'M12 3v9M6.3 6.3a8 8 0 1 0 11.4 0',
  refresh: 'M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5',
  undo: 'M9 14L4 9l5-5M4 9h10a6 6 0 0 1 0 12h-3',
  download: 'M12 4v11M7 10l5 5 5-5M5 20h14',
  copy: 'M9 9h11v11H9zM5 15V4h11',
  menu: 'M4 7h16M4 12h16M4 17h16',
  sun: 'M8 12a4 4 0 1 0 8 0a4 4 0 1 0-8 0M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
  moon: 'M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z',
  monitor: 'M3 5h18v11H3zM8 20h8M12 16v4',
  signout: 'M15 4h4v16h-4M10 8l-4 4 4 4M6 12h11',
  chevron: 'M9 6l6 6-6 6',
  arrow: 'M5 12h14M13 6l6 6-6 6',
  lock: 'M6 11h12v9H6zM8 11V8a4 4 0 0 1 8 0v3',
  octagon: 'M8.2 3h7.6L21 8.2v7.6L15.8 21H8.2L3 15.8V8.2zM12 8v5M12 16v.01',
  triangle: 'M12 3.5l9 16H3zM12 10v4M12 17v.01',
  'alert-circle': 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M12 7.5v5.5M12 16.5v.01',
  info: 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M12 11v5M12 8v.01',
  minus: 'M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0M8 12h8',
  key: 'M3 15a4 4 0 1 0 8 0a4 4 0 1 0-8 0M10 12l9-9M15 7l3 3M17 5l2 2',
  play: 'M7 4l13 8-13 8z',
  shield: 'M12 3l7.5 3v6c0 4.4-3.2 7.9-7.5 9-4.3-1.1-7.5-4.6-7.5-9V6z',
  'shield-check': 'M12 3l7.5 3v6c0 4.4-3.2 7.9-7.5 9-4.3-1.1-7.5-4.6-7.5-9V6zM9 12l2 2 4-4',
  external: 'M14 4h6v6M20 4l-9 9M18 14v6H4V6h6',
};

function icon(name, { label, cls } = {}) {
  const wrap = document.createElement('span');
  wrap.className = cls ? `ico ${cls}` : 'ico';
  if (label) {
    wrap.setAttribute('role', 'img');
    wrap.setAttribute('aria-label', label);
  } else {
    wrap.setAttribute('aria-hidden', 'true');
  }
  const svg = s('svg', {
    viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 2,
    'stroke-linecap': 'round', 'stroke-linejoin': 'round', focusable: 'false',
  }, s('path', { d: ICONS[name] || ICONS.info }));
  wrap.append(svg);
  return wrap;
}

/* --------------------------------------------------------------- formatting */

const numberFmt = new Intl.NumberFormat();
const fullFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
const stampFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
const dayFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' });
const dayLongFmt = new Intl.DateTimeFormat(undefined, { weekday: 'short', month: 'short', day: 'numeric', timeZone: 'UTC' });
const relFmt = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

const fmt = (n) => numberFmt.format(n ?? 0);

function plural(n, one, many = `${one}s`) {
  return `${fmt(n)} ${n === 1 ? one : many}`;
}

function cap(text) {
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : '';
}

function humanize(text) {
  return cap(String(text ?? '').replace(/[_]+/g, ' '));
}

function shortHash(value, head = 8, tail = 6) {
  if (!value) return '';
  return value.length > head + tail + 1 ? `${value.slice(0, head)}…${value.slice(-tail)}` : value;
}

function relTime(iso) {
  const sec = (new Date(iso).getTime() - Date.now()) / 1000;
  const abs = Math.abs(sec);
  if (abs < 45) return sec <= 0 ? 'just now' : 'in a few seconds';
  const table = [
    [3600, 'minute', 60], [86400, 'hour', 3600], [86400 * 7, 'day', 86400],
    [86400 * 30, 'week', 604800], [86400 * 365, 'month', 2592000], [Infinity, 'year', 31536000],
  ];
  for (const [limit, unit, div] of table) {
    if (abs < limit) return relFmt.format(Math.round(sec / div), unit);
  }
  return '';
}

function timeEl(iso, { empty = '—', absolute = false } = {}) {
  if (!iso) return h('span', { class: 'muted' }, empty);
  const date = new Date(iso);
  return h('time', { datetime: iso, title: fullFmt.format(date) }, absolute ? stampFmt.format(date) : relTime(iso));
}

function fmtBytes(n) {
  if (n < 1024) return `${fmt(n)} bytes`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function initials(label) {
  const base = String(label || '?').split('@')[0];
  const parts = base.split(/[\s._-]+/).filter(Boolean);
  return ((parts[0]?.[0] || '?') + (parts[1]?.[0] || '')).toUpperCase();
}

function countBy(list, key) {
  const out = {};
  for (const item of list) {
    const k = typeof key === 'function' ? key(item) : item[key];
    out[k] = (out[k] || 0) + 1;
  }
  return out;
}

/* ----------------------------------------------------------------- API client */

class ApiError extends Error {
  constructor(status, message, detail) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

let token = readStore('sessionStorage', TOKEN_KEY);

function describeDetail(detail) {
  if (!detail) return '';
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail.map((d) => {
      const where = Array.isArray(d?.loc) ? d.loc.filter((x) => x !== 'body' && x !== 'query').join('.') : '';
      return [where, d?.msg].filter(Boolean).join(': ');
    }).join('; ');
  }
  try { return JSON.stringify(detail); } catch { return String(detail); }
}

function friendlyError(status, detail) {
  const d = detail ? `${cap(detail).replace(/\.$/, '')}.` : '';
  if (status === 401) return 'Your API token was not accepted. Sign in again with a valid token.';
  if (status === 403) return `Your token's role can't do this. ${d}`.trim();
  if (status === 404) return d || 'Not found.';
  if (status === 409) return d || 'That change conflicts with the current state. Refresh and try again.';
  if (status === 400 || status === 422) return `The control plane rejected the request. ${d}`.trim();
  if (status >= 502 && status <= 504) return d || `A service behind the control plane did not respond (HTTP ${status}).`;
  if (status >= 500) return `The control plane hit an error (HTTP ${status}). ${d}`.trim();
  return d || `The request failed (HTTP ${status}).`;
}

async function api(path, { method = 'GET', body, raw = false, auth = true, signingIn = false } = {}) {
  const headers = { Accept: 'application/json' };
  if (auth && token) headers.Authorization = `Bearer ${token}`;
  const init = { method, headers, cache: 'no-store' };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(new URL(path, API_ROOT), init);
  } catch {
    throw new ApiError(0, "Can't reach the control plane. Check that it is running and that this browser can connect to it.");
  }
  if (!res.ok) {
    let detail = '';
    try { detail = describeDetail((await res.json())?.detail); } catch { /* body was not JSON */ }
    if (res.status === 401 && auth && !signingIn) expireSession();
    throw new ApiError(res.status, friendlyError(res.status, detail), detail);
  }
  if (raw) return res;
  return res.status === 204 ? null : res.json();
}

let infoPromise = null;
function getInfo() {
  if (!infoPromise) infoPromise = api('v1/info', { auth: false }).catch(() => null);
  return infoPromise;
}

async function saveDownload(path, filename) {
  const res = await api(path, { raw: true });
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const link = h('a', { href: url, download: filename, hidden: true });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  return blob;
}

function fileStamp() {
  return new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
}

/* ------------------------------------------------------- status vocabulary */

// kind -> value -> [tone, icon, label]
const STATUS = {
  agent: {
    active: ['good', 'check-circle', 'Active'],
    pending: ['warning', 'clock', 'Pending review'],
    blocked: ['critical', 'ban', 'Blocked'],
    discovered: ['serious', 'eye', 'Discovered'],
    deleted: ['neutral', 'trash', 'Deleted'],
  },
  risk: {
    low: ['neutral', 'minus', 'Low risk'],
    medium: ['warning', 'alert-circle', 'Medium risk'],
    high: ['serious', 'triangle', 'High risk'],
    critical: ['critical', 'octagon', 'Critical risk'],
  },
  severity: {
    critical: ['critical', 'octagon', 'Critical'],
    high: ['serious', 'triangle', 'High'],
    medium: ['warning', 'alert-circle', 'Medium'],
    low: ['neutral', 'minus', 'Low'],
    info: ['neutral', 'info', 'Info'],
  },
  decision: {
    allow: ['good', 'check-circle', 'Allowed'],
    deny: ['critical', 'ban', 'Denied'],
    require_approval: ['warning', 'user-check', 'Needs approval'],
  },
  approval: {
    pending: ['warning', 'clock', 'Pending'],
    approved: ['good', 'check-circle', 'Approved'],
    denied: ['critical', 'ban', 'Denied'],
    used: ['neutral', 'check-double', 'Used'],
    expired: ['neutral', 'clock', 'Expired'],
    cancelled: ['neutral', 'minus', 'Cancelled'],
  },
  server: {
    approved: ['good', 'check-circle', 'Approved'],
    pending: ['warning', 'clock', 'Pending review'],
    blocked: ['critical', 'ban', 'Blocked'],
    unregistered: ['serious', 'alert-circle', 'Unregistered'],
  },
  finding: {
    open: ['warning', 'alert-circle', 'Open'],
    resolved: ['good', 'check-circle', 'Resolved'],
    dismissed: ['neutral', 'minus', 'Dismissed'],
  },
};
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const TONE_COLOR = {
  good: 'var(--good)', warning: 'var(--warning)', serious: 'var(--serious)',
  critical: 'var(--critical)', neutral: 'var(--neutral)', accent: 'var(--accent)',
};

function statusMeta(kind, value) {
  return STATUS[kind]?.[value] || ['neutral', 'info', value ? humanize(value) : 'Unknown'];
}

function toneOf(kind, value) {
  return statusMeta(kind, value)[0];
}

function chip(kind, value, { extra, title } = {}) {
  const [tone, ic, label] = statusMeta(kind, value);
  return h('span', { class: 'chip', 'data-tone': tone, title: title || null },
    icon(ic), label, extra != null ? h('span', { class: 'risk-score' }, extra) : null);
}

function riskChip(risk) {
  const level = risk?.level || 'low';
  return chip('risk', level, { extra: risk?.score ?? 0, title: `Risk score ${risk?.score ?? 0} of 100` });
}

function plainChip(text, { mono = false, title, tone, iconName } = {}) {
  return h('span', {
    class: ['chip', iconName ? null : 'chip--plain', mono ? 'chip--mono' : null],
    'data-tone': tone || null, title: title || null,
  }, iconName ? icon(iconName) : null, text);
}

/* ------------------------------------------------------------- UI pieces */

function toast(message, { tone = 'good', timeout } = {}) {
  const host = $('#toasts');
  const iconName = { good: 'check-circle', critical: 'alert-circle', warning: 'triangle' }[tone] || 'info';
  const el = h('div', { class: 'toast', 'data-tone': tone, role: tone === 'critical' ? 'alert' : null },
    icon(iconName), h('div', { class: 'toast-body' }, message),
    h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Dismiss notification', onclick: () => el.remove() }, icon('x')));
  host.append(el);
  setTimeout(() => el.remove(), timeout ?? (tone === 'critical' ? 10000 : 5000));
}

function copyable(text, label) {
  const code = h('code', {}, text);
  const btn = h('button', { type: 'button', class: 'icon-btn copy-btn', 'aria-label': `Copy ${label}`, title: `Copy ${label}` }, icon('copy'));
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(text);
      toast(`Copied ${label}.`, { timeout: 2500 });
    } catch {
      const range = document.createRange();
      range.selectNodeContents(code);
      const sel = getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      toast('The text is selected. Press Ctrl+C or Cmd+C to copy it.', { tone: 'neutral' });
    }
  });
  return h('span', { class: 'copyable' }, code, btn);
}

function pageHead({ title, sub, actions, crumbs }) {
  return h('header', { class: 'page-head' },
    h('div', { class: 'page-head-text' }, crumbs || null, h('h1', { tabindex: '-1' }, title), sub ? h('p', {}, sub) : null),
    actions?.length ? h('div', { class: 'page-actions' }, actions) : null);
}

function refreshButton() {
  return h('button', { type: 'button', class: 'btn', 'data-focus-key': 'refresh', onclick: () => refresh() }, icon('refresh'), 'Refresh');
}

function card({ title, sub, actions, body, foot, cls, flush = false, level = 'h2', id }) {
  const headingId = id || nextId('card');
  return h('section', { class: ['card', cls], 'aria-labelledby': headingId },
    h('div', { class: 'card-head' },
      h('div', { class: 'card-head-text' }, h(level, { id: headingId }, title), sub ? h('p', { class: 'card-sub' }, sub) : null),
      actions ? h('div', { class: 'btn-row' }, actions) : null),
    h('div', { class: flush ? 'card-body card-body--flush' : 'card-body' }, body),
    foot ? h('div', { class: 'card-foot' }, foot) : null);
}

function emptyState(title, text, action) {
  return h('div', { class: 'empty' }, h('strong', {}, title), text ? h('span', {}, text) : null,
    action ? h('div', { style: 'margin-top:10px' }, action) : null);
}

function callout(tone, iconName, ...content) {
  return h('div', { class: 'callout', 'data-tone': tone }, icon(iconName), h('div', { class: 'callout-body' }, content));
}

function facts(rows) {
  return h('dl', { class: 'facts' }, rows.filter(Boolean).map(([k, v]) => [h('dt', {}, k), h('dd', {}, v ?? h('span', { class: 'muted' }, '—'))]));
}

function jsonBlock(value) {
  return h('pre', { class: 'kv-pre', tabindex: '0' }, JSON.stringify(value, null, 2));
}

function agentHref(ref) {
  return `#/agents/${encodeURIComponent(ref)}`;
}

function agentLink(id, name) {
  if (id) return h('a', { href: agentHref(id) }, name || id);
  return name ? h('span', {}, name) : h('span', { class: 'muted' }, 'Unknown agent');
}

function tooltip(container) {
  const tip = h('div', { class: 'tooltip', hidden: true, 'aria-hidden': 'true' });
  container.append(tip);
  return {
    show(content, x, y) {
      tip.replaceChildren(...content);
      tip.hidden = false;
      const cw = container.clientWidth;
      const tw = tip.offsetWidth;
      const th = tip.offsetHeight;
      const left = Math.max(0, Math.min(cw - tw, x - tw / 2));
      let top = y - th - 10;
      if (top < 0) top = y + 14;
      tip.style.left = `${left}px`;
      tip.style.top = `${top}px`;
    },
    hide() { tip.hidden = true; },
  };
}

function tipRow(color, value, label) {
  return h('div', { class: 'tooltip-row' },
    color ? h('span', { class: 'tooltip-key', style: `border-color: ${color}` }) : h('span', { class: 'tooltip-key', style: 'border-color: transparent' }),
    h('strong', {}, fmt(value)), label);
}

function observeWidth(el, draw) {
  let last = 0;
  const ro = new ResizeObserver((entries) => {
    if (!el.isConnected) { ro.disconnect(); return; }
    const width = Math.floor(entries[0].contentRect.width);
    if (width > 0 && width !== last) { last = width; draw(width); }
  });
  ro.observe(el);
}

/* ------------------------------------------------------------------ dialog */

function dialogField(f, controls) {
  const id = `dlg-${f.id}`;
  let control;
  if (f.type === 'textarea') {
    control = h('textarea', { id, name: f.id, rows: 3, placeholder: f.placeholder || null });
  } else if (f.type === 'select') {
    control = h('select', { id, name: f.id },
      f.options.map((o) => h('option', { value: o.value, selected: o.value === (f.value ?? '') }, o.label)));
  } else {
    control = h('input', { id, name: f.id, type: 'text', autocomplete: 'off', placeholder: f.placeholder || null });
  }
  if (f.value != null && f.type !== 'select') control.value = f.value;
  if (f.hint) control.setAttribute('aria-describedby', `${id}-hint`);
  controls[f.id] = control;
  return h('div', { class: 'field' },
    h('label', { for: id }, f.label, f.required ? null : h('span', { class: 'muted' }, ' (optional)')),
    control,
    f.hint ? h('p', { class: 'hint', id: `${id}-hint` }, f.hint) : null);
}

/** Show a modal confirmation. Resolves to the field values, or null when cancelled. */
function ask({ title, text, tone = 'primary', iconName = 'info', confirm = 'Confirm', fields = [], extra }) {
  return new Promise((resolve) => {
    const dlg = $('#dialog');
    const opener = document.activeElement;
    const controls = {};
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      if (dlg.open) dlg.close();
      resolve(value);
      if (opener && opener.isConnected) opener.focus();
    };
    const error = h('p', { class: 'form-error', role: 'alert', hidden: true });
    const form = h('form', { class: 'dialog-form', novalidate: true },
      h('div', { class: 'dialog-head' }, icon(iconName),
        h('div', { class: 'stack', style: 'gap:6px' },
          h('h2', { id: 'dialog-title', class: 'dialog-title' }, title),
          text ? h('p', { class: 'dialog-text' }, text) : null)),
      extra || null,
      fields.map((f) => dialogField(f, controls)),
      error,
      h('div', { class: 'dialog-actions' },
        h('button', { type: 'button', class: 'btn', onclick: () => finish(null) }, 'Cancel'),
        h('button', { type: 'submit', class: `btn btn--${tone}` }, confirm)));
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const values = {};
      for (const f of fields) {
        const value = controls[f.id].value.trim();
        if (f.required && !value) {
          error.textContent = `${f.label} is required.`;
          error.hidden = false;
          controls[f.id].focus();
          return;
        }
        values[f.id] = value;
      }
      finish(values);
    });
    dlg.dataset.tone = tone === 'danger' ? 'critical' : 'accent';
    dlg.replaceChildren(form);
    dlg.addEventListener('close', () => finish(null), { once: true });
    dlg.showModal();
    (form.querySelector('input, textarea, select') || form.querySelector('[type="submit"]')).focus();
  });
}

/* ------------------------------------------------------------ nav badges */

function setBadge(sel, count, tone, word) {
  const el = $(sel);
  if (!el) return;
  el.hidden = !count;
  el.dataset.tone = tone || '';
  el.replaceChildren(count ? fmt(count) : '', h('span', { class: 'sr-only' }, ` ${word}`));
}

function summarizeFindings(list) {
  return { open: list.length, by_severity: countBy(list, 'severity') };
}

function updateBadges({ pendingApprovals, findings }) {
  if (pendingApprovals != null) setBadge('#badge-approvals', pendingApprovals, pendingApprovals ? 'warning' : '', 'pending');
  if (findings) {
    const by = findings.by_severity || {};
    const tone = by.critical ? 'critical' : by.high ? 'serious' : findings.open ? 'warning' : '';
    setBadge('#badge-findings', findings.open, tone, 'open');
  }
}

async function refreshBadges() {
  try {
    const [pending, open] = await Promise.all([api('v1/approvals?status=pending'), api('v1/findings?status=open')]);
    updateBadges({ pendingApprovals: pending.length, findings: summarizeFindings(open) });
  } catch { /* badges are a convenience; the pages show the real state */ }
}

/* ------------------------------------------------------------------ router */

const PAGES = [
  { re: /^\/overview$/, nav: 'overview', title: 'Overview', render: renderOverview },
  { re: /^\/agents$/, nav: 'agents', title: 'Agents', render: renderAgents },
  { re: /^\/agents\/([^/]+)$/, nav: 'agents', title: 'Agent', render: renderAgent },
  { re: /^\/map$/, nav: 'map', title: 'Agent map', render: renderMap },
  { re: /^\/approvals(?:\/(history))?$/, nav: 'approvals', title: 'Approvals', render: renderApprovals },
  { re: /^\/toolservers$/, nav: 'toolservers', title: 'Tool servers', render: renderToolservers },
  { re: /^\/findings$/, nav: 'findings', title: 'Findings', render: renderFindings },
  { re: /^\/policies$/, nav: 'policies', title: 'Policies', render: renderPolicies },
  { re: /^\/ledger$/, nav: 'ledger', title: 'Ledger', render: renderLedger },
];

let renderSeq = 0;
let firstRender = true;
let focusAfterSignin = false;

function parseHash() {
  const raw = location.hash.replace(/^#/, '');
  const q = raw.indexOf('?');
  let path = q < 0 ? raw : raw.slice(0, q);
  if (!path || path === '/') path = '/overview';
  if (!path.startsWith('/')) path = `/${path}`;
  return { path, params: new URLSearchParams(q < 0 ? '' : raw.slice(q + 1)) };
}

function setHashQuiet(path, params) {
  const qs = params ? new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString() : '';
  history.replaceState(null, '', `#${path}${qs ? `?${qs}` : ''}`);
}

function setActiveNav(key) {
  for (const a of document.querySelectorAll('[data-nav]')) {
    if (a.dataset.nav === key) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
}

async function route({ soft = false } = {}) {
  if (!token) return;
  const { path, params } = parseHash();
  let page = null;
  let match = null;
  for (const p of PAGES) {
    match = path.match(p.re);
    if (match) { page = p; break; }
  }
  if (!page) { location.replace('#/overview'); return; }
  const seq = ++renderSeq;
  setActiveNav(page.nav);
  closeNav(false);
  const main = $('#main');
  const scrollY = window.scrollY;
  const focusKey = soft ? document.activeElement?.closest?.('[data-focus-key]')?.dataset.focusKey : null;
  main.classList.add('is-loading');
  main.setAttribute('aria-busy', 'true');
  let view;
  try {
    view = await page.render({ match, params });
  } catch (err) {
    if (seq !== renderSeq) return;
    if (err?.status === 401) { main.classList.remove('is-loading'); main.removeAttribute('aria-busy'); return; }
    view = errorView(err, page.title);
  }
  if (seq !== renderSeq) return;
  main.classList.remove('is-loading');
  main.removeAttribute('aria-busy');
  main.replaceChildren(view);
  main.dataset.route = path;
  const title = view.dataset.title || page.title;
  document.title = `${title} · AgentGov`;
  $('#topbar-page').textContent = title;
  if (soft) {
    window.scrollTo(0, scrollY);
    const target = focusKey && main.querySelector(`[data-focus-key="${CSS.escape(focusKey)}"]`);
    if (target) target.focus({ preventScroll: true });
  } else {
    window.scrollTo(0, 0);
    if (!firstRender || focusAfterSignin) main.querySelector('h1')?.focus({ preventScroll: true });
  }
  firstRender = false;
  focusAfterSignin = false;
}

function refresh() {
  return route({ soft: true });
}

function errorView(err, title) {
  return h('div', { class: 'page error-view', 'data-title': title },
    pageHead({ title }),
    h('div', { class: 'callout', 'data-tone': 'critical', role: 'alert' }, icon('alert-circle'),
      h('div', { class: 'callout-body' },
        h('strong', {}, `${title} couldn't be loaded.`),
        h('span', {}, err?.message || String(err)),
        h('div', { class: 'btn-row', style: 'margin-top:6px' },
          h('button', { type: 'button', class: 'btn btn--sm', onclick: () => refresh() }, icon('refresh'), 'Try again')))));
}

/* --------------------------------------------------------------- shell */

function openNav() {
  const nav = $('#nav');
  nav.dataset.open = 'true';
  $('#scrim').hidden = false;
  $('#nav-toggle').setAttribute('aria-expanded', 'true');
  $('#nav-toggle').setAttribute('aria-label', 'Close navigation');
  (nav.querySelector('a[aria-current="page"]') || nav.querySelector('a')).focus();
}

function closeNav(returnFocus) {
  const nav = $('#nav');
  if (nav.dataset.open !== 'true') return;
  nav.dataset.open = 'false';
  $('#scrim').hidden = true;
  $('#nav-toggle').setAttribute('aria-expanded', 'false');
  $('#nav-toggle').setAttribute('aria-label', 'Open navigation');
  if (returnFocus) $('#nav-toggle').focus();
}

function syncThemeButton() {
  const mode = document.documentElement.dataset.theme || 'system';
  const slot = $('#theme-toggle [data-icon]');
  slot.replaceChildren(icon({ system: 'monitor', light: 'sun', dark: 'moon' }[mode]));
  $('#theme-label').textContent = `Theme: ${mode}`;
  $('#theme-toggle').setAttribute('aria-label', `Theme: ${mode}. Select to switch theme.`);
}

function cycleTheme() {
  const mode = document.documentElement.dataset.theme || 'system';
  const next = THEMES[(THEMES.indexOf(mode) + 1) % THEMES.length];
  applyTheme(next);
  writeStore('localStorage', THEME_KEY, next === 'system' ? null : next);
  syncThemeButton();
}

function showSignin(message) {
  $('#shell').hidden = true;
  $('.skip-link').hidden = true;
  $('#signin').hidden = false;
  const err = $('#signin-error');
  err.hidden = !message;
  err.textContent = message || '';
  const input = $('#token');
  input.value = '';
  input.focus();
  document.title = 'Sign in · AgentGov';
}

function enterApp() {
  $('#signin').hidden = true;
  $('.skip-link').hidden = false;
  $('#shell').hidden = false;
  firstRender = true;
  if (!location.hash || location.hash === '#' || location.hash === '#/') history.replaceState(null, '', '#/overview');
  route();
  refreshBadges();
  Promise.all([getInfo(), api('v1/me').catch(() => null)]).then(([info, me]) => {
    if (!info) return;
    $('#nav-meta').textContent = `AgentGov ${info.version} · ${info.identity_provider ? 'Keycloak identities' : 'no identity provider'} · OPA ${info.opa ? 'connected' : 'not configured'}${me ? ` · signed in as ${me.actor}` : ''}`;
  });
}

function signOut(message) {
  token = null;
  writeStore('sessionStorage', TOKEN_KEY, null);
  $('#toasts').replaceChildren();
  if ($('#dialog').open) $('#dialog').close();
  $('#main').replaceChildren(h('p', { class: 'loading-line' }, 'Signed out.'));
  showSignin(message);
}

function expireSession() {
  if (!token) return;
  signOut('Your API token was rejected. It may have been revoked or rotated. Sign in again.');
}

async function onSignin(event) {
  event.preventDefault();
  const input = $('#token');
  const err = $('#signin-error');
  const value = input.value.trim();
  if (!value) {
    err.textContent = 'Enter an API token.';
    err.hidden = false;
    input.focus();
    return;
  }
  const button = $('#signin-submit');
  button.disabled = true;
  button.textContent = 'Signing in…';
  try {
    token = value;
    const pending = await api('v1/approvals?status=pending', { signingIn: true });
    writeStore('sessionStorage', TOKEN_KEY, value);
    updateBadges({ pendingApprovals: pending.length });
    focusAfterSignin = true;
    enterApp();
  } catch (ex) {
    token = null;
    if (ex.status === 401) err.textContent = 'That token was not accepted. Check it for missing or extra characters, or ask an administrator for a new API key.';
    else if (ex.status === 403) err.textContent = `This token can't open the admin center (${ex.detail || 'its role is not allowed'}). Use an admin, approver or auditor key.`;
    else err.textContent = ex.message;
    err.hidden = false;
    input.focus();
    input.select();
  } finally {
    button.disabled = false;
    button.textContent = 'Sign in';
  }
}

function boot() {
  for (const slot of document.querySelectorAll('[data-icon]')) slot.replaceChildren(icon(slot.dataset.icon));
  syncThemeButton();
  $('#signin-form').addEventListener('submit', onSignin);
  // The skip link must not change the hash: the router would treat "#main" as a page.
  $('.skip-link').addEventListener('click', (e) => {
    e.preventDefault();
    $('#main').focus();
  });
  $('#token-toggle').addEventListener('click', (e) => {
    const input = $('#token');
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    e.currentTarget.textContent = show ? 'Hide' : 'Show';
    e.currentTarget.setAttribute('aria-pressed', String(show));
  });
  $('#nav-toggle').addEventListener('click', () => ($('#nav').dataset.open === 'true' ? closeNav(true) : openNav()));
  $('#scrim').addEventListener('click', () => closeNav(true));
  $('#signout').addEventListener('click', () => signOut('You signed out.'));
  $('#theme-toggle').addEventListener('click', cycleTheme);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && $('#nav').dataset.open === 'true') closeNav(true);
  });
  window.addEventListener('hashchange', () => route());
  if (token) enterApp();
  else showSignin();
}

/* =================================================================== pages */

/* ---------------------------------------------------------------- overview */

async function renderOverview() {
  const [ov, info] = await Promise.all([api('v1/overview'), getInfo()]);
  updateBadges({ pendingApprovals: ov.approvals?.pending ?? 0, findings: ov.findings });
  return h('div', { class: 'page' },
    pageHead({
      title: 'Overview',
      sub: 'Agent inventory, policy decisions and evidence for this control plane.',
      actions: [ledgerBadge(ov.ledger), refreshButton()],
    }),
    kpiTiles(ov),
    h('div', { class: 'grid-2 grid-2--even' }, activityCard(ov.activity || []), decisionsCard(ov.decisions_24h || {})),
    h('div', { class: 'grid-2 grid-2--even' }, recentBlocksCard(ov.recent_blocks || []), riskyCard(ov.top_risky || [])),
    controlPlaneCard(ov, info));
}

function ledgerBadge(lg) {
  if (!lg) {
    return h('a', { class: 'ledger-badge', 'data-tone': 'neutral', href: '#/ledger' },
      icon('ledger'), h('span', {}, h('strong', {}, 'Ledger not checked'), ' · verify it on the Ledger page'));
  }
  if (lg.valid) {
    return h('a', { class: 'ledger-badge', 'data-tone': 'good', href: '#/ledger', title: `Chain head ${lg.head}` },
      icon('shield-check'),
      h('span', {}, h('strong', {}, 'Ledger intact'), ` · ${plural(lg.checked, 'entry', 'entries')} · `,
        h('span', { class: 'hash' }, shortHash(lg.head, 6, 4))));
  }
  return h('a', { class: 'ledger-badge', 'data-tone': 'critical', href: '#/ledger' },
    icon('octagon'), h('span', {}, h('strong', {}, `Ledger broken at #${lg.broken_at}`), ` · ${lg.problem}`));
}

function kpiTiles(ov) {
  const agents = ov.agents || {};
  const findings = ov.findings || {};
  const byStatus = agents.by_status || {};
  const statusNote = ['active', 'pending', 'blocked', 'discovered']
    .filter((k) => byStatus[k]).map((k) => `${fmt(byStatus[k])} ${k}`).join(' · ') || 'No agents registered yet';
  const bySev = findings.by_severity || {};
  const topSeverity = SEVERITY_ORDER.find((k) => bySev[k]);
  const sevNote = SEVERITY_ORDER.filter((k) => bySev[k]).map((k) => {
    const [tone, ic, label] = statusMeta('severity', k);
    return h('span', { class: 'sev-count' }, icon(ic, { cls: `t-${tone}` }), `${fmt(bySev[k])} ${label.toLowerCase()}`);
  });
  const pending = ov.approvals?.pending ?? 0;
  const tiles = [
    { label: 'Total agents', value: agents.total, note: statusNote, href: '#/agents' },
    {
      label: 'Agents without owners', value: agents.without_owner, href: '#/agents?owner=none',
      note: agents.without_owner ? 'Assign an owning team or person' : 'Every managed agent has an owner',
      tone: agents.without_owner ? 'warning' : null,
    },
    {
      label: 'Unmanaged agents', value: agents.unmanaged, href: '#/agents?status=discovered',
      note: agents.unmanaged ? 'Seen at runtime, never registered' : 'No unregistered agents seen',
      tone: agents.unmanaged ? 'serious' : null,
    },
    {
      label: 'Agents at risk', value: agents.at_risk, href: '#/agents?risk=elevated',
      note: 'High or critical risk score', tone: agents.at_risk ? 'serious' : null,
    },
    {
      label: 'Pending approvals', value: pending, href: '#/approvals',
      note: pending ? 'Tool calls waiting for a reviewer' : 'Nothing waiting for review', tone: pending ? 'warning' : null,
    },
    {
      label: 'Open findings', value: findings.open, href: '#/findings',
      note: sevNote.length ? sevNote : 'No open findings', tone: topSeverity ? toneOf('severity', topSeverity) : null,
    },
  ];
  const flags = { warning: 'alert-circle', serious: 'triangle', critical: 'octagon' };
  return h('section', { class: 'kpis', 'aria-label': 'Key figures' }, tiles.map((t) => {
    const tone = t.tone === 'neutral' ? null : t.tone;
    return h('a', { class: 'kpi', href: t.href, 'data-tone': tone },
      h('span', { class: 'kpi-label' }, t.label),
      tone ? h('span', { class: 'kpi-flag' }, icon(flags[tone] || 'info', { label: 'Needs attention' })) : null,
      h('span', { class: 'kpi-value' }, fmt(t.value ?? 0)),
      h('span', { class: 'kpi-note' }, t.note));
  }));
}

function niceScale(max, ticks = 4) {
  if (max <= 0) return { top: 4, step: 1 };
  const raw = max / ticks;
  const mag = Math.max(1, 10 ** Math.floor(Math.log10(raw)));
  const step = [1, 2, 5, 10].map((f) => f * mag).find((st) => st >= raw) || mag * 10;
  return { top: Math.ceil(max / step) * step, step };
}

function barPath(x, y, w, height, r) {
  if (height <= 0) return '';
  const rr = Math.min(r, w / 2, height);
  return `M${x},${y + height}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + height}Z`;
}

function activityChart(days) {
  const totals = days.reduce((acc, d) => ({ calls: acc.calls + d.tool_calls, denied: acc.denied + d.denied }), { calls: 0, denied: 0 });
  const live = h('p', { class: 'sr-only', 'aria-live': 'polite' });
  const box = h('div', {
    class: 'chart', tabindex: '0', role: 'group',
    'aria-label': `Tool calls per day for the last 14 days: ${plural(totals.calls, 'call')}, ${fmt(totals.denied)} denied. Use the left and right arrow keys to read each day.`,
  });
  const tip = tooltip(box);
  let geo = null;
  let active = -1;

  function draw(width) {
    const height = 214;
    const m = { t: 22, r: 6, b: 26, l: 36 };
    const pw = Math.max(40, width - m.l - m.r);
    const ph = height - m.t - m.b;
    const peak = Math.max(0, ...days.map((d) => d.tool_calls));
    const { top, step } = niceScale(peak);
    const y = (v) => m.t + ph - (v / top) * ph;
    const band = pw / Math.max(1, days.length);
    const bw = Math.min(24, Math.max(4, band * 0.6));
    const svg = s('svg', { width, height, viewBox: `0 0 ${width} ${height}`, 'aria-hidden': 'true', focusable: 'false' });
    const hover = s('rect', { x: m.l, y: m.t - 4, width: band, height: ph + 4, rx: 4, style: 'fill: var(--chart-hover)', visibility: 'hidden' });
    svg.append(hover);
    for (let v = 0; v <= top; v += step) {
      const yy = Math.round(y(v)) + 0.5;
      svg.append(s('line', { x1: m.l, x2: width - m.r, y1: yy, y2: yy, style: `stroke: var(${v === 0 ? '--chart-axis' : '--chart-grid'}); stroke-width: 1` }));
      svg.append(s('text', { x: m.l - 8, y: yy + 4, 'text-anchor': 'end', class: 'axis-label' }, fmt(v)));
    }
    let peakIndex = -1;
    days.forEach((d, i) => {
      if (d.tool_calls > 0 && d.tool_calls >= (days[peakIndex]?.tool_calls ?? 0)) peakIndex = i;
    });
    const every = band < 34 ? 2 : 1;
    let prevMonth = null;
    const base = y(0);
    days.forEach((d, i) => {
      const x = m.l + band * i + (band - bw) / 2;
      const calls = d.tool_calls;
      const denied = Math.min(d.denied, calls);
      if (calls > 0) {
        const yt = y(calls);
        if (denied > 0) {
          const yd = y(denied);
          const all = denied >= calls;
          svg.append(s('path', { d: barPath(x, yd, bw, base - yd, all ? 4 : 0), style: 'fill: var(--critical)' }));
          const gapBottom = yd - 2; // 2px surface gap between the stacked segments
          if (!all && gapBottom - yt > 0.5) svg.append(s('path', { d: barPath(x, yt, bw, gapBottom - yt, 4), style: 'fill: var(--chart-context)' }));
        } else {
          svg.append(s('path', { d: barPath(x, yt, bw, base - yt, 4), style: 'fill: var(--chart-context)' }));
        }
      }
      if ((days.length - 1 - i) % every === 0) {
        const date = new Date(`${d.day}T00:00:00Z`);
        const month = date.getUTCMonth();
        const label = month !== prevMonth ? dayFmt.format(date) : String(date.getUTCDate());
        prevMonth = month;
        svg.append(s('text', { x: m.l + band * i + band / 2, y: height - 8, 'text-anchor': 'middle', class: 'axis-label' }, label));
      }
    });
    if (peakIndex >= 0) {
      const d = days[peakIndex];
      svg.append(s('text', { x: m.l + band * peakIndex + band / 2, y: y(d.tool_calls) - 7, 'text-anchor': 'middle', class: 'data-label' }, fmt(d.tool_calls)));
    } else {
      svg.append(s('text', { x: m.l + pw / 2, y: m.t + ph / 2, 'text-anchor': 'middle', class: 'chart-note' }, 'No tool calls in the last 14 days'));
    }
    box.querySelector('svg')?.remove();
    box.prepend(svg);
    geo = { m, band, y, hover };
    if (active >= 0) show(active);
  }

  function show(i) {
    if (!geo || !days[i]) return;
    active = i;
    const d = days[i];
    const { m, band, y, hover } = geo;
    hover.setAttribute('x', m.l + band * i);
    hover.setAttribute('width', band);
    hover.setAttribute('visibility', 'visible');
    const date = new Date(`${d.day}T00:00:00Z`);
    tip.show([
      h('div', { class: 'tooltip-title' }, dayLongFmt.format(date)),
      tipRow('var(--chart-context)', d.tool_calls, d.tool_calls === 1 ? 'tool call' : 'tool calls'),
      tipRow('var(--critical)', d.denied, 'denied'),
      tipRow(null, d.model_calls, d.model_calls === 1 ? 'model call' : 'model calls'),
    ], m.l + band * i + band / 2, y(d.tool_calls));
    live.textContent = `${dayLongFmt.format(date)}: ${plural(d.tool_calls, 'tool call')}, ${fmt(d.denied)} denied.`;
  }

  function hide() {
    active = -1;
    geo?.hover.setAttribute('visibility', 'hidden');
    tip.hide();
  }

  box.addEventListener('pointermove', (e) => {
    if (!geo) return;
    const rect = box.getBoundingClientRect();
    const i = Math.floor((e.clientX - rect.left - geo.m.l) / geo.band);
    if (i >= 0 && i < days.length) { if (i !== active) show(i); } else hide();
  });
  box.addEventListener('pointerleave', () => { if (document.activeElement !== box) hide(); });
  box.addEventListener('focus', () => show(active >= 0 ? active : days.length - 1));
  box.addEventListener('blur', hide);
  box.addEventListener('keydown', (e) => {
    const moves = { ArrowLeft: -1, ArrowRight: 1, Home: -Infinity, End: Infinity };
    if (e.key === 'Escape') { hide(); return; }
    if (!(e.key in moves)) return;
    e.preventDefault();
    const current = active >= 0 ? active : days.length - 1;
    show(Math.max(0, Math.min(days.length - 1, current + moves[e.key])));
  });
  box.append(live);
  observeWidth(box, draw);
  return box;
}

function activityCard(days) {
  const total = days.reduce((sum, d) => sum + d.tool_calls, 0);
  const denied = days.reduce((sum, d) => sum + d.denied, 0);
  const tableId = nextId('activity-table');
  const table = h('div', { class: 'table-wrap chart-table', id: tableId, hidden: true },
    h('table', { class: 'data' },
      h('caption', {}, 'Tool calls per day (UTC)'),
      h('thead', {}, h('tr', {}, ['Day', 'Tool calls', 'Denied', 'Model calls'].map((t, i) => h('th', { scope: 'col', class: i ? 'num' : null }, t)))),
      h('tbody', {}, days.slice().reverse().map((d) => h('tr', {},
        h('td', {}, dayLongFmt.format(new Date(`${d.day}T00:00:00Z`))),
        h('td', { class: 'num' }, fmt(d.tool_calls)),
        h('td', { class: 'num' }, fmt(d.denied)),
        h('td', { class: 'num' }, fmt(d.model_calls)))))));
  const toggle = h('button', { type: 'button', class: 'btn btn--sm btn--ghost', 'aria-expanded': 'false', 'aria-controls': tableId }, 'Show table');
  toggle.addEventListener('click', () => {
    const open = table.hidden;
    table.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
    toggle.textContent = open ? 'Hide table' : 'Show table';
  });
  return card({
    title: 'Tool calls',
    sub: `Last 14 days, all agents · ${plural(total, 'call')}, ${fmt(denied)} denied`,
    actions: [toggle],
    body: [
      h('div', { class: 'legend', 'aria-hidden': 'true' },
        h('span', { class: 'legend-item' }, h('span', { class: 'swatch', style: 'background: var(--chart-context)' }), 'Tool calls'),
        h('span', { class: 'legend-item' }, h('span', { class: 'swatch', style: 'background: var(--critical)' }), 'Denied (part of tool calls)')),
      activityChart(days),
      table,
    ],
  });
}

const DECISION_META = {
  allow: { tone: 'good', icon: 'check-circle', label: 'Allowed' },
  require_approval: { tone: 'warning', icon: 'user-check', label: 'Held for approval' },
  deny: { tone: 'critical', icon: 'ban', label: 'Denied' },
};

function decisionsCard(decisions) {
  const keys = ['allow', 'require_approval', 'deny', ...Object.keys(decisions).filter((k) => !(k in DECISION_META))];
  const rows = keys.map((key) => {
    const meta = DECISION_META[key] || { tone: 'neutral', icon: 'minus', label: key === 'none' ? 'No effect recorded' : humanize(key) };
    return { key, count: decisions[key] || 0, ...meta, color: TONE_COLOR[meta.tone] };
  });
  const total = rows.reduce((sum, r) => sum + r.count, 0);
  const pct = (n) => `${total ? Math.round((n / total) * 100) : 0}%`;
  let body;
  if (!total) {
    body = emptyState('No decisions in the last 24 hours', 'Policy decisions appear here as agents call tools through the gateway.');
  } else {
    const holder = h('div', { class: 'chart' });
    const tip = tooltip(holder);
    const bar = h('div', { class: 'splitbar', role: 'img', 'aria-label': rows.map((r) => `${r.label}: ${r.count}`).join(', ') },
      rows.filter((r) => r.count).map((r) => {
        const seg = h('span', { style: `flex: ${r.count} 1 0px; background: ${r.color}` });
        seg.addEventListener('pointerenter', () => tip.show([
          h('div', { class: 'tooltip-row' }, h('span', { class: 'tooltip-key', style: `border-color: ${r.color}` }),
            h('strong', {}, fmt(r.count)), `${r.label.toLowerCase()} · ${pct(r.count)}`),
        ], seg.offsetLeft + seg.offsetWidth / 2, 0));
        seg.addEventListener('pointerleave', () => tip.hide());
        return seg;
      }));
    holder.prepend(bar);
    body = [
      h('div', {}, h('div', { class: 'hero-figure' }, fmt(total)), h('p', { class: 'hero-caption' }, 'tool calls decided by policy')),
      holder,
      h('ul', { class: 'split-legend', role: 'list' }, rows.map((r) => h('li', {},
        icon(r.icon, { cls: `t-${r.tone}` }), h('span', {}, r.label),
        h('span', { class: 'count' }, fmt(r.count)), h('span', { class: 'pct' }, pct(r.count))))),
    ];
  }
  return card({ title: 'Decisions', sub: 'Last 24 hours', body });
}

function recentBlocksCard(entries) {
  // The ledger records both the approval request and the gateway decision for one held call.
  const seen = new Set();
  const items = entries.filter((e) => {
    const key = e.details?.approval_id;
    if (!key) return true;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 6);
  const body = items.length
    ? h('ul', { class: 'feed', role: 'list' }, items.map((e) => h('li', {},
      h('div', { class: 'feed-top' },
        chip('decision', e.decision),
        h('span', { class: 'resource' }, e.resource || e.type),
        e.agent_name ? agentLink(e.agent_id, e.agent_name) : null,
        h('span', { class: 'feed-meta' }, timeEl(e.ts))),
      e.reason ? h('p', { class: 'feed-reason clamp-2' }, e.reason) : null)))
    : emptyState('No blocked calls yet', 'Denied calls and calls held for approval show up here.');
  return card({
    title: 'Recent blocks',
    sub: 'Latest denied calls and calls held for approval',
    actions: [h('a', { class: 'btn btn--sm btn--ghost', href: '#/ledger?decision=deny' }, 'Open ledger', icon('arrow'))],
    body, flush: Boolean(items.length),
  });
}

function riskyCard(list) {
  const body = list.length
    ? h('ul', { class: 'risk-list', role: 'list' }, list.map((a) => {
      const tone = toneOf('risk', a.risk_level);
      return h('li', {},
        h('a', { href: agentHref(a.id), class: 'cell-title break' }, a.name),
        chip('risk', a.risk_level, { extra: a.risk_score }),
        h('div', { class: 'meter', role: 'img', 'aria-label': `Risk score ${a.risk_score} of 100`, style: `background: var(--${tone}-tint)` },
          h('span', { style: `width: ${Math.min(100, a.risk_score)}%; background: ${TONE_COLOR[tone]}` })));
    }))
    : emptyState('No agents at risk', 'No agent has a high or critical risk score right now.');
  return card({
    title: 'Agents at risk', sub: 'Highest risk scores first (out of 100)',
    actions: [h('a', { class: 'btn btn--sm btn--ghost', href: '#/agents?risk=elevated' }, 'View all', icon('arrow'))],
    body, flush: Boolean(list.length),
  });
}

function controlPlaneCard(ov, info) {
  const ts = ov.toolservers || {};
  const cell = (title, value, note, href) => h('div', {},
    h('span', { class: 'cp-title' }, title),
    href ? h('a', { class: 'cp-value', href }, value) : h('span', { class: 'cp-value' }, value),
    note ? h('span', { class: 'small muted' }, note) : null);
  return h('section', { class: 'card', 'aria-labelledby': 'cp-title' },
    h('div', { class: 'card-head' }, h('div', { class: 'card-head-text' },
      h('h2', { id: 'cp-title' }, 'Control plane'),
      h('p', { class: 'card-sub' }, 'Where policy is enforced and evidence is kept'))),
    h('div', { class: 'cp-grid', style: 'margin-top:12px; border-top:1px solid var(--line)' },
      cell('Tool servers', plural(ts.total || 0, 'server'),
        `${plural(ts.tools || 0, 'tool')} in catalogs · ${fmt(ts.pending)} pending · ${fmt(ts.blocked)} blocked`, '#/toolservers'),
      cell('Policy bundle', ov.opa?.bundle_revision ? h('span', { class: 'hash', title: `Bundle revision ${ov.opa.bundle_revision}` }, `rev ${String(ov.opa.bundle_revision).slice(0, 12)}`) : 'Not built',
        ov.opa?.last_status_at ? ['OPA reported ', timeEl(ov.opa.last_status_at)] : 'No OPA status report received by this control plane'),
      cell('Evidence ledger', ov.ledger ? plural(ov.ledger.checked, 'entry', 'entries') : 'Not verified',
        ov.ledger?.head ? ['Head ', h('span', { class: 'hash', title: ov.ledger.head }, shortHash(ov.ledger.head))] : null, '#/ledger'),
      cell('Gateway', info?.gateway_url ? copyable(info.gateway_url, 'gateway URL') : 'Not configured',
        info ? `Unregistered callers: ${info.unknown_agent_mode}` : null)));
}

/* ------------------------------------------------------------------ agents */

const AGENT_STATUS_FILTERS = [
  ['all', 'All'], ['active', 'Active'], ['pending', 'Pending'], ['blocked', 'Blocked'],
  ['discovered', 'Discovered'], ['deleted', 'Deleted'],
];

async function renderAgents({ params }) {
  const state = {
    status: params.get('status') || 'all',
    owner: params.get('owner') || '',
    risk: params.get('risk') || '',
    q: params.get('q') || '',
  };
  const load = (q) => api(`v1/agents?include_deleted=true${q ? `&q=${encodeURIComponent(q)}` : ''}`);
  let agents = await load(state.q);

  const tableHost = h('div', {});
  const countEl = h('p', { class: 'result-count', 'aria-live': 'polite' });
  const chipHost = h('div', { class: 'seg', role: 'group', 'aria-label': 'Filter by status' });
  const extraHost = h('div', { class: 'chip-row' });
  const search = h('input', {
    type: 'search', id: 'agent-search', placeholder: 'Search names and descriptions', value: state.q,
    'data-focus-key': 'agent-search', autocomplete: 'off',
  });

  function sync() {
    setHashQuiet('/agents', { status: state.status === 'all' ? '' : state.status, owner: state.owner, risk: state.risk, q: state.q });
  }

  function apply() {
    const counts = countBy(agents, 'status');
    const live = agents.filter((a) => a.status !== 'deleted').length;
    chipHost.replaceChildren(...AGENT_STATUS_FILTERS.map(([key, label]) => {
      const n = key === 'all' ? live : counts[key] || 0;
      return h('button', {
        type: 'button', class: 'seg-btn', 'aria-pressed': String(state.status === key), 'data-focus-key': `status-${key}`,
        onclick: () => { state.status = key; apply(); sync(); },
      }, label, h('span', { class: 'count' }, fmt(n)));
    }));
    const extras = [];
    if (state.owner === 'none') extras.push(['Without an owner', () => { state.owner = ''; }]);
    if (state.risk === 'elevated') extras.push(['High or critical risk', () => { state.risk = ''; }]);
    extraHost.replaceChildren(...extras.map(([label, clear]) => h('span', { class: 'active-filter' }, label,
      h('button', { type: 'button', 'aria-label': `Remove filter: ${label}`, onclick: () => { clear(); apply(); sync(); search.focus(); } }, icon('x')))));

    let rows = agents.filter((a) => (state.status === 'all' ? a.status !== 'deleted' : a.status === state.status));
    if (state.owner === 'none') rows = rows.filter((a) => !a.owner && a.status !== 'discovered');
    if (state.risk === 'elevated') rows = rows.filter((a) => ['high', 'critical'].includes(a.risk?.level));
    countEl.textContent = plural(rows.length, 'agent');
    tableHost.replaceChildren(rows.length ? agentsTable(rows) : emptyState('No agents match these filters',
      state.q ? `Nothing matches "${state.q}".` : 'Try another status.',
      h('button', {
        type: 'button', class: 'btn btn--sm',
        onclick: async () => {
          Object.assign(state, { status: 'all', owner: '', risk: '', q: '' });
          search.value = '';
          agents = await load('');
          apply();
          sync();
        },
      }, 'Clear filters')));
  }

  let timer = null;
  let searchSeq = 0;
  search.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const mine = ++searchSeq;
      state.q = search.value.trim();
      try {
        const next = await load(state.q);
        if (mine !== searchSeq) return;
        agents = next;
        apply();
        sync();
      } catch (err) {
        toast(err.message, { tone: 'critical' });
      }
    }, 250);
  });

  apply();
  return h('div', { class: 'page' },
    pageHead({
      title: 'Agents',
      sub: 'Every agent identity the control plane knows about: registered, pending review, blocked, and discovered at runtime without registration.',
      actions: [refreshButton()],
    }),
    h('div', { class: 'filters' },
      h('div', { class: 'field' }, h('label', { for: 'agent-search', class: 'sr-only' }, 'Search agents'), search),
      chipHost, extraHost, countEl),
    h('section', { class: 'card', 'aria-label': 'Agent list' }, tableHost));
}

function agentsTable(rows) {
  const table = h('table', { class: 'data rtable' },
    h('thead', {}, h('tr', {}, ['Agent', 'Status', 'Risk', 'Owner', 'Blueprint', 'Last seen'].map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', {}, rows.map((a) => {
      const href = agentHref(a.id);
      const tr = h('tr', { class: 'is-link' },
        h('td', { 'data-label': 'Agent' }, h('a', { class: 'cell-title break', href }, a.name),
          a.description ? h('div', { class: 'cell-sub clamp-2' }, a.description) : null),
        h('td', { 'data-label': 'Status' }, chip('agent', a.status)),
        h('td', { 'data-label': 'Risk' }, riskChip(a.risk)),
        h('td', { 'data-label': 'Owner', class: 'break' }, a.owner || h('span', { class: 'muted' }, a.status === 'discovered' ? 'Unassigned' : 'No owner')),
        h('td', { 'data-label': 'Blueprint' }, a.blueprint || h('span', { class: 'muted' }, 'None')),
        h('td', { 'data-label': 'Last seen', class: 'nowrap' }, timeEl(a.last_seen_at, { empty: 'Never' })));
      tr.addEventListener('click', (e) => {
        if (e.target.closest('a, button') || getSelection().toString()) return;
        location.hash = href;
      });
      return tr;
    })));
  return h('div', { class: 'table-wrap' }, table);
}

/* ------------------------------------------------------------ agent detail */

const LIFECYCLE = {
  approve: {
    label: 'Approve', icon: 'check', cls: 'btn--primary', tone: 'primary', confirm: 'Approve agent',
    text: 'The agent becomes active and can call the tools its blueprint and grants allow. Activation needs at least one sponsor.',
    done: (n) => `Approved ${n}. It is now active.`,
  },
  block: {
    label: 'Block (kill switch)', icon: 'power', cls: 'btn--danger', tone: 'danger', confirm: 'Block agent',
    text: 'This is the kill switch. The gateway refuses every call from this agent as soon as OPA loads the updated policy bundle, usually within seconds. You can unblock it later.',
    done: (n) => `Blocked ${n}. Its tool calls are refused.`,
  },
  unblock: {
    label: 'Unblock', icon: 'undo', cls: 'btn--primary', tone: 'primary', confirm: 'Unblock agent',
    text: 'Calls from this agent will be evaluated against policy again.',
    done: (n) => `Unblocked ${n}.`,
  },
  delete: {
    label: 'Delete', icon: 'trash', cls: 'btn--danger-quiet', tone: 'danger', confirm: 'Delete agent',
    text: 'The agent leaves the inventory and policy denies all of its calls. Deleted agents can be restored.',
    done: (n) => `Deleted ${n}.`,
  },
  restore: {
    label: 'Restore', icon: 'undo', cls: 'btn--primary', tone: 'primary', confirm: 'Restore agent',
    text: 'The agent comes back as pending review. Approve it to make it active again.',
    done: (n) => `Restored ${n}. It is pending review.`,
  },
  adopt: {
    label: 'Adopt', icon: 'user-check', cls: 'btn--primary', tone: 'primary', confirm: 'Adopt agent',
    text: 'Adopting brings this unmanaged agent under governance as a pending registration. Give it an owner, at least one sponsor and a blueprint, then approve it.',
    done: (n) => `Adopted ${n}. It is pending review.`,
  },
};
const ACTIONS_BY_STATUS = {
  pending: ['approve', 'block', 'delete'],
  active: ['block', 'delete'],
  blocked: ['unblock', 'delete'],
  discovered: ['adopt', 'block', 'delete'],
  deleted: ['restore'],
};
const ATTESTABLE = new Set(['active', 'blocked', 'pending']);

async function renderAgent({ match }) {
  const ref = decodeURIComponent(match[1]);
  const agent = await api(`v1/agents/${encodeURIComponent(ref)}`);
  const [entries, openFindings] = await Promise.all([
    api(`v1/ledger?agent=${encodeURIComponent(agent.id)}&limit=12`).catch((e) => e),
    api(`v1/findings?status=open&agent=${encodeURIComponent(agent.id)}`).catch((e) => e),
  ]);
  return h('div', { class: 'page', 'data-title': agent.name },
    agentHeader(agent),
    h('div', { class: 'detail-grid' },
      h('div', { class: 'stack' }, permissionsCard(agent), agentLedgerCard(agent, entries), agentCardCard(agent)),
      h('div', { class: 'stack' }, riskCard(agent), peopleCard(agent), attestationCard(agent), identityCard(agent),
        agentFindingsCard(openFindings))));
}

function agentHeader(a) {
  const [, , statusLabel] = statusMeta('agent', a.status);
  const showReason = a.status_reason && a.status !== 'active';
  return h('header', { class: 'detail-head' },
    h('nav', { class: 'crumbs', 'aria-label': 'Breadcrumb' },
      h('a', { href: '#/agents' }, 'Agents'), icon('chevron'), h('span', { 'aria-current': 'page' }, a.name)),
    h('div', { class: 'title-row' }, h('h1', { tabindex: '-1' }, a.name), chip('agent', a.status), riskChip(a.risk)),
    a.description ? h('p', { style: 'color:var(--ink-2); max-width:72ch' }, a.description) : null,
    showReason ? callout(toneOf('agent', a.status), 'info', h('span', {}, h('strong', {}, `${statusLabel}: `), a.status_reason)) : null,
    agentToolbar(a));
}

function agentToolbar(a) {
  const buttons = (ACTIONS_BY_STATUS[a.status] || []).map((action) => {
    const spec = LIFECYCLE[action];
    return h('button', {
      type: 'button', class: `btn ${spec.cls}`, 'data-focus-key': `lifecycle-${action}`,
      onclick: () => runLifecycle(a, action),
    }, icon(spec.icon), spec.label);
  });
  if (ATTESTABLE.has(a.status)) {
    buttons.push(h('button', { type: 'button', class: 'btn', 'data-focus-key': 'attest', onclick: () => runAttest(a) }, icon('shield-check'), 'Attest'));
  }
  return h('div', { class: 'toolbar', role: 'group', 'aria-label': 'Agent actions' }, buttons);
}

async function runLifecycle(a, action) {
  const spec = LIFECYCLE[action];
  const fields = [];
  if (action === 'adopt') {
    const blueprints = await api('v1/blueprints').catch(() => []);
    fields.push(
      { id: 'owner', label: 'Owner', placeholder: 'Team or person accountable for the agent', value: a.owner || '' },
      { id: 'sponsors', label: 'Sponsors', placeholder: 'alice@example.com, bob@example.com', value: (a.sponsors || []).join(', '), hint: 'Separate people with commas. Approval needs at least one sponsor.' },
      {
        id: 'blueprint', label: 'Blueprint', type: 'select', value: a.blueprint || '',
        options: [{ value: '', label: 'No blueprint' }, ...blueprints.map((b) => ({ value: b.name, label: `${b.name} (${b.risk_tier} risk tier)` }))],
      },
    );
  }
  fields.push({ id: 'reason', label: 'Reason', type: 'textarea', hint: 'Recorded in the evidence ledger.' });
  const values = await ask({
    title: `${spec.label.replace(' (kill switch)', '')} ${a.name}?`,
    text: spec.text, tone: spec.tone, iconName: spec.icon, confirm: spec.confirm, fields,
  });
  if (!values) return;
  const body = {};
  if (values.reason) body.reason = values.reason;
  if (action === 'adopt') {
    if (values.owner) body.owner = values.owner;
    const sponsors = values.sponsors.split(',').map((x) => x.trim()).filter(Boolean);
    if (sponsors.length) body.sponsors = sponsors;
    if (values.blueprint) body.blueprint = values.blueprint;
  }
  try {
    await api(`v1/agents/${encodeURIComponent(a.id)}/${action}`, { method: 'POST', body });
    toast(spec.done(a.name));
    refreshBadges();
    await refresh();
  } catch (err) {
    toast(err.message, { tone: 'critical' });
  }
}

async function runAttest(a) {
  const values = await ask({
    title: `Attest ${a.name}?`,
    text: "Confirm that this agent is still needed and its access is still right. The next review date comes from the blueprint's attestation period (90 days without a blueprint).",
    iconName: 'shield-check', confirm: 'Attest',
    fields: [{ id: 'note', label: 'Note', type: 'textarea', hint: 'Recorded in the evidence ledger.' }],
  });
  if (!values) return;
  try {
    const updated = await api(`v1/agents/${encodeURIComponent(a.id)}/attest`, { method: 'POST', body: values.note ? { note: values.note } : {} });
    const due = updated.attestation?.expires_at;
    toast(`Attested ${a.name}.${due ? ` Next review due ${dateFmt.format(new Date(due))}.` : ''}`);
    await refresh();
  } catch (err) {
    toast(err.message, { tone: 'critical' });
  }
}

async function recalcRisk(a) {
  try {
    const r = await api(`v1/agents/${encodeURIComponent(a.id)}/risk/refresh`, { method: 'POST' });
    toast(`Risk recalculated for ${a.name}: ${r.score} of 100 (${r.level}).`);
    refreshBadges();
    await refresh();
  } catch (err) {
    toast(err.message, { tone: 'critical' });
  }
}

function permissionsCard(a) {
  const effective = a.effective_permissions || [];
  const own = new Map((a.permissions || []).map((g) => [g.server, new Set(g.tools)]));
  const broad = effective.some((g) => g.server === '*' && g.tools.includes('*'));
  const list = effective.length
    ? h('ul', { class: 'perm-list', role: 'list' }, effective.map((g) => h('li', {},
      h('span', { class: 'perm-server' }, g.server === '*' ? '* (any server)' : g.server),
      h('div', { class: 'chip-row' }, g.tools.map((t) => {
        const direct = own.get(g.server)?.has(t);
        return plainChip(t, { mono: true, tone: direct ? 'accent' : null, title: direct ? 'Granted to this agent directly' : `From blueprint ${a.blueprint || ''}`.trim() });
      })))))
    : h('p', { class: 'muted small' }, 'No tools are granted. Policy denies every tool call from this agent.');
  return card({
    title: 'Permissions',
    sub: 'Effective grants: the blueprint plus grants made to this agent. Tool patterns are globs.',
    body: [
      facts([
        ['Blueprint', a.blueprint ? h('a', { href: '#/policies' }, a.blueprint) : h('span', { class: 'muted' }, 'None assigned')],
        ['Declared risk tier', humanize(a.risk_tier)],
      ]),
      broad ? callout('warning', 'triangle', 'This agent may call every tool on every server (*/*). Replace the wildcard with the tools it needs.') : null,
      list,
      own.size ? h('p', { class: 'hint' }, 'Highlighted patterns are granted to this agent directly; the others come from its blueprint.') : null,
    ],
  });
}

function riskCard(a) {
  const risk = a.risk || {};
  const tone = toneOf('risk', risk.level);
  return card({
    title: 'Risk',
    sub: 'Posture factors plus runtime signals from the last 24 hours',
    actions: [h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'recalc', onclick: () => recalcRisk(a) }, icon('refresh'), 'Recalculate')],
    body: [
      h('div', { class: 'risk-head' },
        h('span', { class: 'hero-figure' }, fmt(risk.score ?? 0)), h('span', { class: 'of' }, 'of 100'), chip('risk', risk.level || 'low')),
      h('div', { class: 'meter', role: 'img', 'aria-label': `Risk score ${risk.score ?? 0} of 100`, style: `background: var(--${tone}-tint)` },
        h('span', { style: `width:${Math.min(100, risk.score ?? 0)}%; background:${TONE_COLOR[tone]}` })),
      (risk.factors || []).length
        ? h('ul', { class: 'factor-list', role: 'list' }, risk.factors.map((f) => h('li', {},
          h('span', {}, f.factor, f.detail ? h('span', { class: 'muted' }, ` · ${f.detail}`) : null),
          h('span', { class: 'factor-points' }, `+${f.points}`))))
        : h('p', { class: 'muted small' }, 'No risk factors.'),
      h('p', { class: 'hint' }, 'Levels: 25 medium, 50 high, 75 critical. Policy blocks agents at critical risk.'),
    ],
  });
}

function personRow(name, role) {
  return h('li', { class: 'person' }, h('span', { class: 'avatar', 'aria-hidden': 'true' }, initials(name)),
    h('span', { class: 'person-text' }, h('span', {}, name), h('span', { class: 'role' }, role)));
}

function peopleCard(a) {
  const managed = a.status !== 'discovered';
  const sponsors = a.sponsors || [];
  return card({
    title: 'Owner and sponsors',
    sub: 'The accountable team and the people who vouch for this agent',
    body: [
      a.owner ? h('ul', { class: 'people', role: 'list' }, personRow(a.owner, 'Owner'))
        : callout(managed ? 'warning' : 'neutral', managed ? 'alert-circle' : 'info',
          managed ? 'No owner. Assign an owning team or person.' : 'Unmanaged agents have no owner until someone adopts them.'),
      sponsors.length ? h('ul', { class: 'people', role: 'list' }, sponsors.map((p) => personRow(p, 'Sponsor')))
        : callout(managed ? 'warning' : 'neutral', managed ? 'alert-circle' : 'info',
          'No sponsor. An agent needs at least one sponsor before it can be activated.'),
    ],
  });
}

function attestationCard(a) {
  const att = a.attestation || {};
  let status;
  if (!att.expires_at) {
    status = callout('neutral', 'info', 'No review is scheduled. A review date is set when the agent is approved or attested.');
  } else {
    const days = (new Date(att.expires_at).getTime() - Date.now()) / 86400000;
    if (days < 0) status = callout('critical', 'octagon', h('span', {}, h('strong', {}, 'Review overdue. '), `The attestation expired ${relTime(att.expires_at)}.`));
    else if (days < 14) status = callout('warning', 'clock', h('span', {}, h('strong', {}, 'Review due soon. '), `Due ${relTime(att.expires_at)}.`));
    else status = callout('good', 'check-circle', h('span', {}, 'Next review due ', h('strong', {}, dateFmt.format(new Date(att.expires_at))), ` (${relTime(att.expires_at)}).`));
  }
  return card({
    title: 'Attestation',
    sub: 'Periodic confirmation by a sponsor that the agent is still needed',
    actions: ATTESTABLE.has(a.status) ? [h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'attest-card', onclick: () => runAttest(a) }, icon('shield-check'), 'Attest')] : null,
    body: [status, facts([
      ['Last attested', att.attested_at ? [timeEl(att.attested_at), att.attested_by ? ` by ${att.attested_by}` : ''] : h('span', { class: 'muted' }, 'Never')],
      ['Review due', att.expires_at ? h('time', { datetime: att.expires_at, title: fullFmt.format(new Date(att.expires_at)) }, dateFmt.format(new Date(att.expires_at))) : null],
    ])],
  });
}

function identityCard(a) {
  const id = a.identity || {};
  const labels = Object.entries(a.labels || {});
  const external = Object.entries(a.external_ids || {});
  return card({
    title: 'Identity',
    sub: 'The OAuth client the gateway authenticates this agent with',
    body: [
      id.error ? callout('critical', 'octagon', h('strong', {}, 'Identity out of sync. '), id.error) : null,
      facts([
        ['Provider', humanize(id.provider || 'none')],
        ['Client ID', id.client_id ? copyable(id.client_id, 'client ID') : h('span', { class: 'muted' }, a.status === 'discovered' ? 'Not issued (unmanaged)' : 'Not issued')],
        ['Synced', id.synced_at ? timeEl(id.synced_at) : h('span', { class: 'muted' }, 'Not synced yet')],
        ['Agent ID', copyable(a.id, 'agent ID')],
        ['Source', a.source],
        ['Framework', a.framework],
        ['Environment', a.environment],
        a.platform ? ['Platform', a.platform] : null,
        (a.models || []).length ? ['Models', h('div', { class: 'chip-row' }, a.models.map((m) => plainChip(m, { mono: true })))] : null,
        labels.length ? ['Labels', h('div', { class: 'chip-row' }, labels.map(([k, v]) => plainChip(`${k}=${v}`, { mono: true })))] : null,
        external.length ? ['External IDs', h('div', { class: 'chip-row' }, external.map(([k, v]) => plainChip(`${k}: ${v}`, { mono: true })))] : null,
        ['Created', [timeEl(a.created_at), a.created_by ? ` by ${a.created_by}` : '']],
        ['Last seen', timeEl(a.last_seen_at, { empty: 'Never' })],
        a.deleted_at ? ['Deleted', timeEl(a.deleted_at)] : null,
      ]),
    ],
  });
}

function agentCardCard(a) {
  const ac = a.agent_card;
  if (!ac) {
    return card({ title: 'A2A agent card', sub: 'Skills and interfaces the agent advertises', body: h('p', { class: 'muted small' }, 'This agent has not published an A2A agent card.') });
  }
  const skills = Array.isArray(ac.skills) ? ac.skills : [];
  return card({
    title: 'A2A agent card',
    sub: [ac.name || a.name, ac.version ? ` · version ${ac.version}` : ''],
    body: [
      skills.length ? h('ul', { class: 'factor-list', role: 'list' }, skills.map((sk) => h('li', {},
        h('span', {}, h('strong', {}, sk.name || sk.id), sk.description ? h('span', { class: 'muted' }, ` · ${sk.description}`) : null),
        h('span', { class: 'chip-row' }, (sk.tags || []).map((t) => plainChip(t)))))) : null,
      h('details', { class: 'disclosure' }, h('summary', {}, icon('chevron'), 'Show agent card JSON'), jsonBlock(ac)),
    ],
  });
}

function agentLedgerCard(a, entries) {
  const body = entries instanceof Error
    ? callout('critical', 'alert-circle', `The ledger couldn't be loaded. ${entries.message}`)
    : entries.length
      ? ledgerTable(entries, { compact: true })
      : emptyState('No ledger entries', 'Lifecycle changes and tool-call decisions for this agent appear here.');
  return card({
    title: 'Recent activity',
    sub: 'Latest evidence-ledger entries for this agent',
    actions: [h('a', { class: 'btn btn--sm btn--ghost', href: `#/ledger?agent=${encodeURIComponent(a.name)}` }, 'Open in ledger', icon('arrow'))],
    body, flush: !(entries instanceof Error) && entries.length > 0,
  });
}

function agentFindingsCard(list) {
  if (list instanceof Error || !list.length) return null;
  const sorted = list.slice().sort((x, y) => SEVERITY_ORDER.indexOf(x.severity) - SEVERITY_ORDER.indexOf(y.severity));
  return card({
    title: 'Open findings',
    sub: plural(sorted.length, 'finding'),
    actions: [h('a', { class: 'btn btn--sm btn--ghost', href: '#/findings' }, 'All findings', icon('arrow'))],
    flush: true,
    body: h('ul', { class: 'feed', role: 'list' }, sorted.map((f) => h('li', {},
      h('div', { class: 'feed-top' }, chip('severity', f.severity), h('span', { class: 'feed-meta' }, timeEl(f.last_seen))),
      h('span', {}, f.title)))),
  });
}

/* --------------------------------------------------------------------- map */

function buildGraph(graph) {
  const nodes = new Map((graph.nodes || []).map((n) => [n.id, { ...n }]));
  const edges = (graph.edges || []).filter((e) => nodes.has(e.from) && nodes.has(e.to));
  const cols = { person: [], agent: [], server: [] };
  for (const n of nodes.values()) (cols[n.kind] || cols.agent).push(n);
  const statusRank = { active: 0, pending: 1, blocked: 2, discovered: 3 };
  const byLabel = (x, y) => String(x.label).localeCompare(String(y.label));
  cols.agent.sort((x, y) => (statusRank[x.status] ?? 9) - (statusRank[y.status] ?? 9) || byLabel(x, y));
  cols.person.sort(byLabel);
  cols.server.sort(byLabel);
  const maxLen = Math.max(1, cols.person.length, cols.agent.length, cols.server.length);
  const place = () => {
    for (const list of Object.values(cols)) list.forEach((n, i) => { n.slot = (maxLen - list.length) / 2 + i; });
  };
  place();
  const neighbours = new Map();
  for (const e of edges) {
    if (!neighbours.has(e.from)) neighbours.set(e.from, []);
    if (!neighbours.has(e.to)) neighbours.set(e.to, []);
    neighbours.get(e.from).push(e.to);
    neighbours.get(e.to).push(e.from);
  }
  const bary = (n) => {
    const ns = neighbours.get(n.id) || [];
    return ns.length ? ns.reduce((sum, id) => sum + nodes.get(id).slot, 0) / ns.length : n.slot;
  };
  // Deterministic barycentre sweeps reduce edge crossings without any randomness.
  for (let pass = 0; pass < 4; pass++) {
    for (const kind of ['person', 'server', 'agent']) {
      // Connected nodes first (ordered by barycentre); unconnected ones keep their order at the end.
      cols[kind] = cols[kind]
        .map((n) => [neighbours.has(n.id) ? 0 : 1, bary(n), n.slot, n])
        .sort((x, y) => x[0] - y[0] || x[1] - y[1] || x[2] - y[2])
        .map((x) => x[3]);
      place();
    }
  }
  // Final placement: the longest column fills rows 0..n-1; every other node sits at the
  // average row of its neighbours, pushed down just enough to keep one row between nodes.
  const settle = (list, anchorKinds) => {
    let prev = -1;
    for (const n of list) {
      const ns = (neighbours.get(n.id) || []).map((id) => nodes.get(id)).filter((m) => anchorKinds.includes(m.kind));
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
  const kinds = ['person', 'agent', 'server'];
  const anchor = kinds.reduce((best, k) => (cols[k].length > cols[best].length ? k : best), 'agent');
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

function nodeSubLabel(model, n) {
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

function describeNode(model, n) {
  const kind = { person: 'Person', agent: 'Agent', server: 'Tool server' }[n.kind] || 'Node';
  return `${kind} ${n.label}: ${nodeSubLabel(model, n)}`;
}

function bezierPoint(p0, p1, p2, p3, t) {
  const u = 1 - t;
  return u * u * u * p0 + 3 * u * u * t * p1 + 3 * u * t * t * p2 + t * t * t * p3;
}

function mapView(model, onFocusNode) {
  const holder = h('div', { class: 'map-scroll' });
  const hint = h('p', { class: 'map-hint', hidden: true }, 'The map is wider than this screen: scroll it sideways, or use the Connections table below.');
  let svg = null;
  let preview = null;
  let pinned = null;

  function highlight(id) {
    if (!svg) return;
    svg.classList.toggle('has-active', Boolean(id));
    const related = new Set(id ? [id, ...(model.neighbours.get(id) || [])] : []);
    for (const g of svg.querySelectorAll('.node')) {
      g.classList.toggle('is-related', related.has(g.dataset.id));
      g.classList.toggle('is-active', g.dataset.id === id);
    }
    for (const el of svg.querySelectorAll('.edge, .edge-tag')) {
      el.classList.toggle('is-related', Boolean(id) && (el.dataset.from === id || el.dataset.to === id));
    }
  }

  function update() {
    const id = preview || pinned;
    highlight(id);
    onFocusNode(id, pinned);
  }

  function draw(width) {
    const W = Math.max(620, width);
    const NODE_H = 46;
    const PITCH = 62;
    const TOP = 34;
    const height = TOP + model.maxLen * PITCH + 2;
    const nodeW = Math.min(210, Math.max(150, Math.floor((W - 8 - 2 * 76) / 3)));
    const xs = { person: 4, agent: Math.round((W - nodeW) / 2), server: W - 4 - nodeW };
    const pos = new Map();
    for (const [kind, list] of Object.entries(model.cols)) {
      for (const n of list) pos.set(n.id, { x: xs[kind], y: TOP + n.slot * PITCH });
    }
    svg = s('svg', { class: 'map-svg', width: W, height, viewBox: `0 0 ${W} ${height}`, role: 'group', 'aria-label': 'Agent map: people, agents and tool servers' });
    svg.append(
      s('text', { x: xs.person + 2, y: 14, class: 'col-label' }, 'PEOPLE'),
      s('text', { x: xs.agent + 2, y: 14, class: 'col-label' }, 'AGENTS'),
      s('text', { x: xs.server + 2, y: 14, class: 'col-label' }, 'TOOL SERVERS'));
    const edgeLayer = s('g', {});
    const tagLayer = s('g', {});
    const nodeLayer = s('g', {});
    svg.append(edgeLayer, tagLayer, nodeLayer);
    const maxCalls = Math.max(0, ...model.edges.map((e) => e.calls || 0));
    const gap = xs.agent - (xs.person + nodeW);
    for (const e of model.edges) {
      const a = pos.get(e.from);
      const b = pos.get(e.to);
      const x1 = a.x + nodeW;
      const y1 = a.y + NODE_H / 2;
      const x2 = b.x;
      const y2 = b.y + NODE_H / 2;
      const dx = (x2 - x1) / 2;
      const usage = e.kind === 'granted' || e.kind === 'ungranted';
      const widthPx = usage ? (e.calls > 0 && maxCalls > 0 ? 1.5 + 4.5 * (Math.log1p(e.calls) / Math.log1p(maxCalls)) : 1.25) : null;
      const from = model.nodes.get(e.from);
      const to = model.nodes.get(e.to);
      const relText = { owner: 'owns', sponsor: 'sponsors', granted: 'is granted', ungranted: 'used without a grant' }[e.kind] || e.kind;
      const tipText = `${from.label} ${relText} ${to.label}${usage ? ` · ${plural(e.calls || 0, 'call')} in 30 days, ${fmt(e.denied || 0)} denied` : ''}`;
      edgeLayer.append(s('path', {
        d: `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`,
        class: `edge edge-${e.kind}`, 'data-from': e.from, 'data-to': e.to,
        style: widthPx ? `stroke-width: ${widthPx.toFixed(2)}` : null,
      }, s('title', {}, tipText)));
      if (usage && e.calls > 0) {
        const full = e.denied ? `${fmt(e.calls)} calls · ${fmt(e.denied)} denied` : plural(e.calls, 'call');
        const text = full.length * 6 + 16 <= gap - 8 ? full : fmt(e.calls);
        const tw = text.length * 6 + 16;
        const px = bezierPoint(x1, x1 + dx, x2 - dx, x2, 0.5);
        const py = bezierPoint(y1, y1, y2, y2, 0.5);
        tagLayer.append(s('g', { class: 'edge-tag', 'data-from': e.from, 'data-to': e.to, transform: `translate(${px.toFixed(1)},${py.toFixed(1)})` },
          s('title', {}, tipText),
          s('rect', { x: -tw / 2, y: -9, width: tw, height: 18, rx: 9, class: 'edge-label-bg', style: e.denied ? 'stroke: var(--critical)' : null }),
          s('text', { x: 0, y: 4, 'text-anchor': 'middle', class: 'edge-label' }, text)));
      }
    }
    const clip = (t, x0, px) => {
      const max = Math.max(4, Math.floor((nodeW - x0 - 10) / px));
      return t.length > max ? `${t.slice(0, max - 1)}…` : t;
    };
    const ordered = ['person', 'agent', 'server'].flatMap((k) => model.cols[k].slice().sort((x, y) => x.slot - y.slot));
    for (const n of ordered) {
      const p = pos.get(n.id);
      const g = s('g', {
        class: 'node', tabindex: '0', role: 'button', 'data-id': n.id,
        'aria-label': describeNode(model, n), transform: `translate(${p.x},${p.y})`,
      });
      g.append(s('title', {}, describeNode(model, n)));
      g.append(s('rect', { class: 'node-focus', x: -3, y: -3, width: nodeW + 6, height: NODE_H + 6, rx: 10 }));
      let boxStyle = null;
      if (n.kind === 'agent' && (n.risk_level === 'high' || n.risk_level === 'critical')) {
        boxStyle = `stroke: ${TONE_COLOR[toneOf('risk', n.risk_level)]}; stroke-width: 1.75`;
      }
      g.append(s('rect', { class: 'node-box', width: nodeW, height: NODE_H, rx: 8, style: boxStyle }));
      if (n.kind === 'person') {
        g.append(s('circle', { class: 'node-avatar', cx: 22, cy: NODE_H / 2, r: 13 }));
        g.append(s('text', { class: 'node-initial', x: 22, y: NODE_H / 2 + 4, 'text-anchor': 'middle' }, initials(n.label)));
        g.append(s('text', { class: 'node-label', x: 42, y: 20 }, clip(n.label, 42, 7.6)));
        g.append(s('text', { class: 'node-sub', x: 42, y: 36 }, clip(nodeSubLabel(model, n), 42, 6.2)));
      } else {
        const tone = n.kind === 'server' ? toneOf('server', n.status) : toneOf('agent', n.status);
        g.append(s('path', { d: `M8,0 H4 A4,4 0 0 0 0,4 V${NODE_H - 4} A4,4 0 0 0 4,${NODE_H} H8 Z`, style: `fill: ${TONE_COLOR[tone]}` }));
        g.append(s('text', { class: 'node-label', x: 16, y: 20 }, clip(n.label, 16, 7.6)));
        g.append(s('text', { class: 'node-sub', x: 16, y: 36 }, clip(nodeSubLabel(model, n), 16, 6.2)));
      }
      nodeLayer.append(g);
    }
    svg.addEventListener('pointerover', (e) => {
      const g = e.target.closest?.('.node');
      if (g && g.dataset.id !== preview) { preview = g.dataset.id; update(); }
    });
    svg.addEventListener('pointerleave', () => { preview = null; update(); });
    svg.addEventListener('focusin', (e) => {
      const g = e.target.closest?.('.node');
      if (g) { preview = g.dataset.id; update(); }
    });
    svg.addEventListener('focusout', (e) => {
      if (!svg.contains(e.relatedTarget)) { preview = null; update(); }
    });
    svg.addEventListener('click', (e) => {
      const g = e.target.closest?.('.node');
      pinned = g ? (pinned === g.dataset.id ? null : g.dataset.id) : null;
      update();
    });
    svg.addEventListener('keydown', (e) => {
      const g = e.target.closest?.('.node');
      if (!g) return;
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        pinned = pinned === g.dataset.id ? null : g.dataset.id;
        update();
      } else if (e.key === 'Escape') {
        pinned = null;
        update();
      }
    });
    const focused = holder.contains(document.activeElement) ? document.activeElement?.dataset?.id : null;
    holder.replaceChildren(svg);
    hint.hidden = width >= W;
    if (focused) svg.querySelector(`.node[data-id="${CSS.escape(focused)}"]`)?.focus({ preventScroll: true });
    highlight(preview || pinned);
  }

  observeWidth(holder, draw);
  return [hint, holder];
}

function nodeDetail(model, id) {
  const all = [...model.nodes.values()];
  if (!id) {
    const counts = countBy(all, 'kind');
    const usage = model.edges.filter((e) => e.kind === 'granted' || e.kind === 'ungranted');
    const ungranted = usage.filter((e) => e.kind === 'ungranted');
    const busiest = usage.slice().sort((x, y) => (y.calls || 0) - (x.calls || 0))[0];
    return [
      facts([
        ['People', fmt(counts.person || 0)],
        ['Agents', fmt(counts.agent || 0)],
        ['Tool servers', fmt(counts.server || 0)],
        ['Ungranted use', ungranted.length ? h('span', { class: 'tone-text-critical' }, plural(ungranted.length, 'connection')) : 'None'],
        busiest && busiest.calls ? ['Busiest link', `${model.nodes.get(busiest.from).label} → ${model.nodes.get(busiest.to).label}: ${plural(busiest.calls, 'call')}, ${fmt(busiest.denied)} denied`] : null,
      ]),
      h('p', { class: 'hint' }, 'Point at, focus or select a node to trace its connections. Edge width follows call volume over the last 30 days.'),
    ];
  }
  const n = model.nodes.get(id);
  if (!n) return [];
  const rel = model.edges.filter((e) => e.from === id || e.to === id);
  const other = (e) => model.nodes.get(e.from === id ? e.to : e.from);
  const relLabel = (e) => ({
    owner: e.from === id ? 'owns' : 'owned by', sponsor: e.from === id ? 'sponsors' : 'sponsored by',
    granted: e.from === id ? 'granted' : 'granted to', ungranted: e.from === id ? 'used without grant' : 'used without grant by',
  }[e.kind] || e.kind);
  const conns = rel.length
    ? h('ul', { class: 'conn-list', role: 'list' }, rel.map((e) => {
      const o = other(e);
      const usage = e.kind === 'granted' || e.kind === 'ungranted';
      return h('li', {},
        h('span', { class: 'muted' }, relLabel(e)),
        o.kind === 'agent' ? agentLink(o.id.slice(6), o.label) : h('strong', {}, o.label),
        usage ? h('span', { class: 'muted' }, `· ${plural(e.calls || 0, 'call')}, ${fmt(e.denied || 0)} denied`) : null,
        e.kind === 'ungranted' ? plainChip('no grant', { tone: 'critical', iconName: 'ban' }) : null);
    }))
    : h('p', { class: 'muted small' }, 'No connections.');
  let head;
  let action = null;
  if (n.kind === 'agent') {
    head = [h('div', { class: 'chip-row' }, chip('agent', n.status), chip('risk', n.risk_level || 'low')),
      facts([['Blueprint', n.blueprint || h('span', { class: 'muted' }, 'None')]])];
    action = h('a', { class: 'btn btn--sm', href: agentHref(n.id.slice(6)) }, 'Open agent', icon('arrow'));
  } else if (n.kind === 'server') {
    head = [h('div', { class: 'chip-row' }, chip('server', n.status)),
      facts([['Classification', n.classification ? humanize(n.classification) : null], ['Trust', n.trust ? humanize(n.trust) : null]])];
    action = n.status === 'unregistered' ? null : h('a', { class: 'btn btn--sm', href: '#/toolservers' }, 'Open tool servers', icon('arrow'));
  } else {
    head = [h('p', { class: 'muted small' }, 'Owner or sponsor')];
  }
  return [h('h3', { class: 'break' }, n.label), ...head, h('div', { class: 'field-label' }, 'Connections'), conns, action];
}

function mapLegend() {
  const line = (cls, extra = '') => s('svg', { width: 28, height: 10, 'aria-hidden': 'true' }, s('path', { d: 'M1,5 H27', class: `edge ${cls}`, style: extra }));
  const stripe = (tone) => h('span', { class: 'swatch', style: `background:${TONE_COLOR[tone]}; width:6px; height:14px` });
  const item = (mark, label) => h('span', { class: 'legend-item' }, mark, label);
  return h('div', { class: 'map-legend' },
    item(line('edge-owner'), 'Owner'),
    item(line('edge-sponsor'), 'Sponsor'),
    item(line('edge-granted', 'stroke-width:3'), 'Granted (width = calls)'),
    item(line('edge-ungranted', 'stroke-width:2'), 'Used without a grant'),
    item(stripe('good'), 'Active / approved'),
    item(stripe('warning'), 'Pending review'),
    item(stripe('critical'), 'Blocked'),
    item(stripe('serious'), 'Discovered / unregistered'),
    item(h('span', { class: 'swatch', style: 'background:transparent; border:2px solid var(--serious); width:14px; height:12px; border-radius:3px' }), 'High-risk agent (outline)'));
}

async function renderMap() {
  const graph = await api('v1/graph');
  const model = buildGraph(graph);
  const detailBody = h('div', { class: 'card-body' });
  const detailTitle = h('h2', { id: 'map-detail-title' }, 'Summary');
  const setDetail = (id, pinned) => {
    detailTitle.textContent = id ? (id === pinned ? 'Selected' : 'Details') : 'Summary';
    fill(detailBody, nodeDetail(model, id));
  };
  setDetail(null, null);
  const view = model.nodes.size
    ? mapView(model, setDetail)
    : emptyState('Nothing to map yet', 'Register agents and tool servers to see who owns what and which tools each agent reaches.');
  const connections = connectionsTable(model);
  return h('div', { class: 'page' },
    pageHead({
      title: 'Agent map',
      sub: 'Who is accountable for each agent, and which tool servers each agent can reach or has used in the last 30 days.',
      actions: [refreshButton()],
    }),
    h('div', { class: 'map-layout' },
      card({ title: 'People, agents and tool servers', sub: 'Columns are fixed: accountable people on the left, tool servers on the right.', body: [mapLegend(), view] }),
      h('section', { class: 'card map-detail', 'aria-labelledby': 'map-detail-title', 'aria-live': 'polite' },
        h('div', { class: 'card-head' }, h('div', { class: 'card-head-text' }, detailTitle)), detailBody)),
    connections);
}

function connectionsTable(model) {
  if (!model.edges.length) return null;
  const order = { owner: 0, sponsor: 1, granted: 2, ungranted: 3 };
  const rows = model.edges.slice().sort((x, y) => String(model.nodes.get(x.from).label).localeCompare(String(model.nodes.get(y.from).label)) || order[x.kind] - order[y.kind]);
  const label = { owner: 'Owner of', sponsor: 'Sponsor of', granted: 'Granted', ungranted: 'Used without a grant' };
  const nameCell = (n) => (n.kind === 'agent' ? agentLink(n.id.slice(6), n.label) : n.label);
  return card({
    title: 'Connections',
    sub: 'The same graph as a table',
    flush: true,
    body: h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
      h('thead', {}, h('tr', {}, ['From', 'Relation', 'To', 'Calls (30 days)', 'Denied'].map((t, i) => h('th', { scope: 'col', class: i > 2 ? 'num' : null }, t)))),
      h('tbody', {}, rows.map((e) => {
        const usage = e.kind === 'granted' || e.kind === 'ungranted';
        return h('tr', {},
          h('td', { 'data-label': 'From', class: 'break' }, nameCell(model.nodes.get(e.from))),
          h('td', { 'data-label': 'Relation' }, e.kind === 'ungranted' ? plainChip(label[e.kind], { tone: 'critical', iconName: 'ban' }) : label[e.kind]),
          h('td', { 'data-label': 'To', class: 'break' }, nameCell(model.nodes.get(e.to))),
          h('td', { 'data-label': 'Calls', class: 'num' }, usage ? fmt(e.calls || 0) : '—'),
          h('td', { 'data-label': 'Denied', class: 'num' }, usage ? fmt(e.denied || 0) : '—'));
      })))),
  });
}

/* --------------------------------------------------------------- approvals */

async function renderApprovals({ match }) {
  const tab = match[1] === 'history' ? 'history' : 'pending';
  const [all, agents] = await Promise.all([api('v1/approvals'), api('v1/agents?include_deleted=true').catch(() => [])]);
  const agentsById = new Map(agents.map((a) => [a.id, a]));
  const pending = all.filter((r) => r.status === 'pending');
  const history = all.filter((r) => r.status !== 'pending');
  updateBadges({ pendingApprovals: pending.length });
  const tabs = h('nav', { class: 'tabs', 'aria-label': 'Approval views' },
    h('a', { class: 'tab', href: '#/approvals', 'aria-current': tab === 'pending' ? 'page' : null },
      'Pending', h('span', { class: 'nav-badge', 'data-tone': pending.length ? 'warning' : '' }, fmt(pending.length))),
    h('a', { class: 'tab', href: '#/approvals/history', 'aria-current': tab === 'history' ? 'page' : null },
      'History', h('span', { class: 'nav-badge' }, fmt(history.length))));
  let content;
  if (tab === 'pending') {
    content = pending.length
      ? h('div', { class: 'approval-list' }, pending.map((r) => approvalCard(r, agentsById.get(r.agent_id))))
      : h('section', { class: 'card' }, emptyState('Nothing is waiting for approval',
        'When policy holds a tool call for a human (for example a tool its server marks destructive), it appears here.'));
  } else {
    content = h('section', { class: 'card', 'aria-label': 'Approval history' },
      history.length ? approvalHistoryTable(history) : emptyState('No decided approvals yet'));
  }
  return h('div', { class: 'page', 'data-title': tab === 'history' ? 'Approval history' : 'Approvals' },
    pageHead({
      title: 'Approvals',
      sub: 'Tool calls that policy held for a human decision. An approval is single-use: the agent retries the identical call and it goes through once.',
      actions: [refreshButton()],
    }),
    tabs, content);
}

function approvalCard(r, agent) {
  const noteId = `note-${r.id}`;
  const note = h('textarea', { id: noteId, rows: 1, placeholder: 'For example: confirmed with the customer', 'data-focus-key': noteId });
  const approveBtn = h('button', { type: 'button', class: 'btn btn--primary' }, icon('check'), 'Approve');
  const denyBtn = h('button', { type: 'button', class: 'btn btn--danger-quiet' }, icon('ban'), 'Deny');
  const decide = async (verdict) => {
    approveBtn.disabled = true;
    denyBtn.disabled = true;
    const text = note.value.trim();
    try {
      await api(`v1/approvals/${encodeURIComponent(r.id)}/${verdict}`, { method: 'POST', body: text ? { note: text } : {} });
      toast(verdict === 'approve'
        ? `Approved ${r.resource}. ${r.agent_name} can retry the call once.`
        : `Denied ${r.resource} for ${r.agent_name}.`);
      refreshBadges();
      await refresh();
    } catch (err) {
      toast(err.message, { tone: 'critical' });
      approveBtn.disabled = false;
      denyBtn.disabled = false;
    }
  };
  approveBtn.addEventListener('click', () => decide('approve'));
  denyBtn.addEventListener('click', () => decide('deny'));
  const agentWarning = agent && agent.status !== 'active'
    ? callout(toneOf('agent', agent.status), 'info',
      h('span', {}, h('strong', {}, `${agent.name} is ${statusMeta('agent', agent.status)[2].toLowerCase()}. `),
        'Policy denies its calls before approvals are checked, so approving changes nothing unless the agent becomes active before the request expires.'))
    : null;
  const headingId = nextId('approval');
  return h('section', { class: 'card approval', 'aria-labelledby': headingId, 'data-focus-key': `approval-${r.id}`, tabindex: '-1' },
    h('div', { class: 'card-head' },
      h('div', { class: 'card-head-text' },
        h('h2', { id: headingId, class: 'resource' }, r.resource),
        h('p', { class: 'card-sub' }, `${r.action} requested by `, agentLink(r.agent_id, r.agent_name), ' · ', timeEl(r.requested_at))),
      h('div', { class: 'chip-row' }, chip('approval', r.status),
        h('span', { class: 'chip chip--plain', title: r.expires_at ? fullFmt.format(new Date(r.expires_at)) : null }, icon('clock'), `Expires ${r.expires_at ? relTime(r.expires_at) : 'never'}`))),
    h('div', { class: 'card-body' },
      agentWarning,
      h('div', { class: 'approval-grid' },
        h('div', { class: 'stack', style: 'gap:8px' }, h('span', { class: 'field-label' }, 'Why it was held'),
          (r.reasons || []).length
            ? h('ul', { class: 'reasons', role: 'list' }, r.reasons.map((reason) => h('li', {}, icon('user-check'), h('span', {}, reason))))
            : h('p', { class: 'muted small' }, 'No reason recorded.')),
        h('div', { class: 'stack', style: 'gap:8px' }, h('span', { class: 'field-label' }, 'Arguments (redacted)'), jsonBlock(r.arguments ?? {}))),
      h('div', { class: 'decide' },
        h('div', { class: 'field' }, h('label', { for: noteId }, 'Note for the ledger ', h('span', { class: 'muted' }, '(optional)')), note),
        h('div', { class: 'btn-row' }, denyBtn, approveBtn))));
}

function approvalHistoryTable(rows) {
  return h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
    h('thead', {}, h('tr', {}, ['Outcome', 'Tool call', 'Agent', 'Decided by', 'Decided', 'Note', 'Requested'].map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', {}, rows.map((r) => h('tr', {},
      h('td', { 'data-label': 'Outcome' }, chip('approval', r.status, { title: r.used_at ? `Used ${fullFmt.format(new Date(r.used_at))}` : null })),
      h('td', { 'data-label': 'Tool call' }, h('span', { class: 'resource' }, r.resource)),
      h('td', { 'data-label': 'Agent', class: 'break' }, agentLink(r.agent_id, r.agent_name)),
      h('td', { 'data-label': 'Decided by', class: 'break' }, r.decided_by || h('span', { class: 'muted' }, r.status === 'expired' ? 'Nobody (expired)' : '—')),
      h('td', { 'data-label': 'Decided', class: 'nowrap' }, timeEl(r.decided_at)),
      h('td', { 'data-label': 'Note', class: 'break' }, r.decision_note || h('span', { class: 'muted' }, '—')),
      h('td', { 'data-label': 'Requested', class: 'nowrap' }, timeEl(r.requested_at)))))));
}

/* ------------------------------------------------------------ tool servers */

const openCatalogs = new Set();
const ANNOTATION_LABELS = {
  readOnlyHint: ['Read-only', null],
  destructiveHint: ['Destructive', 'warning'],
  idempotentHint: ['Idempotent', null],
  openWorldHint: ['Open world', null],
};

function isChanged(t) {
  return Boolean(t.changed_at) || Boolean(t.approved_fingerprint && t.fingerprint && t.approved_fingerprint !== t.fingerprint);
}

async function renderToolservers() {
  const servers = await api('v1/toolservers');
  return h('div', { class: 'page' },
    pageHead({
      title: 'Tool servers',
      sub: 'MCP servers published through the gateway. AgentGov fingerprints every tool definition when it is first seen and quarantines tools that change or carry hidden instructions.',
      actions: [refreshButton()],
    }),
    servers.length
      ? h('div', { class: 'stack' }, servers.map(serverCard))
      : h('section', { class: 'card' }, emptyState('No tool servers registered', 'Register an MCP server with POST /v1/toolservers or a ToolServer manifest.')));
}

function serverCard(ts) {
  const tools = ts.tools || [];
  const poisoned = tools.filter((t) => t.poisoned);
  const changed = tools.filter(isChanged);
  if (!openCatalogs.has(`init:${ts.name}`)) {
    openCatalogs.add(`init:${ts.name}`);
    if (poisoned.length || changed.length) openCatalogs.add(ts.name);
  }
  const catalogId = `catalog-${ts.id}`;
  const catalog = h('div', { id: catalogId, hidden: !openCatalogs.has(ts.name) }, toolTable(ts));
  const toggle = h('button', {
    type: 'button', class: 'btn btn--sm', 'aria-expanded': String(openCatalogs.has(ts.name)), 'aria-controls': catalogId,
    'data-focus-key': `catalog-${ts.name}`,
  }, icon('chevron'), `${openCatalogs.has(ts.name) ? 'Hide' : 'Show'} tool catalog (${tools.length})`);
  toggle.addEventListener('click', () => {
    const open = catalog.hidden;
    catalog.hidden = !open;
    if (open) openCatalogs.add(ts.name); else openCatalogs.delete(ts.name);
    toggle.setAttribute('aria-expanded', String(open));
    toggle.lastChild.textContent = `${open ? 'Hide' : 'Show'} tool catalog (${tools.length})`;
  });
  const actions = [];
  if (ts.status === 'pending') actions.push(h('button', { type: 'button', class: 'btn btn--primary', 'data-focus-key': `ts-approve-${ts.name}`, onclick: () => serverAction(ts, 'approve') }, icon('check'), 'Approve'));
  if (ts.status === 'blocked') actions.push(h('button', { type: 'button', class: 'btn btn--primary', 'data-focus-key': `ts-unblock-${ts.name}`, onclick: () => serverAction(ts, 'unblock') }, icon('undo'), 'Unblock'));
  else actions.push(h('button', { type: 'button', class: 'btn btn--danger-quiet', 'data-focus-key': `ts-block-${ts.name}`, onclick: () => serverAction(ts, 'block') }, icon('power'), 'Block server'));
  const headingId = nextId('server');
  const trustChip = ts.trust_level === 'verified'
    ? plainChip('Verified', { tone: 'good', iconName: 'shield-check' })
    : plainChip(humanize(ts.trust_level || 'unverified'), { tone: 'warning', iconName: 'shield' });
  return h('section', { class: 'card', 'aria-labelledby': headingId },
    h('div', { class: 'card-body' },
      h('div', { class: 'server-head' },
        h('div', { class: 'server-title' },
          h('div', { class: 'title-row' }, h('h2', { id: headingId, class: 'tool-name' }, ts.name), chip('server', ts.status), trustChip,
            plainChip(humanize(ts.data_classification || 'unclassified'), { iconName: 'lock', title: 'Data classification' })),
          ts.description ? h('p', { style: 'color:var(--ink-2)' }, ts.description) : null),
        h('div', { class: 'btn-row' }, actions)),
      poisoned.length ? callout('critical', 'octagon', h('span', {}, h('strong', {}, `${plural(poisoned.length, 'tool')} quarantined. `),
        'Hidden instructions were found in the description, so the tool is hidden from agents and calls to it are denied. Block the server if the definition is malicious.')) : null,
      changed.length ? callout('warning', 'triangle', h('span', {}, h('strong', {}, `${plural(changed.length, 'tool')} changed since approval. `),
        'Calls are refused until an administrator approves the new definition.')) : null,
      facts([
        ['Gateway URL', ts.gateway_url ? copyable(ts.gateway_url, 'gateway URL') : h('span', { class: 'muted' }, 'Gateway public URL not configured')],
        ['Upstream', h('code', { class: 'break' }, ts.url || '—')],
        ['Owner', ts.owner],
        ['Catalog', `${plural(tools.length, 'tool')} · ${fmt(poisoned.length)} poisoned · ${fmt(changed.length)} changed`],
        ['Catalog synced', timeEl(ts.tools_synced_at, { empty: 'Not yet observed' })],
      ]),
      h('div', {}, toggle)),
    catalog);
}

function toolTable(ts) {
  const tools = ts.tools || [];
  if (!tools.length) return h('div', { style: 'border-top:1px solid var(--line)' }, emptyState('No tools observed yet', 'The catalog fills in when an agent lists this server\'s tools through the gateway.'));
  return h('div', { class: 'table-wrap', style: 'border-top:1px solid var(--line)' }, h('table', { class: 'data rtable' },
    h('caption', { class: 'sr-only' }, `Tool catalog for ${ts.name}`),
    h('thead', {}, h('tr', {}, ['Tool', 'Description', 'Annotations', 'Status', ''].map((t) => h('th', { scope: 'col' }, t || h('span', { class: 'sr-only' }, 'Actions'))))),
    h('tbody', {}, tools.map((t) => {
      const changed = isChanged(t);
      const ann = Object.entries(t.annotations || {}).filter(([, v]) => v === true);
      let status;
      if (t.poisoned) {
        status = h('div', { class: 'stack', style: 'gap:6px' }, chip('severity', 'critical', { title: 'Possible tool poisoning' }),
          h('div', { class: 'chip-row' }, (t.poisoning_reasons || []).map((r) => plainChip(humanize(r)))));
        status.firstChild.lastChild.textContent = 'Poisoned';
      } else if (changed) {
        status = h('div', { class: 'stack', style: 'gap:4px' }, plainChip('Changed since approval', { tone: 'warning', iconName: 'triangle' }),
          t.changed_at ? h('span', { class: 'xsmall muted' }, 'changed ', timeEl(t.changed_at)) : null);
      } else {
        status = plainChip('Matches approval', { tone: 'good', iconName: 'check-circle' });
      }
      const description = t.poisoned
        ? h('div', { class: 'quarantine' }, h('span', { class: 'quarantine-label' }, icon('octagon'), 'Hidden instructions found. Shown as plain text.'), h('pre', {}, t.description || ''))
        : h('p', { class: 'tool-desc small' }, t.description || h('span', { class: 'muted' }, 'No description'));
      return h('tr', {},
        h('td', { 'data-label': 'Tool' }, h('div', { class: 'tool-name' }, t.name),
          h('div', { class: 'fp', title: `Fingerprint ${t.fingerprint || ''}` }, shortHash(t.fingerprint, 8, 4))),
        h('td', { 'data-label': 'Description', style: 'max-width:420px' }, description),
        h('td', { 'data-label': 'Annotations' }, ann.length
          ? h('div', { class: 'chip-row' }, ann.map(([k]) => {
            const [label, tone] = ANNOTATION_LABELS[k] || [humanize(k.replace(/Hint$/, '')), null];
            return plainChip(label, { tone, iconName: tone ? 'triangle' : null, title: k });
          }))
          : h('span', { class: 'muted small' }, 'None')),
        h('td', { 'data-label': 'Status' }, status),
        h('td', { 'data-label': '' }, changed
          ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `approve-tool-${ts.name}-${t.name}`, onclick: () => approveTool(ts, t) }, icon('shield-check'), 'Approve new definition')
          : null));
    }))));
}

async function serverAction(ts, action) {
  const specs = {
    approve: { title: `Approve ${ts.name}?`, text: 'Agents whose grants cover this server can call its tools through the gateway.', confirm: 'Approve server', tone: 'primary', icon: 'check', done: `Approved ${ts.name}.` },
    block: { title: `Block ${ts.name}?`, text: "Every agent's calls to this server are refused once OPA loads the updated bundle. Its catalog is kept, and you can unblock it later.", confirm: 'Block server', tone: 'danger', icon: 'power', done: `Blocked ${ts.name}. Calls to it are refused.` },
    unblock: { title: `Unblock ${ts.name}?`, text: 'Calls to this server will be evaluated against policy again.', confirm: 'Unblock server', tone: 'primary', icon: 'undo', done: `Unblocked ${ts.name}.` },
  };
  const spec = specs[action];
  const ok = await ask({ title: spec.title, text: spec.text, confirm: spec.confirm, tone: spec.tone, iconName: spec.icon });
  if (!ok) return;
  try {
    await api(`v1/toolservers/${encodeURIComponent(ts.name)}/${action}`, { method: 'POST' });
    toast(spec.done);
    await refresh();
  } catch (err) {
    toast(err.message, { tone: 'critical' });
  }
}

async function approveTool(ts, t) {
  const ok = await ask({
    title: `Approve the new definition of ${t.name}?`,
    text: `Calls to ${ts.name}/${t.name} are refused until you accept its current definition. Read the description and annotations first: a changed definition is how an MCP "rug pull" starts.`,
    iconName: 'shield-check', confirm: 'Approve definition',
    extra: facts([
      ['Approved', h('code', { class: 'break' }, t.approved_fingerprint || '—')],
      ['Current', h('code', { class: 'break' }, t.fingerprint || '—')],
    ]),
  });
  if (!ok) return;
  try {
    await api(`v1/toolservers/${encodeURIComponent(ts.name)}/tools/${encodeURIComponent(t.name)}/approve`, { method: 'POST' });
    toast(`Approved the current definition of ${ts.name}/${t.name}.`);
    await refresh();
  } catch (err) {
    toast(err.message, { tone: 'critical' });
  }
}

/* ---------------------------------------------------------------- findings */

const FINDING_STATUS = [['open', 'Open'], ['resolved', 'Resolved'], ['dismissed', 'Dismissed'], ['all', 'All']];

async function renderFindings({ params }) {
  const state = {
    status: FINDING_STATUS.some(([k]) => k === params.get('status')) ? params.get('status') : 'open',
    severity: params.get('severity') || '',
    category: params.get('category') || '',
  };
  const [initial, agents] = await Promise.all([
    api(`v1/findings?status=${encodeURIComponent(state.status)}`),
    api('v1/agents?include_deleted=true').catch(() => []),
  ]);
  let list = initial;
  const agentsById = new Map(agents.map((a) => [a.id, a]));
  if (state.status === 'open') updateBadges({ findings: summarizeFindings(list) });

  const statusHost = h('div', { class: 'seg', role: 'group', 'aria-label': 'Finding status' });
  const sevHost = h('div', { class: 'seg', role: 'group', 'aria-label': 'Severity' });
  const category = h('select', { id: 'finding-category', 'data-focus-key': 'finding-category' },
    [['', 'All categories'], ['threat', 'Threats'], ['posture', 'Posture']].map(([v, l]) => h('option', { value: v, selected: v === state.category }, l)));
  const countEl = h('p', { class: 'result-count', 'aria-live': 'polite' });
  const listHost = h('div', { class: 'finding-list' });
  const listTitle = h('h2', { class: 'sr-only', tabindex: '-1', id: 'finding-list-title' }, 'Findings');

  const sync = () => setHashQuiet('/findings', { status: state.status === 'open' ? '' : state.status, severity: state.severity, category: state.category });

  async function reload() {
    list = await api(`v1/findings?status=${encodeURIComponent(state.status)}`);
    if (state.status === 'open') updateBadges({ findings: summarizeFindings(list) });
  }

  function apply() {
    statusHost.replaceChildren(...FINDING_STATUS.map(([key, label]) => h('button', {
      type: 'button', class: 'seg-btn', 'aria-pressed': String(state.status === key), 'data-focus-key': `fstatus-${key}`,
      onclick: async () => {
        state.status = key;
        sync();
        try { await reload(); } catch (err) { toast(err.message, { tone: 'critical' }); }
        apply();
      },
    }, label)));
    const scoped = list.filter((f) => !state.category || f.category === state.category);
    const bySev = countBy(scoped, 'severity');
    sevHost.replaceChildren(
      h('button', { type: 'button', class: 'seg-btn', 'aria-pressed': String(!state.severity), 'data-focus-key': 'sev-all', onclick: () => { state.severity = ''; apply(); sync(); } },
        'Any severity', h('span', { class: 'count' }, fmt(scoped.length))),
      ...SEVERITY_ORDER.filter((k) => bySev[k] || state.severity === k).map((k) => {
        const [tone, ic, label] = statusMeta('severity', k);
        return h('button', {
          type: 'button', class: 'seg-btn', 'aria-pressed': String(state.severity === k), 'data-focus-key': `sev-${k}`,
          onclick: () => { state.severity = k; apply(); sync(); },
        }, icon(ic, { cls: `t-${tone}` }), label, h('span', { class: 'count' }, fmt(bySev[k] || 0)));
      }));
    const rows = scoped
      .filter((f) => !state.severity || f.severity === state.severity)
      .sort((x, y) => SEVERITY_ORDER.indexOf(x.severity) - SEVERITY_ORDER.indexOf(y.severity) || String(y.last_seen).localeCompare(String(x.last_seen)));
    countEl.textContent = plural(rows.length, `${state.status === 'all' ? '' : `${state.status} `}finding`.trim());
    listHost.replaceChildren(...(rows.length
      ? rows.map((f) => findingCard(f, agentsById, async (action) => {
        try {
          await api(`v1/findings/${encodeURIComponent(f.id)}/${action}`, { method: 'POST' });
          toast(`${{ resolve: 'Resolved', dismiss: 'Dismissed', reopen: 'Reopened' }[action]}: ${f.title}`);
          const index = rows.indexOf(f);
          await reload();
          apply();
          const target = listHost.querySelector(`[data-focus-key="finding-${CSS.escape(f.id)}"]`)
            || listHost.querySelectorAll('.finding')[Math.min(index, listHost.querySelectorAll('.finding').length - 1)]
            || listTitle;
          target.focus();
          refreshBadges();
        } catch (err) {
          toast(err.message, { tone: 'critical' });
        }
      }))
      : [h('section', { class: 'card' }, emptyState(state.status === 'open' ? 'No open findings' : 'No findings match these filters',
        state.status === 'open' ? 'Posture scans and runtime detections raise findings here.' : null))]));
  }

  category.addEventListener('change', () => { state.category = category.value; apply(); sync(); });
  apply();
  return h('div', { class: 'page' },
    pageHead({
      title: 'Findings',
      sub: 'Posture gaps from scheduled scans and threats detected at runtime, most severe first.',
      actions: [refreshButton()],
    }),
    h('div', { class: 'filters' }, statusHost,
      h('div', { class: 'field', style: 'flex:0 1 180px' }, h('label', { for: 'finding-category', class: 'sr-only' }, 'Category'), category)),
    h('div', { class: 'filters' }, sevHost, countEl),
    listTitle,
    listHost);
}

function findingCard(f, agentsById, act) {
  const tone = toneOf('severity', f.severity);
  const agent = f.agent_id ? agentsById.get(f.agent_id) : null;
  const headingId = `finding-title-${f.id}`;
  const actions = f.status === 'open'
    ? [h('button', { type: 'button', class: 'btn btn--sm', onclick: () => act('dismiss') }, icon('minus'), 'Dismiss'),
      h('button', { type: 'button', class: 'btn btn--sm btn--primary', onclick: () => act('resolve') }, icon('check'), 'Resolve')]
    : [h('button', { type: 'button', class: 'btn btn--sm', onclick: () => act('reopen') }, icon('undo'), 'Reopen')];
  return h('article', { class: 'card finding', 'data-tone': tone, 'aria-labelledby': headingId, tabindex: '-1', 'data-focus-key': `finding-${f.id}` },
    h('div', { class: 'finding-stripe', 'aria-hidden': 'true' }),
    h('div', { class: 'finding-main' },
      h('div', { class: 'finding-top' }, chip('severity', f.severity), plainChip(humanize(f.category)),
        f.status !== 'open' ? chip('finding', f.status) : null, h('span', { class: 'ledger-type muted' }, f.type)),
      h('h3', { id: headingId, class: 'break' }, f.title),
      f.description ? h('p', { class: 'finding-desc small' }, f.description) : null,
      f.remediation ? h('p', { class: 'finding-fix' }, h('strong', {}, 'How to fix: '), f.remediation) : null,
      h('div', { class: 'finding-actions' },
        h('div', { class: 'finding-meta' },
          h('span', {}, 'Subject: ', f.agent_id ? agentLink(f.agent_id, agent?.name || f.subject) : h('code', {}, f.subject)),
          h('span', {}, `Seen ${f.occurrences === 1 ? 'once' : `${fmt(f.occurrences)} times`}`),
          h('span', {}, 'First ', timeEl(f.first_seen)),
          h('span', {}, 'Last ', timeEl(f.last_seen)),
          f.resolved_at ? h('span', {}, `${f.status === 'dismissed' ? 'Dismissed' : 'Resolved'} by ${f.resolved_by || 'unknown'} `, timeEl(f.resolved_at)) : null),
        h('div', { class: 'btn-row' }, actions))));
}

/* ---------------------------------------------------------------- policies */

async function renderPolicies() {
  const [blueprints, policies, agents, servers] = await Promise.all([
    api('v1/blueprints'), api('v1/policies'), api('v1/agents'), api('v1/toolservers'),
  ]);
  const usage = countBy(agents, (a) => a.blueprint || '');
  const exportBtn = h('button', { type: 'button', class: 'btn', 'data-focus-key': 'export-yaml' }, icon('download'), 'Export manifests');
  exportBtn.addEventListener('click', async () => {
    exportBtn.disabled = true;
    try {
      const blob = await saveDownload('v1/export', `agentgov-manifests-${fileStamp()}.yaml`);
      toast(`Exported blueprints, tool servers, policies and agents as YAML (${fmtBytes(blob.size)}).`);
    } catch (err) {
      toast(err.message, { tone: 'critical' });
    } finally {
      exportBtn.disabled = false;
    }
  });
  return h('div', { class: 'page' },
    pageHead({
      title: 'Policies',
      sub: 'Blueprints decide what each class of agent may call. Organisation Rego policies add rules on top of the built-in library, and OPA enforces both at the gateway.',
      actions: [exportBtn, refreshButton()],
    }),
    h('div', { class: 'policy-layout' },
      h('div', { class: 'stack' },
        h('section', { class: 'stack', 'aria-labelledby': 'bp-title' },
          h('div', { class: 'section-title' }, h('h2', { id: 'bp-title' }, 'Blueprints'), h('p', {}, 'IT-approved templates: permissions, risk tier, sponsor and review rules')),
          blueprints.length
            ? h('div', { class: 'bp-grid' }, blueprints.map((b) => blueprintCard(b, usage[b.name] || 0)))
            : h('section', { class: 'card' }, emptyState('No blueprints yet', 'Create one with POST /v1/blueprints or a Blueprint manifest.'))),
        h('section', { class: 'stack', 'aria-labelledby': 'rego-title' },
          h('div', { class: 'section-title' }, h('h2', { id: 'rego-title' }, 'Organisation policies'),
            h('p', {}, 'Rego modules under agentgov.custom that can add denials, approval requirements and redactions')),
          policies.length
            ? policies.map(policyCard)
            : h('section', { class: 'card' }, emptyState('No organisation policies', 'Only the built-in library (package agentgov.mcp) is enforced.')))),
      whatIfCard(agents, servers)));
}

function permissionList(grants) {
  if (!grants?.length) return h('p', { class: 'muted small' }, 'No tools granted.');
  return h('ul', { class: 'perm-list', role: 'list' }, grants.map((g) => h('li', {},
    h('span', { class: 'perm-server' }, g.server),
    h('div', { class: 'chip-row' }, g.tools.map((t) => plainChip(t, { mono: true }))))));
}

function blueprintCard(b, used) {
  const labels = Object.entries(b.labels || {});
  return card({
    title: b.name, level: 'h3', id: `bp-${b.id}`,
    sub: b.description,
    actions: [plainChip(`${humanize(b.risk_tier)} risk tier`, { tone: toneOf('risk', b.risk_tier === 'minimal' ? 'low' : b.risk_tier), iconName: statusMeta('risk', b.risk_tier === 'minimal' ? 'low' : b.risk_tier)[1] })],
    body: [
      facts([
        ['Used by', used ? h('a', { href: '#/agents' }, plural(used, 'agent')) : h('span', { class: 'muted' }, 'No agents')],
        ['Sponsor', b.require_sponsor ? 'Required before activation' : 'Not required'],
        ['Attestation', b.attestation_days ? `Every ${plural(b.attestation_days, 'day')}` : 'Not required'],
        labels.length ? ['Labels', h('div', { class: 'chip-row' }, labels.map(([k, v]) => plainChip(`${k}=${v}`, { mono: true })))] : null,
      ]),
      h('div', { class: 'field-label' }, 'Permissions'),
      permissionList(b.permissions),
    ],
  });
}

function policyCard(p) {
  return card({
    title: p.name, level: 'h3',
    sub: p.description,
    actions: [plainChip(p.enabled ? 'Enabled' : 'Disabled', { tone: p.enabled ? 'good' : null, iconName: p.enabled ? 'check-circle' : 'minus' }), plainChip(`v${p.version}`, { mono: true })],
    body: [
      facts([['Package', h('code', {}, p.package)], ['Updated', timeEl(p.updated_at)]]),
      h('details', { class: 'disclosure' }, h('summary', {}, icon('chevron'), 'View Rego source'),
        h('pre', { class: 'kv-pre rego', tabindex: '0' }, p.rego)),
    ],
  });
}

function whatIfCard(agents, servers) {
  const registered = agents.filter((a) => a.status !== 'discovered');
  const discovered = agents.filter((a) => a.status === 'discovered');
  const recent = (a) => (a.last_seen_at ? Date.parse(a.last_seen_at) : 0);
  const preferred = registered.filter((a) => a.status === 'active' && a.blueprint).sort((x, y) => recent(y) - recent(x))[0]
    || registered[0] || discovered[0];
  const agentSel = h('select', { id: 'wi-agent', name: 'agent' },
    registered.length ? h('optgroup', { label: 'Registered' }, registered.map((a) => h('option', { value: a.id, selected: a === preferred },
      `${a.name}${a.identity?.client_id ? ` (${a.identity.client_id})` : ''} · ${a.status}`))) : null,
    discovered.length ? h('optgroup', { label: 'Discovered (unmanaged)' }, discovered.map((a) => h('option', { value: a.id, selected: a === preferred }, `${a.name} · no client ID`))) : null,
    h('option', { value: '__unregistered' }, 'An unregistered caller'));
  const serverInput = h('input', { type: 'text', id: 'wi-server', list: 'wi-server-list', autocomplete: 'off', spellcheck: 'false' });
  const toolInput = h('input', { type: 'text', id: 'wi-tool', list: 'wi-tool-list', autocomplete: 'off', spellcheck: 'false' });
  const serverList = h('datalist', { id: 'wi-server-list' }, servers.map((ts) => h('option', { value: ts.name })));
  const toolList = h('datalist', { id: 'wi-tool-list' });
  const firstServer = servers.find((ts) => ts.status === 'approved') || servers[0];
  serverInput.value = firstServer?.name || '';
  const fillTools = () => {
    const ts = servers.find((x) => x.name === serverInput.value.trim());
    toolList.replaceChildren(...(ts?.tools || []).map((t) => h('option', { value: t.name })));
    return ts;
  };
  const ts0 = fillTools();
  const destructive = (ts0?.tools || []).find((t) => t.annotations?.destructiveHint && !t.poisoned);
  toolInput.value = destructive?.name || ts0?.tools?.[0]?.name || '';
  serverInput.addEventListener('change', fillTools);

  const phaseRequest = h('input', { type: 'radio', name: 'wi-phase', id: 'wi-phase-request', value: 'request', checked: true });
  const phaseResponse = h('input', { type: 'radio', name: 'wi-phase', id: 'wi-phase-response', value: 'response' });
  const pii = h('input', { type: 'checkbox', id: 'wi-pii', value: 'pii' });
  const secret = h('input', { type: 'checkbox', id: 'wi-secret', value: 'secret' });
  const injection = h('input', { type: 'checkbox', id: 'wi-injection' });
  const result = h('div', { class: 'stack', style: 'gap:12px', 'aria-live': 'polite' });
  const submit = h('button', { type: 'submit', class: 'btn btn--primary' }, icon('play'), 'Evaluate');

  function buildInput() {
    const agentId = agentSel.value;
    const agent = agents.find((a) => a.id === agentId);
    const categories = [pii, secret].filter((c) => c.checked).map((c) => c.value);
    const phase = phaseResponse.checked ? 'response' : 'request';
    return {
      phase,
      method: 'tools/call',
      agent: agentId === '__unregistered'
        ? { client_id: 'agent-not-registered' }
        : { agent_id: agent?.id, client_id: agent?.identity?.client_id || undefined },
      resource: { server: serverInput.value.trim(), name: toolInput.value.trim() },
      detections: { categories, prompt_injection: injection.checked, injection_score: injection.checked ? 0.95 : 0 },
    };
  }

  async function evaluate(example) {
    const input = buildInput();
    if (!input.resource.server || !input.resource.name) {
      result.replaceChildren(callout('warning', 'alert-circle', 'Choose a tool server and a tool to evaluate.'));
      return;
    }
    submit.disabled = true;
    try {
      const res = await api('v1/policies/evaluate', { method: 'POST', body: { input } });
      fill(result, whatIfResult(res, input, example));
    } catch (err) {
      result.replaceChildren(callout('critical', 'alert-circle', h('span', {}, h('strong', {}, "Couldn't evaluate. "), err.message)));
    } finally {
      submit.disabled = false;
    }
  }

  const form = h('form', { class: 'whatif-form', novalidate: true },
    h('div', { class: 'field' }, h('label', { for: 'wi-agent' }, 'Agent'), agentSel),
    h('div', { class: 'form-row' },
      h('div', { class: 'field' }, h('label', { for: 'wi-server' }, 'Tool server'), serverInput, serverList),
      h('div', { class: 'field' }, h('label', { for: 'wi-tool' }, 'Tool'), toolInput, toolList)),
    h('fieldset', { class: 'field' }, h('legend', { class: 'field-label' }, 'Phase'),
      h('div', { class: 'radio-row' },
        h('label', { class: 'check', for: 'wi-phase-request' }, phaseRequest, 'Request (the tool call)'),
        h('label', { class: 'check', for: 'wi-phase-response' }, phaseResponse, 'Response (the tool result)'))),
    h('fieldset', { class: 'field' }, h('legend', { class: 'field-label' }, 'Detections ', h('span', { class: 'muted' }, '(what Presidio and the detectors found)')),
      h('label', { class: 'check', for: 'wi-pii' }, pii, 'Personal data (pii)'),
      h('label', { class: 'check', for: 'wi-secret' }, secret, 'Credentials (secret)'),
      h('label', { class: 'check', for: 'wi-injection' }, injection, 'Prompt injection in the result')),
    h('div', { class: 'btn-row' }, submit));
  form.addEventListener('submit', (e) => { e.preventDefault(); evaluate(false); });
  if (agents.length || servers.length) evaluate(true);
  else result.replaceChildren(h('p', { class: 'muted small' }, 'Register an agent and a tool server to try a scenario.'));

  return h('section', { class: 'card whatif', 'aria-labelledby': 'whatif-title' },
    h('div', { class: 'card-head' }, h('div', { class: 'card-head-text' },
      h('h2', { id: 'whatif-title' }, 'What if'),
      h('p', { class: 'card-sub' }, 'Ask the live OPA what it would decide for a tool call. Nothing is recorded.'))),
    h('div', { class: 'card-body' }, form, h('hr', { style: 'border:0; border-top:1px solid var(--line); margin:4px 0; width:100%' }), result));
}

function whatIfResult(res, input, example) {
  const r = res?.result;
  if (!r) {
    return [callout('warning', 'alert-circle', `OPA returned no decision for ${res?.path || 'agentgov/mcp/decision'}. Check that the AgentGov policy bundle is loaded.`)];
  }
  const meta = {
    allow: ['good', 'check-circle', 'Allow', 'The call would go through.'],
    deny: ['critical', 'ban', 'Deny', 'The gateway would refuse the call.'],
    require_approval: ['warning', 'user-check', 'Require approval', 'The call would wait for a human approval.'],
  }[r.effect] || ['neutral', 'info', humanize(r.effect), ''];
  const [tone, ic, label, sub] = meta;
  return [
    example ? h('p', { class: 'example-tag' }, 'Example: the scenario filled in above, evaluated when the page loaded.') : null,
    h('div', { class: 'effect', 'data-tone': tone }, icon(ic),
      h('div', {}, h('div', { class: 'effect-label' }, label), h('div', { class: 'effect-sub' }, sub))),
    (r.reasons || []).length
      ? h('div', { class: 'stack', style: 'gap:6px' }, h('span', { class: 'field-label' }, 'Reasons'),
        h('ul', { class: 'reasons', role: 'list' }, r.reasons.map((reason) => h('li', {}, icon(r.effect === 'deny' ? 'ban' : 'user-check'), h('span', {}, reason)))))
      : null,
    facts([
      ['Redact', (r.redact || []).length ? h('div', { class: 'chip-row' }, r.redact.map((c) => plainChip(c, { mono: true }))) : 'Nothing'],
      ['Agent seen as', r.agent ? [r.agent.name, ` · ${r.agent.status} · ${r.agent.risk_level} risk`] : h('span', { class: 'muted' }, 'Not a registered agent')],
      ['Policy path', h('code', {}, res.path)],
    ]),
    h('details', { class: 'disclosure' }, h('summary', {}, icon('chevron'), 'Show OPA input and result'),
      h('div', { class: 'stack', style: 'gap:8px' }, jsonBlock({ input }), jsonBlock(r))),
  ];
}

/* ------------------------------------------------------------------ ledger */

const LEDGER_TYPES = [
  ['', 'All events'], ['decision.*', 'Policy decisions'], ['approval.*', 'Approvals'], ['agent.*', 'Agent lifecycle'],
  ['toolserver.*', 'Tool servers'], ['policy.*', 'Organisation policies'], ['blueprint.*', 'Blueprints'], ['apikey.*', 'API keys'],
];
const LEDGER_DECISIONS = [['', 'Any decision'], ['allow', 'Allowed'], ['deny', 'Denied'], ['require_approval', 'Needs approval']];
const PAGE_SIZE = 100;

function ledgerDetail(e) {
  return h('div', { class: 'stack', style: 'gap:10px; padding: 4px 0 6px' },
    facts([
      ['Event ID', h('code', {}, e.id)],
      ['Time', timeEl(e.ts, { absolute: true })],
      ['Severity', humanize(e.severity)],
      ['Action', e.action ? h('code', {}, e.action) : null],
      e.trace_id ? ['Trace ID', h('code', {}, e.trace_id)] : null,
      ['Hash', h('code', { class: 'hash break' }, e.hash)],
      ['Previous hash', h('code', { class: 'hash break' }, e.prev_hash)],
    ]),
    Object.keys(e.details || {}).length ? jsonBlock(e.details) : null);
}

const clockFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
const shortDayFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });

function ledgerTime(iso) {
  const date = new Date(iso);
  return h('time', { datetime: iso, title: fullFmt.format(date) },
    h('span', { class: 'num' }, clockFmt.format(date)), h('span', { class: 'cell-sub' }, shortDayFmt.format(date)));
}

function ledgerRows(entries, { compact = false } = {}) {
  const cols = compact ? 4 : 6;
  const dash = () => h('span', { class: 'muted' }, '—');
  return entries.flatMap((e) => {
    const detailId = `ledger-detail-${e.seq}`;
    const toggle = h('button', { type: 'button', class: 'expander', 'aria-expanded': 'false', 'aria-controls': detailId },
      icon('chevron'), `#${e.seq}`, h('span', { class: 'sr-only' }, ' details'));
    // The actor is only worth showing when it is not the agent itself (an admin, the system, a service).
    const actorIsAgent = e.agent_name && e.actor === `agent:${e.agent_name}`;
    const event = h('td', { 'data-label': 'Event', class: 'break' },
      h('span', { class: 'ledger-type' }, e.severity === 'warning' ? h('span', { class: 'sev-dot', title: 'Warning' }) : null, e.type),
      e.resource ? h('div', { class: 'cell-sub' }, h('code', {}, e.resource)) : null,
      compact && e.reason ? h('div', { class: 'cell-sub clamp-2', title: e.reason }, e.reason) : null);
    const row = h('tr', {},
      h('td', { 'data-label': 'Seq', class: 'nowrap' }, toggle),
      h('td', { 'data-label': 'Time', class: 'nowrap' }, ledgerTime(e.ts)),
      event,
      compact ? null : h('td', { 'data-label': 'Agent', class: 'break col-agent' },
        e.agent_name ? agentLink(e.agent_id, e.agent_name) : null,
        actorIsAgent ? null : h('div', { class: e.agent_name ? 'cell-sub nowrap' : null }, e.agent_name ? `by ${e.actor}` : e.actor)),
      h('td', { 'data-label': 'Decision', class: e.decision ? null : 'is-empty' }, e.decision ? chip('decision', e.decision) : dash()),
      compact ? null : h('td', { 'data-label': 'Reason', class: e.reason ? 'break' : 'is-empty' }, e.reason ? h('span', { class: 'clamp-2', title: e.reason }, e.reason) : dash()));
    const detail = h('tr', { class: 'row-detail', id: detailId, hidden: true }, h('td', { colspan: cols, 'data-label': '' }, ledgerDetail(e)));
    toggle.addEventListener('click', () => {
      const open = toggle.getAttribute('aria-expanded') !== 'true';
      toggle.setAttribute('aria-expanded', String(open));
      detail.hidden = !open;
      row.classList.toggle('is-open', open);
    });
    return [row, detail];
  });
}

function ledgerTable(entries, { compact = false } = {}) {
  const heads = compact
    ? ['Seq', 'Time', 'Event', 'Decision']
    : ['Seq', 'Time', 'Event and resource', 'Agent / actor', 'Decision', 'Reason'];
  const tbody = h('tbody', {}, ledgerRows(entries, { compact }));
  const wrap = h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
    h('thead', {}, h('tr', {}, heads.map((t) => h('th', { scope: 'col' }, t)))), tbody));
  wrap.tbody = tbody;
  return wrap;
}

async function renderLedger({ params }) {
  const state = { agent: params.get('agent') || '', type: params.get('type') || '', decision: params.get('decision') || '' };
  const agents = await api('v1/agents?include_deleted=true').catch(() => []);
  const query = (before) => {
    const p = new URLSearchParams({ limit: String(PAGE_SIZE) });
    if (state.agent) p.set('agent', state.agent);
    if (state.type) p.set('type', state.type);
    if (state.decision) p.set('decision', state.decision);
    if (before) p.set('before_seq', String(before));
    return api(`v1/ledger?${p}`);
  };

  const agentInput = h('input', { type: 'text', id: 'ledger-agent', list: 'ledger-agent-list', value: state.agent, placeholder: 'Any agent', autocomplete: 'off', spellcheck: 'false', 'data-focus-key': 'ledger-agent' });
  const agentList = h('datalist', { id: 'ledger-agent-list' }, agents.map((a) => h('option', { value: a.name })));
  const typeSel = h('select', { id: 'ledger-type', 'data-focus-key': 'ledger-type' }, LEDGER_TYPES.map(([v, l]) => h('option', { value: v, selected: v === state.type }, l)));
  const decisionSel = h('select', { id: 'ledger-decision', 'data-focus-key': 'ledger-decision' }, LEDGER_DECISIONS.map(([v, l]) => h('option', { value: v, selected: v === state.decision }, l)));
  const banner = h('div', { class: 'verify-banner', 'aria-live': 'polite' });
  const tableHost = h('div', {});
  const countEl = h('p', { class: 'result-count', 'aria-live': 'polite' });
  let shown = [];

  const verifyBtn = h('button', { type: 'button', class: 'btn btn--primary', 'data-focus-key': 'verify' }, icon('shield-check'), 'Verify chain');
  verifyBtn.addEventListener('click', async () => {
    verifyBtn.disabled = true;
    banner.replaceChildren(callout('neutral', 'clock', 'Recomputing every hash from the genesis entry…'));
    try {
      const v = await api('v1/ledger/verify');
      banner.replaceChildren(v.valid
        ? callout('good', 'shield-check', h('span', {}, h('strong', {}, 'Chain intact. '),
          `Recomputed ${plural(v.checked, 'hash', 'hashes')} from the genesis entry; nothing was edited, removed or reordered. Head `,
          h('code', { class: 'hash', title: v.head }, shortHash(v.head)), '.'))
        : callout('critical', 'octagon', h('span', {}, h('strong', {}, `Chain broken at entry #${v.broken_at}. `),
          `${cap(v.problem)}. The ${plural(v.checked, 'entry', 'entries')} before it verified; entries from #${v.broken_at} on can't be trusted.`)));
    } catch (err) {
      banner.replaceChildren(callout('critical', 'alert-circle', err.message));
    } finally {
      verifyBtn.disabled = false;
    }
  });

  const exportBtn = h('button', { type: 'button', class: 'btn', 'data-focus-key': 'export-jsonl' }, icon('download'), 'Export JSONL');
  exportBtn.addEventListener('click', async () => {
    exportBtn.disabled = true;
    try {
      const blob = await saveDownload('v1/ledger/export', `agentgov-ledger-${fileStamp()}.jsonl`);
      toast(`Exported the full ledger as JSON Lines (${fmtBytes(blob.size)}).`);
    } catch (err) {
      toast(err.message, { tone: 'critical' });
    } finally {
      exportBtn.disabled = false;
    }
  });

  function renderEntries(entries, error) {
    shown = entries;
    if (error) {
      tableHost.replaceChildren(h('div', { class: 'card-body' }, callout('critical', 'alert-circle', error.message)));
      countEl.textContent = '';
      return;
    }
    countEl.textContent = entries.length >= PAGE_SIZE ? `Latest ${fmt(entries.length)} entries` : plural(entries.length, 'entry', 'entries');
    if (!entries.length) {
      tableHost.replaceChildren(emptyState('No entries match these filters'));
      return;
    }
    const table = ledgerTable(entries);
    const more = h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'ledger-more' }, 'Load older entries');
    const moreWrap = h('div', { class: 'load-more' }, more);
    more.addEventListener('click', async () => {
      more.disabled = true;
      try {
        const older = await query(shown[shown.length - 1].seq);
        shown = shown.concat(older);
        table.tbody.append(...ledgerRows(older));
        countEl.textContent = plural(shown.length, 'entry', 'entries');
        if (older.length < PAGE_SIZE) moreWrap.remove();
      } catch (err) {
        toast(err.message, { tone: 'critical' });
      } finally {
        more.disabled = false;
      }
    });
    fill(tableHost, table, entries.length >= PAGE_SIZE ? moreWrap : null);
  }

  async function reload() {
    setHashQuiet('/ledger', state);
    try {
      renderEntries(await query());
    } catch (err) {
      renderEntries([], err);
    }
  }

  agentInput.addEventListener('change', () => { state.agent = agentInput.value.trim(); reload(); });
  typeSel.addEventListener('change', () => { state.type = typeSel.value; reload(); });
  decisionSel.addEventListener('change', () => { state.decision = decisionSel.value; reload(); });
  const clearBtn = h('button', {
    type: 'button', class: 'btn btn--ghost', 'data-focus-key': 'ledger-clear',
    onclick: () => {
      Object.assign(state, { agent: '', type: '', decision: '' });
      agentInput.value = '';
      typeSel.value = '';
      decisionSel.value = '';
      reload();
    },
  }, 'Clear filters');

  try {
    renderEntries(await query());
  } catch (err) {
    if (err.status === 401) throw err;
    renderEntries([], err);
  }

  return h('div', { class: 'page' },
    pageHead({
      title: 'Ledger',
      sub: "Tamper-evident record of lifecycle changes, admin actions and policy decisions. Each entry's SHA-256 hash covers the previous entry's hash, so any edit breaks the chain.",
      actions: [verifyBtn, exportBtn],
    }),
    banner,
    h('div', { class: 'filters' },
      h('div', { class: 'field' }, h('label', { for: 'ledger-agent' }, 'Agent'), agentInput, agentList),
      h('div', { class: 'field' }, h('label', { for: 'ledger-type' }, 'Event type'), typeSel),
      h('div', { class: 'field' }, h('label', { for: 'ledger-decision' }, 'Decision'), decisionSel),
      h('div', { class: 'field', style: 'flex:0 0 auto; align-self:flex-end' }, clearBtn),
      countEl),
    h('section', { class: 'card', 'aria-label': 'Ledger entries' }, tableHost));
}

/* -------------------------------------------------------------------- go */

boot();
