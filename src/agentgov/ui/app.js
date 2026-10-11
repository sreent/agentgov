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
  plus: 'M12 5v14M5 12h14',
  edit: 'M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4',
  upload: 'M12 15V4M7 9l5-5 5 5M5 20h14',
  access: 'M5 8a4 4 0 1 0 8 0a4 4 0 1 0-8 0M3 21c0-3.3 2.7-6 6-6 1.2 0 2.3.3 3.2.9M17 14a2 2 0 1 0 0 4a2 2 0 1 0 0-4M18.4 15.6L22 12M20.5 13.5l1.5 1.5',
  platforms: 'M7 19h10.5a4.5 4.5 0 0 0 .5-8.98A6 6 0 0 0 6.34 9.03 5 5 0 0 0 7 19z',
  features: 'M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1M15 4v4M9 10v4M17 16v4',
  models: 'M7 7h10v10H7zM10 10h4v4h-4zM10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4',
  developers: 'M8 8l-4 4 4 4M16 8l4 4-4 4M13.5 5l-3 14',
  secops: 'M10 12a2 2 0 1 0 4 0a2 2 0 1 0-4 0M8.5 8.5a5 5 0 0 0 0 7M15.5 8.5a5 5 0 0 1 0 7M5.6 5.6a9 9 0 0 0 0 12.8M18.4 5.6a9 9 0 0 1 0 12.8',
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
// Signed in through single sign-on: the control plane keeps the session and the
// browser holds only an HttpOnly cookie, so there is no token in this tab.
let session = false;
// Who is signed in (GET /v1/me): name, roles and how they authenticated.
let me = null;
const READ_ROLES = ['admin', 'approver', 'secops', 'auditor'];

// What the signed-in person may change. The control plane enforces roles; this
// only hides controls it would refuse. The security team's secops role may triage,
// contain and decide as far as the hand-off to security operations has reached.
function can(kind) {
  const roles = me?.roles || [];
  if (roles.includes('admin')) return true;
  if (kind === 'approve' && roles.includes('approver')) return true;
  return roles.includes('secops') && (me?.handoff?.reached || []).includes(kind);
}

// Someone without an AgentGov role, signed in to see the issues sent to them (the issues
// feature) and decide the approval requests that agents acting for them sent them (the
// approvals-by-person feature). They see only those.
function isPerson() {
  return Boolean(me) && !me.roles.some((r) => READ_ROLES.includes(r)) && me.roles.includes('person');
}

// Their pages: issues (on the findings page) and approvals, as the features allow.
function personPages() {
  const inbox = me?.inbox || {};
  const pages = [inbox.issues ? 'findings' : null, inbox.approvals ? 'approvals' : null].filter(Boolean);
  return pages.length ? pages : ['approvals'];
}

function personHome() {
  return `#/${personPages()[0]}`;
}

// Reasons /auth/callback sends back (?sso_error=...). Only these fixed texts are shown.
const SSO_ERRORS = {
  no_role: 'You signed in, but your account has no AgentGov role. Ask an administrator for agentgov-admin, agentgov-approver, agentgov-secops or agentgov-auditor.',
  state: 'That sign-in could not be completed in this browser. Start again.',
  expired: 'That sign-in expired or was already used. Start again.',
  provider: 'The identity provider could not complete the sign-in. Try again, or use an API token.',
  token: "The control plane could not verify the identity provider's response. Try again, or ask an administrator to check the single sign-on settings.",
};

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
  if (status === 401) return session ? 'Your session has ended. Sign in again.' : 'Your API token was not accepted. Sign in again with a valid token.';
  if (status === 403) return `Your role can't do this. ${d}`.trim();
  if (status === 404) return d || 'Not found.';
  if (status === 409) return d || 'That change conflicts with the current state. Refresh and try again.';
  if (status === 400 || status === 422) return `The control plane rejected the request. ${d}`.trim();
  if (status >= 502 && status <= 504) return d || `A service behind the control plane did not respond (HTTP ${status}).`;
  if (status >= 500) return `The control plane hit an error (HTTP ${status}). ${d}`.trim();
  return d || `The request failed (HTTP ${status}).`;
}

async function api(path, { method = 'GET', body, text, contentType = 'text/plain', raw = false, auth = true, signingIn = false } = {}) {
  // Required on writes authenticated by the session cookie (other sites cannot set it).
  const headers = { Accept: 'application/json', 'X-AgentGov-CSRF': '1' };
  if (auth && token) headers.Authorization = `Bearer ${token}`;
  const init = { method, headers, cache: 'no-store' };
  if (text !== undefined) {
    headers['Content-Type'] = contentType;
    init.body = text;
  } else if (body !== undefined) {
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
    accepted: ['neutral', 'shield-check', 'Risk accepted'],
  },
  notification: {
    pending: ['neutral', 'clock', 'Sending'],
    sent: ['good', 'check-circle', 'Sent'],
    failed: ['critical', 'octagon', 'Not sent'],
  },
  apikey: {
    active: ['good', 'check-circle', 'Active'],
    revoked: ['neutral', 'ban', 'Revoked'],
  },
  person: {
    signed_in: ['good', 'check-circle', 'Signed in'],
    signed_out: ['neutral', 'minus', 'Signed out'],
    refused: ['critical', 'ban', 'Refused'],
  },
  sync: {
    ok: ['good', 'check-circle', 'Succeeded'],
    failed: ['critical', 'octagon', 'Failed'],
  },
  connector: {
    approved: ['good', 'check-circle', 'Approved'],
    unapproved: ['serious', 'triangle', 'Not approved'],
    unchecked: ['neutral', 'minus', 'Not approved'],
  },
  connection: {
    ok: ['good', 'check-circle', 'Working'],
    waiting: ['neutral', 'clock', 'Waiting for its first run'],
    missing_permission: ['warning', 'triangle', 'Missing a permission'],
    failing: ['critical', 'octagon', 'Failing'],
    off: ['neutral', 'minus', 'Not set up'],
    available: ['neutral', 'user-check', 'Ready for admins signed in with Entra ID'],
    import: ['neutral', 'upload', 'Import only'],
    out_of_date: ['warning', 'triangle', 'Out of date'],
    monitor: ['neutral', 'eye', 'Monitoring'],
    enforce: ['good', 'shield-check', 'Enforcing'],
    turned_off: ['neutral', 'power', 'Turned off in Features'],
  },
  mode: {
    enforce: ['good', 'shield-check', 'Enforce'],
    monitor: ['warning', 'eye', 'Monitor'],
    on: ['good', 'check-circle', 'On'],
    off: ['neutral', 'minus', 'Off'],
    inform: ['good', 'secops', 'Inform'],
    triage: ['good', 'check-circle', 'Triage'],
    contain: ['warning', 'ban', 'Contain'],
    decide: ['warning', 'user-check', 'Decide'],
  },
  destination: {
    active: ['good', 'check-circle', 'Active'],
    paused: ['neutral', 'minus', 'Paused'],
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

/** Wrap an async click handler so that a failure shows as a toast instead of being lost. */
function guarded(fn) {
  return async (...args) => {
    try {
      await fn(...args);
    } catch (err) {
      toast(err?.message || String(err), { tone: 'critical' });
    }
  };
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

// Field types: text (default), textarea, code (monospace textarea), select,
// checkbox, number; plus layout entries { type: 'section', label } and
// { type: 'row', fields: [...] } for two fields side by side.
function dialogField(f, controls) {
  if (f.type === 'section') return h('h3', { class: 'dialog-section' }, f.label);
  if (f.type === 'row') return h('div', { class: 'form-row' }, f.fields.map((x) => dialogField(x, controls)));
  const id = `dlg-${f.id}`;
  const hint = f.hint ? h('p', { class: 'hint', id: `${id}-hint` }, f.hint) : null;
  if (f.type === 'checkbox') {
    const box = h('input', { id, name: f.id, type: 'checkbox', checked: Boolean(f.value), 'aria-describedby': hint ? `${id}-hint` : null });
    controls[f.id] = box;
    return h('div', { class: 'field' }, h('label', { class: 'check', for: id }, box, f.label), hint);
  }
  let control;
  let loader = null;
  if (f.type === 'textarea' || f.type === 'code') {
    control = h('textarea', {
      id, name: f.id, rows: f.rows || 3, placeholder: f.placeholder || null,
      class: f.type === 'code' ? 'code-input' : null, spellcheck: f.type === 'code' ? 'false' : null,
    });
    if (f.file) {
      // Read a local file into the editor; nothing is uploaded until the form is saved.
      const picker = h('input', { type: 'file', accept: f.file, hidden: true });
      picker.addEventListener('change', async () => {
        const file = picker.files?.[0];
        if (file) control.value = await file.text();
        picker.value = '';
        control.focus();
      });
      loader = h('div', { class: 'btn-row' }, picker,
        h('button', { type: 'button', class: 'btn btn--sm', onclick: () => picker.click() }, icon('upload'), `Load a ${f.file} file`));
    }
  } else if (f.type === 'select') {
    control = h('select', { id, name: f.id },
      f.options.map((o) => h('option', { value: o.value, selected: o.value === (f.value ?? '') }, o.label)));
  } else {
    control = h('input', {
      id, name: f.id, type: f.type === 'number' ? 'number' : 'text', autocomplete: 'off',
      placeholder: f.placeholder || null, min: f.min ?? null, step: f.type === 'number' ? 1 : null,
      list: f.datalist ? `${id}-list` : null, spellcheck: f.mono ? 'false' : null, class: f.mono ? 'mono' : null,
    });
  }
  if (f.value != null && f.type !== 'select') control.value = f.value;
  if (hint) control.setAttribute('aria-describedby', `${id}-hint`);
  controls[f.id] = control;
  return h('div', { class: 'field' },
    h('label', { for: id }, f.label, f.required ? null : h('span', { class: 'muted' }, ' (optional)')),
    control,
    f.datalist ? h('datalist', { id: `${id}-list` }, f.datalist.map((v) => h('option', { value: v }))) : null,
    loader, hint);
}

function inputFields(fields) {
  return fields.flatMap((f) => (f.type === 'row' ? f.fields : f.type === 'section' ? [] : [f]));
}

/**
 * Show a modal dialog. Resolves to the field values, or null when cancelled.
 *
 * With `submit`, the dialog stays open while `submit(values)` runs: an error
 * it throws (a refused API call, say) is shown in the dialog so nothing typed
 * is lost, and the dialog resolves to its result once it succeeds.
 */
function ask({
  title, text, tone = 'primary', iconName = 'info', confirm = 'Confirm', cancel = 'Cancel',
  fields = [], extra, wide = false, submit, busy = 'Saving…', onReady,
}) {
  return new Promise((resolve) => {
    const dlg = $('#dialog');
    const opener = document.activeElement;
    const controls = {};
    let settled = false;
    let working = false;
    const holdOpen = (event) => { if (working) event.preventDefault(); };
    // "close" fires asynchronously, so when this dialog replaces one that just
    // closed, that dialog's close event arrives while this one is open: ignore it.
    const onClose = () => { if (!dlg.open) finish(null); };
    const finish = (value) => {
      if (settled) return;
      settled = true;
      dlg.removeEventListener('cancel', holdOpen);
      dlg.removeEventListener('close', onClose);
      if (dlg.open) dlg.close();
      resolve(value);
      if (opener && opener.isConnected) opener.focus();
    };
    const error = h('p', { class: 'form-error', role: 'alert', hidden: true });
    const cancelBtn = cancel ? h('button', { type: 'button', class: 'btn', onclick: () => finish(null) }, cancel) : null;
    const confirmBtn = h('button', { type: 'submit', class: `btn btn--${tone}` }, confirm);
    const form = h('form', { class: 'dialog-form', novalidate: true },
      h('div', { class: 'dialog-head' }, icon(iconName),
        h('div', { class: 'stack', style: 'gap:6px' },
          h('h2', { id: 'dialog-title', class: 'dialog-title' }, title),
          text ? h('p', { class: 'dialog-text' }, text) : null)),
      extra || null,
      fields.map((f) => dialogField(f, controls)),
      error,
      h('div', { class: 'dialog-actions' }, cancelBtn, confirmBtn));
    const showError = (message, control) => {
      error.textContent = message;
      error.hidden = false;
      if (control) control.focus();
    };
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (working) return;
      const values = {};
      for (const f of inputFields(fields)) {
        const control = controls[f.id];
        if (f.type === 'checkbox') { values[f.id] = control.checked; continue; }
        const value = f.type === 'code' ? control.value : control.value.trim();
        if (f.required && !value.trim()) { showError(`${f.label} is required.`, control); return; }
        if (f.match != null && value !== f.match) { showError(f.mismatch || `${f.label} doesn't match.`, control); return; }
        values[f.id] = value;
      }
      if (!submit) { finish(values); return; }
      working = true;
      error.hidden = true;
      confirmBtn.disabled = true;
      if (cancelBtn) cancelBtn.disabled = true;
      confirmBtn.textContent = busy;
      try {
        const result = await submit(values);
        working = false;
        finish(result ?? values);
      } catch (err) {
        working = false;
        confirmBtn.disabled = false;
        if (cancelBtn) cancelBtn.disabled = false;
        confirmBtn.textContent = confirm;
        showError(err?.message || String(err));
      }
    });
    dlg.dataset.tone = tone === 'danger' ? 'critical' : 'accent';
    dlg.classList.toggle('dialog--wide', wide);
    dlg.replaceChildren(form);
    dlg.addEventListener('close', onClose);
    dlg.addEventListener('cancel', holdOpen);
    dlg.showModal();
    if (onReady) onReady(controls);
    (form.querySelector('input:not([type="file"]), textarea, select') || confirmBtn).focus();
  });
}

/* ------------------------------------------------------------- form values */

// Lists are typed "a, b" or one per line, labels "key=value", and tool grants
// "server: tool, tool" with one server per line. The control plane validates
// everything again; these only turn the text into the API's JSON shapes.
function parseList(text) {
  return String(text || '').split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);
}

function parseLabels(text) {
  const out = {};
  for (const item of parseList(text)) {
    const eq = item.indexOf('=');
    if (eq < 1) throw new Error(`Write labels as key=value, separated by commas ("${item}" has no "=").`);
    out[item.slice(0, eq).trim()] = item.slice(eq + 1).trim();
  }
  return out;
}

function formatLabels(labels) {
  return Object.entries(labels || {}).map(([k, v]) => `${k}=${v}`).join(', ');
}

function parseGrants(text) {
  return String(text || '').split('\n').map((line) => line.trim()).filter(Boolean).map((line) => {
    const colon = line.indexOf(':');
    if (colon < 1) throw new Error(`Write each grant as "server: tool, tool" ("${line}" has no server).`);
    const server = line.slice(0, colon).trim();
    const tools = parseList(line.slice(colon + 1));
    if (!tools.length) throw new Error(`List the tools granted on ${server}, or * for all of them.`);
    return { server, tools };
  });
}

function formatGrants(grants) {
  return (grants || []).map((g) => `${g.server}: ${g.tools.join(', ')}`).join('\n');
}

// Model access is typed like tool grants: "provider: model, model", one provider per line.
function parseModelAccess(text) {
  return String(text || '').split('\n').map((line) => line.trim()).filter(Boolean).map((line) => {
    const colon = line.indexOf(':');
    if (colon < 1) throw new Error(`Write each line as "provider: model, model" ("${line}" has no provider).`);
    const provider = line.slice(0, colon).trim();
    const models = parseList(line.slice(colon + 1));
    if (!models.length) throw new Error(`List the models of ${provider} it may call, or * for all of them.`);
    return { provider, models };
  });
}

function formatModelAccess(access) {
  return (access || []).map((g) => `${g.provider}: ${g.models.join(', ')}`).join('\n');
}

function parseBudget(text) {
  if (!text) return null;
  const n = Number(text);
  if (!Number.isInteger(n) || n < 0) throw new Error('The daily token budget is a whole number of tokens, or empty.');
  return n;
}

const orNull = (text) => text || null;

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
    if (isPerson()) {
      const pages = personPages();
      const [pending, issues] = await Promise.all([
        pages.includes('approvals') ? api('v1/me/approvals?status=pending') : [],
        pages.includes('findings') ? api('v1/me/issues?status=open') : [],
      ]);
      updateBadges({ pendingApprovals: pending.length, findings: summarizeFindings(issues) });
      return;
    }
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
  { re: /^\/findings\/teams$/, nav: 'findings', title: 'Teams', render: renderTeams },
  { re: /^\/findings\/([^/]+)$/, nav: 'findings', title: 'Finding', render: renderFinding },
  { re: /^\/policies$/, nav: 'policies', title: 'Policies', render: renderPolicies },
  { re: /^\/ledger$/, nav: 'ledger', title: 'Ledger', render: renderLedger },
  { re: /^\/access$/, nav: 'access', title: 'Access', render: renderAccess },
  { re: /^\/platforms$/, nav: 'platforms', title: 'Platforms', render: renderPlatforms },
  { re: /^\/features$/, nav: 'features', title: 'Features', render: renderFeatures },
  { re: /^\/models$/, nav: 'models', title: 'Models', render: renderModels },
  { re: /^\/developers$/, nav: 'developers', title: 'Developer tools', render: renderDevelopers },
  { re: /^\/secops$/, nav: 'secops', title: 'Security operations', render: renderSecops },
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
  if (!me) return; // not signed in (by token or single sign-on)
  const { path, params } = parseHash();
  let page = null;
  let match = null;
  for (const p of PAGES) {
    match = path.match(p.re);
    if (match) { page = p; break; }
  }
  if (!page) { location.replace(isPerson() ? personHome() : '#/overview'); return; }
  if (isPerson() && !personPages().includes(page.nav)) { location.replace(personHome()); return; }
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
  getInfo().then((info) => {
    const sso = Boolean(info?.sso?.enabled);
    $('#sso').hidden = !sso;
    $('#sso-link').href = new URL('auth/login', API_ROOT).href;
    $('#signin-submit').className = `btn btn--block${sso ? '' : ' btn--primary'}`;
  });
}

function enterApp() {
  $('#signin').hidden = true;
  $('.skip-link').hidden = false;
  $('#shell').hidden = false;
  firstRender = true;
  // People without an AgentGov role have only their issues and approvals.
  for (const link of document.querySelectorAll('#nav [data-nav]')) {
    link.closest('li').hidden = isPerson() && !personPages().includes(link.dataset.nav);
  }
  $('#nav-findings-label').textContent = isPerson() ? 'Your issues' : 'Findings';
  if (!location.hash || location.hash === '#' || location.hash === '#/') history.replaceState(null, '', isPerson() ? personHome() : '#/overview');
  route();
  refreshBadges();
  getInfo().then((info) => {
    if (!info) return;
    const who = me ? ` · signed in as ${me.actor}${me.via === 'session' ? ' (single sign-on)' : ''}` : '';
    $('#nav-meta').textContent = `AgentGov ${info.version} · ${info.identity_provider ? 'Keycloak identities' : 'no identity provider'} · OPA ${info.opa ? 'connected' : 'not configured'}${who}`;
  });
}

function resetToSignin(message) {
  token = null;
  session = false;
  me = null;
  writeStore('sessionStorage', TOKEN_KEY, null);
  $('#toasts').replaceChildren();
  if ($('#dialog').open) $('#dialog').close();
  $('#main').replaceChildren(h('p', { class: 'loading-line' }, 'Signed out.'));
  showSignin(message);
}

async function signOut(message) {
  if (session) {
    // End the control plane's session, then the identity provider's.
    try {
      const out = await api('auth/logout', { method: 'POST', signingIn: true });
      if (out?.logout_url) {
        location.assign(out.logout_url);
        return;
      }
    } catch { /* already ended or unreachable: show the sign-in page anyway */ }
  }
  resetToSignin(message);
}

function expireSession() {
  if (session) resetToSignin('Your session has ended. Sign in again.');
  else if (token) resetToSignin('Your API token was rejected. It may have been revoked or rotated. Sign in again.');
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
    const who = await api('v1/me', { signingIn: true });
    if (!who.roles.some((r) => READ_ROLES.includes(r) || r === 'person')) throw new ApiError(403, '', `its role is ${who.role}`);
    me = who;
    session = false;
    writeStore('sessionStorage', TOKEN_KEY, value);
    focusAfterSignin = true;
    enterApp();
  } catch (ex) {
    token = null;
    if (ex.status === 401) err.textContent = 'That token was not accepted. Check it for missing or extra characters, or ask an administrator for a new API key.';
    else if (ex.status === 403) err.textContent = `This token can't open the admin center (${ex.detail || 'its role is not allowed'}). Use an admin, approver, secops or auditor key.`;
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
  start();
}

// Resume a token kept in this tab, or a single sign-on session (auth/session
// answers 200 either way, so a visitor who is not signed in causes no failed
// request); otherwise show the sign-in page, with the reason a single sign-on
// attempt failed.
async function start() {
  const ssoError = new URLSearchParams(location.search).get('sso_error');
  if (ssoError) history.replaceState(null, '', location.pathname + location.hash);
  try {
    const who = token ? await api('v1/me', { signingIn: true }) : await api('auth/session', { signingIn: true });
    if (!token && !who.signed_in) {
      showSignin(ssoError ? SSO_ERRORS[ssoError] || SSO_ERRORS.provider : undefined);
      return;
    }
    if (!who.roles.some((r) => READ_ROLES.includes(r) || r === 'person')) {
      if (!token) await api('auth/logout', { method: 'POST', signingIn: true }).catch(() => null);
      resetToSignin(`Your role (${who.role}) can't open the admin center. Use an admin, approver, secops or auditor account.`);
      return;
    }
    me = who;
    session = who.via === 'session';
    enterApp();
  } catch (err) {
    if (token && err.status === 401) resetToSignin('Your API token was rejected. It may have been revoked or rotated. Sign in again.');
    else if (ssoError) showSignin(SSO_ERRORS[ssoError] || SSO_ERRORS.provider);
    else showSignin(err.status === 401 ? undefined : err.message);
  }
}

/* =================================================================== pages */

/* ---------------------------------------------------------------- overview */

async function renderOverview() {
  const [ov, info, features] = await Promise.all([api('v1/overview'), getInfo(), api('v1/features').then((v) => v.features).catch(() => null)]);
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
    controlPlaneCard(ov, info, features));
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

function controlPlaneCard(ov, info, features) {
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
        features ? [
          features.find((f) => f.key === 'unknown-callers')?.mode === 'monitor' ? 'Unknown callers let through' : 'Unknown callers refused',
          ' · ', h('a', { href: '#/features' }, featureSummary(features)),
        ] : null)));
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
    source: params.get('source') || '',
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
    setHashQuiet('/agents', { status: state.status === 'all' ? '' : state.status, owner: state.owner, risk: state.risk, source: state.source, q: state.q });
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
    if (state.source) extras.push([`Runs on ${PLATFORM_SOURCES[state.source] || state.source}`, () => { state.source = ''; }]);
    extraHost.replaceChildren(...extras.map(([label, clear]) => h('span', { class: 'active-filter' }, label,
      h('button', { type: 'button', 'aria-label': `Remove filter: ${label}`, onclick: () => { clear(); apply(); sync(); search.focus(); } }, icon('x')))));

    let rows = agents.filter((a) => (state.status === 'all' ? a.status !== 'deleted' : a.status === state.status));
    if (state.owner === 'none') rows = rows.filter((a) => !a.owner && a.status !== 'discovered');
    if (state.risk === 'elevated') rows = rows.filter((a) => ['high', 'critical'].includes(a.risk?.level));
    if (state.source) rows = rows.filter((a) => a.source === state.source);
    countEl.textContent = plural(rows.length, 'agent');
    tableHost.replaceChildren(rows.length ? agentsTable(rows) : emptyState('No agents match these filters',
      state.q ? `Nothing matches "${state.q}".` : 'Try another status.',
      h('button', {
        type: 'button', class: 'btn btn--sm',
        onclick: async () => {
          Object.assign(state, { status: 'all', owner: '', risk: '', source: '', q: '' });
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
      actions: [
        can('admin') ? h('button', { type: 'button', class: 'btn btn--primary', 'data-focus-key': 'register-agent', onclick: guarded(registerAgent) }, icon('plus'), 'Register agent') : null,
        refreshButton(),
      ],
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
        h('td', { 'data-label': 'Blueprint' }, a.blueprint || (platformOf(a)
          ? h('span', { class: 'muted', title: 'Blueprints grant gateway tools; this agent runs on another platform' }, `${platformOf(a)} agent`)
          : h('span', { class: 'muted' }, 'None'))),
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
// Blocking or deleting a platform agent changes AgentGov's registry, not the platform.
const PLATFORM_LIFECYCLE = {
  approve: (p) => ({ text: `The agent becomes active in AgentGov's registry, with an owner, sponsors and periodic review. It runs in ${p} either way. Activation needs at least one sponsor.` }),
  block: (p) => ({
    label: 'Block', confirm: 'Block in AgentGov',
    text: `This marks the agent as blocked in AgentGov's registry and ledger. It does not stop the agent in ${p}: block it in ${p}'s admin center too.`,
    done: (n) => `Blocked ${n} in AgentGov. Block it in ${p} too.`,
  }),
  unblock: (p) => ({ text: `The agent is no longer marked as blocked in AgentGov. This doesn't change ${p}.` }),
  delete: (p) => ({ text: `The agent leaves AgentGov's inventory but stays in ${p}. Deleted agents can be restored.` }),
  adopt: (p) => ({ text: `Adopting brings this ${p} agent under governance as a pending registration. Give it an owner and at least one sponsor, then approve it.` }),
};

function lifecycleSpec(a, action) {
  const p = platformOf(a);
  return p && PLATFORM_LIFECYCLE[action] ? { ...LIFECYCLE[action], ...PLATFORM_LIFECYCLE[action](p) } : LIFECYCLE[action];
}

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
  const [entries, openFindings, instructions, usage, a2a] = await Promise.all([
    api(`v1/ledger?agent=${encodeURIComponent(agent.id)}&limit=12`).catch((e) => e),
    api(`v1/findings?status=open&agent=${encodeURIComponent(agent.id)}`).catch((e) => e),
    api(`v1/agents/${encodeURIComponent(agent.id)}/instructions`).catch((e) => e),
    api(`v1/models/usage?agent=${encodeURIComponent(agent.id)}&days=7`).catch((e) => e),
    api(`v1/agents/${encodeURIComponent(agent.id)}/a2a`).catch((e) => e),
  ]);
  // Agents on Microsoft 365 or Copilot Studio don't use the gateway: show what their platform reports.
  const views = agent.platforms || [];
  const where = views.length && agent.status !== 'deleted' ? await platformActionTarget(agent) : null;
  const main = views.length ? views.map((v) => platformCard(agent, v, where))
    : [permissionsCard(agent), agentModelsCard(agent, usage), agentA2ACard(agent, a2a)];
  // With threat detection enforcing, AgentGov's policies decide about its tool calls.
  const enforced = views.some((v) => v.source === 'copilot-studio')
    && (await featureModes().catch(() => ({})))['copilot-studio-threat-detection'] === 'enforce';
  return h('div', { class: 'page', 'data-title': agent.name },
    agentHeader(agent),
    h('div', { class: 'detail-grid' },
      h('div', { class: 'stack' }, main, instructionsCard(agent, instructions), agentLedgerCard(agent, entries),
        views.length ? null : agentCardCard(agent)),
      h('div', { class: 'stack' }, riskCard(agent, enforced), peopleCard(agent), attestationCard(agent), identityCard(agent),
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

// Sponsors attest their own agents; admins any agent.
function mayAttest(a) {
  if (!ATTESTABLE.has(a.status)) return false;
  return can('admin') || (can('approve') && (a.sponsors || []).includes(me?.name));
}

function agentToolbar(a) {
  const allowed = can('admin') ? ACTIONS_BY_STATUS[a.status] || []
    : can('contain') ? (ACTIONS_BY_STATUS[a.status] || []).filter((x) => x === 'block' || x === 'unblock') : [];
  const buttons = allowed.map((action) => {
    const spec = lifecycleSpec(a, action);
    return h('button', {
      type: 'button', class: `btn ${spec.cls}`, 'data-focus-key': `lifecycle-${action}`,
      onclick: () => runLifecycle(a, action),
    }, icon(spec.icon), spec.label);
  });
  if (mayAttest(a)) {
    buttons.push(h('button', { type: 'button', class: 'btn', 'data-focus-key': 'attest', onclick: () => runAttest(a) }, icon('shield-check'), 'Attest'));
  }
  if (can('admin') && a.status !== 'deleted') {
    buttons.unshift(h('button', { type: 'button', class: 'btn', 'data-focus-key': 'edit-agent', onclick: guarded(() => editAgent(a)) }, icon('edit'), 'Edit'));
  }
  if (can('admin') && a.status === 'deleted') {
    buttons.push(h('button', { type: 'button', class: 'btn btn--danger-quiet', 'data-focus-key': 'purge-agent', onclick: () => purgeAgent(a) }, icon('trash'), 'Delete permanently'));
  }
  if (!buttons.length) return null;
  return h('div', { class: 'toolbar', role: 'group', 'aria-label': 'Agent actions' }, buttons);
}

async function runLifecycle(a, action) {
  const spec = lifecycleSpec(a, action);
  const fields = [];
  if (action === 'adopt') {
    fields.push(
      { id: 'owner', label: 'Owner', placeholder: 'Team or person accountable for the agent', value: a.owner || '' },
      { id: 'sponsors', label: 'Sponsors', placeholder: 'alice@example.com, bob@example.com', value: (a.sponsors || []).join(', '), hint: 'Separate people with commas. Approval needs at least one sponsor.' },
    );
    // Blueprints grant gateway tools, which agents on other platforms don't use.
    if (!platformOf(a)) {
      const blueprints = await api('v1/blueprints').catch(() => []);
      fields.push({
        id: 'blueprint', label: 'Blueprint', type: 'select', value: a.blueprint || '',
        options: [{ value: '', label: 'No blueprint' }, ...blueprints.map((b) => ({ value: b.name, label: `${b.name} (${b.risk_tier} risk tier)` }))],
      });
    }
  }
  // A platform agent can be blocked (or released) in its own platform too, as the signed-in admin.
  const where = action === 'block' || action === 'unblock' ? await platformActionTarget(a) : null;
  let text = spec.text;
  if (where && me?.microsoft) {
    // The checkbox covers the platform, so the text says only what AgentGov does.
    text = action === 'block' ? "This marks the agent as blocked in AgentGov's registry and ledger." : 'The agent is no longer marked as blocked in AgentGov.';
    fields.push({
      id: 'in_platform', type: 'checkbox', value: true,
      label: action === 'block' ? where.blockLabel : where.unblockLabel,
      hint: `AgentGov does this in ${where.name} as you, so ${where.name} records it under your name.`,
    });
  } else if (where) {
    text += ` To do that from here, sign in to AgentGov with Microsoft Entra ID.`;
  }
  fields.push({ id: 'reason', label: 'Reason', type: 'textarea', hint: 'Recorded in the evidence ledger.' });
  const done = await ask({
    title: `${spec.label.replace(' (kill switch)', '')} ${a.name}?`,
    text, tone: spec.tone, iconName: spec.icon, confirm: spec.confirm, fields, busy: 'Working…',
    submit: async (values) => {
      const body = {};
      if (values.reason) body.reason = values.reason;
      if (action === 'adopt') {
        if (values.owner) body.owner = values.owner;
        const sponsors = values.sponsors.split(',').map((x) => x.trim()).filter(Boolean);
        if (sponsors.length) body.sponsors = sponsors;
        if (values.blueprint) body.blueprint = values.blueprint;
      }
      // AgentGov first: if it refuses (an unblock needs a sponsor), the platform is left
      // alone. If the platform then refuses, the agent is still blocked where it runs.
      await api(`v1/agents/${encodeURIComponent(a.id)}/${action}`, { method: 'POST', body });
      if (!values.in_platform) return { inPlatform: false };
      try {
        await api(`v1/agents/${encodeURIComponent(a.id)}/platform/${action}`, { method: 'POST' });
        return { inPlatform: true };
      } catch (err) {
        return { inPlatform: false, platformError: err };
      }
    },
  });
  if (!done) return;
  if (done.platformError) {
    const verb = action === 'block' ? 'Blocked' : 'Unblocked';
    toast(`${verb} ${a.name} in AgentGov. ${done.platformError.message}`, { tone: 'critical' });
  } else {
    toast(done.inPlatform ? (action === 'block' ? where.blocked(a.name) : where.unblocked(a.name)) : spec.done(a.name));
  }
  refreshBadges();
  await refresh();
}

/** Where Block can also act for a platform agent, when signed-in admins may act in Microsoft. */
async function platformActionTarget(a) {
  const views = (a.platforms || []).filter((v) => BLOCKABLE_SOURCES.has(v.source));
  const info = await getInfo();
  if (!views.length || !info?.microsoft_admin_actions || !can('admin')) return null;
  // The control plane quarantines the Copilot Studio agent when there is one (no licence needed).
  if (views.some((v) => v.source === 'copilot-studio')) {
    return {
      name: 'Copilot Studio', source: 'copilot-studio',
      blockLabel: 'Also quarantine it in Copilot Studio', unblockLabel: 'Also release it from quarantine in Copilot Studio',
      blocked: (n) => `Blocked ${n} in AgentGov and quarantined it in Copilot Studio.`,
      unblocked: (n) => `Unblocked ${n} in AgentGov and released it from quarantine in Copilot Studio.`,
    };
  }
  return {
    name: 'Microsoft 365', source: 'microsoft-365',
    blockLabel: 'Also block it in Microsoft 365', unblockLabel: 'Also unblock it in Microsoft 365',
    blocked: (n) => `Blocked ${n} in AgentGov and in Microsoft 365.`,
    unblocked: (n) => `Unblocked ${n} in AgentGov and in Microsoft 365.`,
  };
}

async function platformBlock(a, where, blocking) {
  const studio = where.source === 'copilot-studio';
  const verb = blocking ? (studio ? 'Quarantine' : 'Block') : (studio ? 'Release' : 'Unblock');
  const done = await ask({
    title: `${verb} ${a.name} in ${where.name}?`,
    text: blocking
      ? (studio ? 'Copilot Studio stops the agent on every channel; its makers can still open and test it. ' : 'Microsoft 365 blocks the agent for everyone in the organisation. ')
        + `AgentGov does this as you and records it in the evidence ledger. The agent's status in AgentGov doesn't change.`
      : `${where.name} lets people use the agent again. AgentGov does this as you and records it in the evidence ledger.`,
    tone: blocking ? 'danger' : 'primary', iconName: blocking ? 'ban' : 'undo',
    confirm: `${verb} in ${where.name}`, busy: 'Working…',
    submit: () => api(`v1/agents/${encodeURIComponent(a.id)}/platform/${blocking ? 'block' : 'unblock'}`, { method: 'POST' }),
  });
  if (!done) return;
  toast(blocking ? `${studio ? 'Quarantined' : 'Blocked'} ${a.name} in ${where.name}.` : `${studio ? 'Released' : 'Unblocked'} ${a.name} in ${where.name}.`);
  await refresh();
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

const RISK_TIERS = ['minimal', 'low', 'medium', 'high', 'critical'];
const NAME_HINT = 'Lowercase letters, digits and hyphens, starting and ending with a letter or digit.';

/** Register an agent (no `a`) or edit one. Resolves to the saved agent, or null. */
async function agentForm(a) {
  const [blueprints, issuers, teams] = await Promise.all([
    api('v1/blueprints'), api('v1/identity-issuers').catch(() => []), api('v1/teams').catch(() => []),
  ]);
  const editing = Boolean(a);
  const identity = a?.workload_identity;
  // How it authenticates: offered once there's an issuer to choose.
  const authentication = issuers.length || identity ? [
    { type: 'section', label: 'Authentication' },
    {
      id: 'workload_issuer', label: 'Authenticates with', type: 'select', value: identity?.issuer || '',
      options: [
        { value: '', label: 'A client secret' },
        ...issuers.map((i) => ({ value: i.name, label: `Its own identity from ${i.name} (${issuerKind(i.kind)}${i.status === 'blocked' ? ', blocked' : ''})` })),
      ],
      hint: 'An identity it already has, such as a Kubernetes service account, needs no secret to store or rotate.',
    },
    { id: 'workload_subject', label: 'Subject', mono: true, value: identity?.subject || '', hint: 'Its subject at the issuer: the sub claim of its tokens there.' },
  ] : [];
  const tiers = RISK_TIERS.map((t) => ({ value: t, label: humanize(t) }));
  const fields = [
    editing ? null : {
      id: 'name', label: 'Name', required: true, mono: true, placeholder: 'support-bot',
      hint: `${NAME_HINT} The agent gets the OAuth client agent-<name>.`,
    },
    { id: 'description', label: 'Description', type: 'textarea', value: a?.description || '' },
    { type: 'section', label: 'Accountability' },
    { type: 'row', fields: [
      { id: 'owner', label: 'Owner', value: a?.owner || '', placeholder: 'Team or person', datalist: teams.map((t) => t.name) },
      { id: 'environment', label: 'Environment', value: a?.environment || '', placeholder: 'prod', datalist: ['prod', 'staging', 'dev'] },
    ] },
    {
      id: 'sponsors', label: 'Sponsors', value: (a?.sponsors || []).join(', '), placeholder: 'alice@example.com',
      hint: 'People who vouch for the agent, separated by commas. Approval needs at least one unless the blueprint waives it.',
    },
    {
      id: 'team', label: 'Team', type: 'select', value: a?.team || '',
      options: [{ value: '', label: "Its blueprint's team (or the default team)" }, ...teams.map((t) => ({ value: t.name, label: t.name }))],
      hint: 'Issues about the agent go to its owner, then its sponsors, then this team.',
    },
    ...authentication,
    { type: 'section', label: 'Access' },
    {
      id: 'blueprint', label: 'Blueprint', type: 'select', value: a?.blueprint || '',
      options: [{ value: '', label: 'No blueprint' }, ...blueprints.map((b) => ({ value: b.name, label: `${b.name} (${b.risk_tier} risk tier)` }))],
      hint: "The agent gets the blueprint's tool grants, sponsor rule and review period.",
    },
    {
      id: 'permissions', label: 'Extra tool grants', type: 'code', rows: 3, value: formatGrants(a?.permissions), placeholder: 'crm: search_customers, get_*',
      hint: 'Added to the blueprint\'s grants. One server per line; tool names can use * wildcards, and * alone means every tool.',
    },
    {
      id: 'model_access', label: 'Extra model access', type: 'code', rows: 2, value: formatModelAccess(a?.model_access), placeholder: 'openai: gpt-4o-mini',
      hint: "Added to the blueprint's model access. One provider per line; model names can use * wildcards.",
    },
    { id: 'daily_token_budget', label: 'Daily token budget', type: 'number', min: 0, value: a?.daily_token_budget ?? '', hint: "Input and output tokens per UTC day. Empty: the blueprint's budget." },
    {
      id: 'risk_tier', label: 'Declared risk tier', type: 'select', value: a?.risk_tier || '',
      options: editing ? tiers : [{ value: '', label: "The blueprint's tier (medium without one)" }, ...tiers],
    },
    { type: 'section', label: 'Agent to agent' },
    {
      id: 'a2a_url', label: 'A2A endpoint', value: a?.a2a_url || '', placeholder: 'http://billing-agent:9600', mono: true,
      hint: 'Where it serves A2A (its JSON-RPC endpoint), reachable only from the gateway. Other agents then call it at /a2a/<name> on the gateway, as their grants allow.',
    },
    {
      id: 'agent_access', label: 'Extra agents it may call', value: (a?.agent_access || []).join(', '), placeholder: 'billing-agent, kb-*', mono: true,
      hint: "Added to the agents its blueprint may call over A2A, separated by commas; names can use * wildcards.",
    },
    { type: 'section', label: 'Details' },
    { type: 'row', fields: [
      { id: 'framework', label: 'Framework', value: a?.framework || '' },
      { id: 'platform', label: 'Platform', value: a?.platform || '' },
    ] },
    { id: 'models', label: 'Models', value: (a?.models || []).join(', '), hint: 'Separated by commas.' },
    { id: 'labels', label: 'Labels', value: formatLabels(a?.labels), placeholder: 'team=cx, cost-center=42', mono: true },
    editing ? null : { id: 'approve', label: 'Approve now', type: 'checkbox', hint: 'Otherwise the agent waits in Pending review until an admin approves it.' },
  ].filter(Boolean);
  return ask({
    title: editing ? `Edit ${a.name}` : 'Register an agent',
    text: editing
      ? 'Changes are recorded in the evidence ledger, and the gateway enforces them as soon as OPA loads the updated policy bundle.'
      : 'Approved agents get their own OAuth client in Keycloak and can call the tools they are granted.',
    iconName: editing ? 'edit' : 'agents', confirm: editing ? 'Save changes' : 'Register agent', fields,
    onReady: (controls) => {
      if (!controls.workload_issuer) return;
      const subject = controls.workload_subject;
      const show = () => {
        const issuer = issuers.find((i) => i.name === controls.workload_issuer.value);
        subject.closest('.field').hidden = !issuer;
        if (!issuer) return;
        subject.placeholder = ISSUER_KINDS[issuer.kind]?.[1] || '';
        if (issuer.kind === 'spiffe') subject.placeholder = `${issuer.issuer}/ns/agents/sa/${a?.name || 'support-bot'}`;
        // An agent linked to Microsoft Entra Agent ID: its tokens' subject is its object ID.
        const entra = a?.external_ids?.entra_agent_id;
        if (isEntra(issuer) && entra && !subject.value) subject.value = entra;
      };
      controls.workload_issuer.addEventListener('change', show);
      show();
    },
    submit: async (v) => {
      if (v.workload_issuer && !v.workload_subject) throw new Error('Give its subject at the issuer, or choose a client secret.');
      const body = {
        description: v.description,
        owner: orNull(v.owner),
        environment: orNull(v.environment),
        sponsors: parseList(v.sponsors),
        team: v.team || null,
        blueprint: v.blueprint || null,
        permissions: parseGrants(v.permissions),
        model_access: parseModelAccess(v.model_access),
        daily_token_budget: parseBudget(v.daily_token_budget),
        agent_access: parseList(v.agent_access),
        a2a_url: orNull(v.a2a_url),
        framework: orNull(v.framework),
        platform: orNull(v.platform),
        models: parseList(v.models),
        labels: parseLabels(v.labels),
      };
      if ('workload_issuer' in v) {
        body.workload_identity = v.workload_issuer ? { issuer: v.workload_issuer, subject: v.workload_subject } : null;
      }
      // Left unchanged, the tier follows the blueprint (as the API does).
      if (v.risk_tier && v.risk_tier !== a?.risk_tier) body.risk_tier = v.risk_tier;
      if (editing) return api(`v1/agents/${encodeURIComponent(a.id)}`, { method: 'PATCH', body });
      return api('v1/agents', { method: 'POST', body: { name: v.name, ...body, approve: v.approve } });
    },
  });
}

async function registerAgent() {
  const created = await agentForm(null);
  if (!created) return;
  toast(`Registered ${created.name}. ${created.status === 'active' ? 'It is active.' : 'It is pending review.'}`);
  refreshBadges();
  location.hash = agentHref(created.id);
}

async function editAgent(a) {
  const saved = await agentForm(a);
  if (!saved) return;
  toast(`Saved ${saved.name}.`);
  await refresh();
}

async function purgeAgent(a) {
  const done = await ask({
    title: `Delete ${a.name} permanently?`,
    text: 'The agent and its OAuth client are removed and cannot be restored. Its ledger entries are kept.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete permanently', busy: 'Deleting…',
    fields: [{ id: 'confirm_name', label: `Type ${a.name} to confirm`, required: true, mono: true, match: a.name, mismatch: `Type ${a.name} exactly to confirm.` }],
    submit: () => api(`v1/agents/${encodeURIComponent(a.id)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted ${a.name} permanently.`);
  location.hash = '#/agents';
}

/** How an agent with a workload identity authenticates: its issuer's token, no secret. */
async function agentSignIn(a) {
  let creds;
  try {
    creds = await api(`v1/agents/${encodeURIComponent(a.id)}/credentials`, { method: 'POST', body: {} });
  } catch (err) {
    toast(err.message, { tone: 'critical' });
    return;
  }
  const request = [
    `POST ${creds.token_endpoint}`,
    'grant_type=client_credentials',
    `client_assertion_type=${creds.assertion_type}`,
    "client_assertion=<the issuer's token>",
  ].join('\n');
  await ask({
    title: `How ${a.name} authenticates`,
    text: `With a token from ${creds.issuer} whose subject is its own, instead of a client secret. Keycloak checks the token against the issuer's keys and gives back an AgentGov access token for the gateway.`,
    iconName: 'key', confirm: 'Done', cancel: null, wide: true,
    extra: [
      facts([
        ['Client ID', copyable(creds.client_id, 'client ID')],
        ['Issuer', creds.issuer],
        ['Subject', copyable(creds.subject, 'subject')],
        ["Its token's audience", copyable(creds.assertion_audience, 'audience')],
        ['Token endpoint', copyable(creds.token_endpoint, 'token endpoint')],
        ['Gateway audience', copyable(creds.audience, 'gateway audience')],
      ]),
      h('pre', { class: 'kv-pre', tabindex: '0' }, request),
    ],
  });
}

/** Show the agent's OAuth client credentials, after issuing a new secret if `rotate`. */
async function agentCredentials(a, rotate) {
  const creds = await ask({
    title: rotate ? `Rotate the client secret of ${a.name}?` : `Show the credentials of ${a.name}?`,
    text: rotate
      ? 'Keycloak issues a new secret and the current one stops working at once, so update the agent straight away. The rotation is recorded in the evidence ledger.'
      : 'The client secret is shown in the next dialog. Viewing it is recorded in the evidence ledger.',
    tone: rotate ? 'danger' : 'primary', iconName: 'key', confirm: rotate ? 'Rotate secret' : 'Show credentials',
    busy: rotate ? 'Rotating…' : 'Loading…',
    submit: () => api(`v1/agents/${encodeURIComponent(a.id)}/credentials`, { method: 'POST', body: { rotate } }),
  });
  if (!creds) return;
  await ask({
    title: `${rotate ? 'New credentials' : 'Credentials'} for ${a.name}`,
    text: 'The agent exchanges these for 5-minute access tokens with the client credentials grant. Keep the secret in a secret store, not in code.',
    iconName: 'key', confirm: 'Done', cancel: null, wide: true,
    extra: facts([
      ['Client ID', copyable(creds.client_id, 'client ID')],
      ['Client secret', copyable(creds.client_secret, 'client secret')],
      ['Token endpoint', copyable(creds.token_endpoint, 'token endpoint')],
      ['Audience', copyable(creds.audience, 'audience')],
    ]),
  });
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
        ['Acts for', actsFor(a)],
      ]),
      broad ? callout('warning', 'triangle', 'This agent may call every tool on every server (*/*). Replace the wildcard with the tools it needs.') : null,
      list,
      own.size ? h('p', { class: 'hint' }, 'Highlighted patterns are granted to this agent directly; the others come from its blueprint.') : null,
    ],
  });
}

function agentModelsCard(a, usage) {
  const access = a.effective_model_access || [];
  const own = new Map((a.model_access || []).map((g) => [g.provider, new Set(g.models)]));
  const budget = a.effective_daily_token_budget;
  const today = usage instanceof Error ? null : (usage.today || []).find((b) => b.agent_id === a.id);
  const used = today?.used_today ?? 0;
  const totals = usage instanceof Error ? null : usage.totals;
  const tone = budget != null && used >= budget ? 'critical' : 'accent';
  return card({
    title: 'Models',
    sub: 'Models it may call through the gateway, and what it used in the last 7 days',
    body: [
      access.length
        ? h('ul', { class: 'perm-list', role: 'list' }, access.map((g) => h('li', {},
          h('span', { class: 'perm-server' }, g.provider),
          h('div', { class: 'chip-row' }, g.models.map((m) => {
            const direct = own.get(g.provider)?.has(m);
            return plainChip(m, { mono: true, tone: direct ? 'accent' : null, title: direct ? 'Granted to this agent directly' : `From blueprint ${a.blueprint || ''}`.trim() });
          })))))
        : h('p', { class: 'muted small' }, 'No model access. Policy refuses its model calls through the gateway.'),
      facts([
        ['Daily token budget', budget == null ? h('span', { class: 'muted' }, 'None') : `${fmt(budget)} tokens${a.daily_token_budget == null ? ' (from its blueprint)' : ''}`],
        ['Used today', budget == null ? `${fmt(used)} tokens`
          : h('div', { class: 'stack', style: 'gap:4px' }, `${fmt(used)} of ${fmt(budget)} tokens`,
            h('div', { class: 'meter', role: 'img', 'aria-label': `${fmt(used)} of ${fmt(budget)} tokens used today`, style: `background: var(--${tone === 'critical' ? 'critical' : 'neutral'}-tint)` },
              h('span', { style: `width:${budget ? Math.min(100, (used / budget) * 100) : 100}%; background:${TONE_COLOR[tone]}` })))],
        totals ? ['Last 7 days', `${plural(totals.calls, 'call')}, ${fmt(totals.input_tokens + totals.output_tokens)} tokens${totals.cost_usd ? `, $${totals.cost_usd.toFixed(2)}` : ''}${totals.refused ? `, ${fmt(totals.refused)} refused` : ''}`] : null,
      ]),
    ],
  });
}

function riskCard(a, enforced = false) {
  const risk = a.risk || {};
  const tone = toneOf('risk', risk.level);
  const platform = platformOf(a);
  return card({
    title: 'Risk',
    sub: platform ? `Posture, instructions, and how ${platform} has it set up` : 'Posture, instructions, and runtime signals from the last 24 hours',
    actions: can('admin') ? [h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'recalc', onclick: () => recalcRisk(a) }, icon('refresh'), 'Recalculate')] : null,
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
      h('p', { class: 'hint' }, platform && !enforced
        ? `Levels: 25 medium, 50 high, 75 critical. High and critical risk raise an alert; ${platform} keeps running the agent.`
        : `Levels: 25 medium, 50 high, 75 critical. Policy blocks agents at critical risk${enforced ? ": Copilot Studio asks AgentGov before each of this agent's tool calls" : ''}.`),
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
      a.team ? h('ul', { class: 'people', role: 'list' }, personRow(a.team, 'Team: issues escalate to it')) : null,
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
    actions: mayAttest(a) ? [h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'attest-card', onclick: () => runAttest(a) }, icon('shield-check'), 'Attest')] : null,
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
  const workload = a.workload_identity;
  // Keycloak only issues secrets to active agents; one with a workload identity has none.
  let credentialActions = can('admin') && a.status === 'active' && id.client_id ? [
    h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'show-credentials', onclick: guarded(() => agentCredentials(a, false)) }, icon('key'), 'Show secret'),
    h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', 'data-focus-key': 'rotate-credentials', onclick: guarded(() => agentCredentials(a, true)) }, icon('refresh'), 'Rotate'),
  ] : null;
  if (credentialActions && workload) {
    credentialActions = [h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'show-sign-in', onclick: guarded(() => agentSignIn(a)) }, icon('key'), 'How it authenticates')];
  }
  const platform = platformOf(a);
  let noClient = a.status === 'discovered' ? 'Not issued (unmanaged)' : 'Not issued';
  if (platform) noClient = "Not needed: it doesn't use the gateway";
  return card({
    title: 'Identity',
    sub: platform ? `Runs on ${platform}, outside AgentGov's gateway` : 'The OAuth client the gateway authenticates this agent with',
    actions: credentialActions,
    body: [
      id.error ? callout('critical', 'octagon', h('strong', {}, 'Identity out of sync. '), id.error) : null,
      facts([
        platform ? null : ['Provider', humanize(id.provider || 'none')],
        ['Client ID', id.client_id ? copyable(id.client_id, 'client ID') : h('span', { class: 'muted' }, noClient)],
        platform ? null : ['Authenticates with', workload
          ? ['Its own identity from ', h('a', { href: '#/access' }, workload.issuer)]
          : 'A client secret'],
        workload ? ['Subject', copyable(workload.subject, 'subject')] : null,
        platform ? null : ['Synced', id.synced_at ? timeEl(id.synced_at) : h('span', { class: 'muted' }, 'Not synced yet')],
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

// Agent to agent: where other agents call it, whom it may call, and who may call it.
function agentA2ACard(a, view) {
  if (view instanceof Error) {
    return card({ title: 'Agent to agent', body: callout('critical', 'alert-circle', view.message) });
  }
  const names = (list) => (list.length
    ? h('div', { class: 'chip-row' }, list.map((name) => h('a', { class: 'chip chip--plain', href: `#/agents/${encodeURIComponent(name)}` }, name)))
    : h('span', { class: 'muted' }, 'No agent'));
  const rows = [
    view.serves ? ['Serves A2A at', h('code', { class: 'break' }, view.a2a_url)] : null,
    view.published ? ['Agents call it at', copyable(view.url, 'A2A address')] : null,
    view.published ? ['Its card', copyable(view.card_url, 'agent card address')] : null,
    view.serves && !view.published ? ['On the gateway', h('span', { class: 'muted' }, `Not published: ${view.unpublished}`)] : null,
    ['May call', names(view.may_call)],
    view.agent_access.length ? ['Its grants', h('span', { class: 'chip-row' }, view.agent_access.map((p) => plainChip(p, { mono: true })))] : null,
    view.serves ? ['Called by', names(view.called_by)] : null,
  ];
  const idle = !view.serves && !view.may_call.length && !view.agent_access.length;
  return card({
    title: 'Agent to agent',
    sub: 'Calls between agents go through the gateway (A2A), where policy checks each one; the agent called gets who handed the work down, with the person at its head.',
    body: idle
      ? emptyState("It doesn't serve or call other agents", can('admin') ? 'Give it an A2A endpoint, or agents it may call, with Edit.' : null)
      : facts(rows),
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

/* ------------------------------------------------------------ instructions */

const INSTRUCTION_SOURCES = {
  registered: 'Registered', telemetry: 'Reported in telemetry', 'microsoft-365': 'From Microsoft 365',
};

function classifierLine(c, settings) {
  if (c.state === 'unchecked') {
    return callout('neutral', 'minus', h('span', {}, "Not checked: instruction checks were off when these arrived. They are checked once instruction checks are on (",
      h('a', { href: '#/features' }, 'Features'), ')).'));
  }
  if (!settings?.enabled) return h('p', { class: 'hint' }, 'Checked by AgentGov\'s rules. No classifier is configured.');
  const model = c.model || settings.model;
  if (c.state === 'pending') return h('p', { class: 'hint' }, icon('clock'), ` The classifier (${model}) is still checking these instructions.`);
  if (c.state === 'error') return callout('warning', 'triangle', `The classifier (${model}) failed: ${c.error}`);
  if (c.state === 'done') {
    const flagged = Object.entries(c.verdicts || {}).filter(([, v]) => v === 'yes').map(([k]) => humanize(k));
    return h('p', { class: 'hint' }, `Checked by AgentGov's rules and the classifier (${model})${flagged.length ? `, which flagged ${flagged.join(', ')}` : ', which flagged nothing'}.`);
  }
  return h('p', { class: 'hint' }, 'Checked by AgentGov\'s rules; the classifier hasn\'t checked them yet.');
}

function issueList(issues) {
  if (!issues.length) return h('p', { class: 'tone-text-good small' }, icon('check-circle'), ' No problems found.');
  return h('ul', { class: 'issue-list', role: 'list' }, issues.map((i) => h('li', {},
    h('div', { class: 'issue-head' }, chip('severity', i.severity), h('strong', {}, i.title),
      i.detector === 'classifier' ? plainChip('Classifier', { title: 'Judged by the classifier' }) : null),
    i.excerpt ? h('q', { class: 'issue-excerpt' }, i.excerpt) : null)));
}

function instructionsCard(a, view) {
  if (view instanceof Error) {
    return card({ title: 'Instructions', body: callout('critical', 'alert-circle', `The instructions couldn't be loaded. ${view.message}`) });
  }
  const sources = view.sources || [];
  const admin = can('admin') && a.status !== 'deleted';
  const actions = admin ? [
    sources.length ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'rescan-instructions', onclick: guarded(() => rescanInstructions(a)) }, icon('refresh'), 'Rescan') : null,
    sources.some((x) => x.source === 'registered') ? null
      : h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'add-instructions', onclick: guarded(() => editInstructions(a, null)) }, icon('plus'), 'Add instructions'),
  ].filter(Boolean) : null;
  const body = sources.length ? sources.map((x) => h('div', { class: 'instructions-source' },
    h('div', { class: 'instructions-head' },
      h('div', {}, h('strong', {}, INSTRUCTION_SOURCES[x.source] || x.source_name),
        h('div', { class: 'cell-sub' }, `From ${x.reported_by}, changed `, timeEl(x.updated_at))),
      admin ? h('div', { class: 'btn-row' },
        x.source === 'registered' ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'edit-instructions', onclick: guarded(() => editInstructions(a, x)) }, icon('edit'), 'Edit') : null,
        h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', 'data-focus-key': `forget-${x.source}`, onclick: guarded(() => forgetInstructions(a, x)) }, icon('trash'), 'Forget')) : null),
    x.classifier?.state === 'unchecked' ? null : issueList(x.issues || []),
    classifierLine(x.classifier || {}, view.classifier),
    h('details', { class: 'disclosure' }, h('summary', {}, icon('chevron'), 'Show the instructions'),
      h('pre', { class: 'kv-pre instructions-text', tabindex: '0' }, x.text),
      x.truncated ? h('p', { class: 'hint' }, 'Only the beginning is kept.') : null)))
    : emptyState('No instructions known',
      "Agents that capture message content report them in telemetry (gen_ai.system_instructions), Microsoft 365 reports declarative agents' instructions, and they can be added here or in a manifest.");
  return card({
    title: 'Instructions',
    sub: 'What the agent is told to do (its system prompt), checked for harmful or malicious content. Credentials in it are redacted.',
    actions,
    body,
  });
}

async function editInstructions(a, current) {
  const saved = await ask({
    title: current ? `Edit ${a.name}'s instructions` : `Add instructions for ${a.name}`,
    text: 'The instructions are checked as soon as they are saved, and the result is recorded in the evidence ledger. Credentials in them are redacted before they are stored.',
    iconName: 'edit', confirm: 'Save and check', busy: 'Checking…', wide: true,
    fields: [{ id: 'text', label: 'Instructions', type: 'code', rows: 14, required: true, file: '.txt,.md', value: current?.text || '', placeholder: 'You are the Contoso IT helpdesk assistant. …' }],
    submit: (v) => api(`v1/agents/${encodeURIComponent(a.id)}/instructions`, { method: 'PUT', body: { text: v.text } }),
  });
  if (!saved) return;
  const n = (saved.issues || []).length;
  toast(n ? `Saved. ${plural(n, 'problem')} found in the instructions.` : 'Saved. No problems found.', { tone: n ? 'warning' : 'good' });
  refreshBadges();
  await refresh();
}

async function forgetInstructions(a, x) {
  const done = await ask({
    title: `Forget ${(INSTRUCTION_SOURCES[x.source] || x.source).toLowerCase()} instructions?`,
    text: x.source === 'registered'
      ? 'The registered instructions are removed. A finding about them is resolved.'
      : 'AgentGov forgets this copy. If the source reports the instructions again, they come back and are checked again.',
    tone: 'danger', iconName: 'trash', confirm: 'Forget', busy: 'Forgetting…',
    submit: () => api(`v1/agents/${encodeURIComponent(a.id)}/instructions?source=${encodeURIComponent(x.source)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Forgot ${a.name}'s ${x.source} instructions.`);
  refreshBadges();
  await refresh();
}

async function rescanInstructions(a) {
  const out = await api(`v1/agents/${encodeURIComponent(a.id)}/instructions/rescan`, { method: 'POST' });
  toast(`Checked ${plural(out.rescanned, 'set')} of instructions again.`);
  refreshBadges();
  await refresh();
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

// Edges that count calls: agents' use of tool servers, and agents calling other agents.
const USAGE_EDGES = new Set(['granted', 'ungranted', 'calls', 'calls-ungranted']);
const isUsage = (e) => USAGE_EDGES.has(e.kind);
const isAgentCall = (e) => e.kind === 'calls' || e.kind === 'calls-ungranted';
const isUngranted = (e) => e.kind === 'ungranted' || e.kind === 'calls-ungranted';

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
      const usage = isUsage(e);
      const widthPx = usage ? (e.calls > 0 && maxCalls > 0 ? 1.5 + 4.5 * (Math.log1p(e.calls) / Math.log1p(maxCalls)) : 1.25) : null;
      const from = model.nodes.get(e.from);
      const to = model.nodes.get(e.to);
      const relText = { owner: 'owns', sponsor: 'sponsors', granted: 'is granted', ungranted: 'used without a grant', calls: 'may call', 'calls-ungranted': 'called without a grant' }[e.kind] || e.kind;
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
      edgeLayer.append(s('path', {
        d: `M${x1},${y1} C${c1[0]},${c1[1]} ${c2[0]},${c2[1]} ${x2},${y2}`,
        class: `edge edge-${e.kind}`, 'data-from': e.from, 'data-to': e.to,
        style: widthPx ? `stroke-width: ${widthPx.toFixed(2)}` : null,
      }, s('title', {}, tipText)));
      if (isAgentCall(e)) {
        const half = Math.max(4.5, (widthPx || 1.25) + 1.5);
        edgeLayer.append(s('path', {
          d: `M${(x2 - half * 1.8).toFixed(1)},${(y2 - half).toFixed(1)} L${x2},${y2} L${(x2 - half * 1.8).toFixed(1)},${(y2 + half).toFixed(1)} Z`,
          class: `edge edge-head edge-head-${e.kind}`, 'data-from': e.from, 'data-to': e.to,
        }));
      }
      if (usage && e.calls > 0) {
        const full = e.denied ? `${fmt(e.calls)} calls · ${fmt(e.denied)} denied` : plural(e.calls, 'call');
        const text = full.length * 6 + 16 <= gap - 8 ? full : fmt(e.calls);
        const tw = text.length * 6 + 16;
        let px = bezierPoint(x1, c1[0], c2[0], x2, 0.5);
        const py = bezierPoint(y1, c1[1], c2[1], y2, 0.5);
        // An arc's tag stays clear of the agent column.
        if (isAgentCall(e)) px = Math.min(px, x1 - tw / 2 - 4);
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
    const usage = model.edges.filter(isUsage);
    const ungranted = usage.filter(isUngranted);
    const calls = usage.filter(isAgentCall);
    const busiest = usage.slice().sort((x, y) => (y.calls || 0) - (x.calls || 0))[0];
    return [
      facts([
        ['People', fmt(counts.person || 0)],
        ['Agents', fmt(counts.agent || 0)],
        ['Tool servers', fmt(counts.server || 0)],
        calls.length ? ['Agents calling agents', plural(calls.length, 'connection')] : null,
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
    calls: e.from === id ? 'may call' : 'may be called by', 'calls-ungranted': e.from === id ? 'called without grant' : 'called without grant by',
  }[e.kind] || e.kind);
  const conns = rel.length
    ? h('ul', { class: 'conn-list', role: 'list' }, rel.map((e) => {
      const o = other(e);
      return h('li', {},
        h('span', { class: 'muted' }, relLabel(e)),
        o.kind === 'agent' ? agentLink(o.id.slice(6), o.label) : h('strong', {}, o.label),
        isUsage(e) ? h('span', { class: 'muted' }, `· ${plural(e.calls || 0, 'call')}, ${fmt(e.denied || 0)} denied`) : null,
        isUngranted(e) ? plainChip('no grant', { tone: 'critical', iconName: 'ban' }) : null);
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

function mapLegend(model) {
  const line = (cls, extra = '') => s('svg', { width: 28, height: 10, 'aria-hidden': 'true' }, s('path', { d: 'M1,5 H27', class: `edge ${cls}`, style: extra }));
  const arc = (kind) => s('svg', { width: 28, height: 16, 'aria-hidden': 'true' },
    s('path', { d: 'M25,3 C9,3 9,12 25,12', class: `edge edge-${kind}`, style: 'stroke-width:2' }),
    s('path', { d: 'M19,8 L26,12 L19,16 Z', class: `edge edge-head edge-head-${kind}` }));
  const stripe = (tone) => h('span', { class: 'swatch', style: `background:${TONE_COLOR[tone]}; width:6px; height:14px` });
  const item = (mark, label) => h('span', { class: 'legend-item' }, mark, label);
  const agentCalls = model.edges.filter(isAgentCall);
  return h('div', { class: 'map-legend' },
    item(line('edge-owner'), 'Owner'),
    item(line('edge-sponsor'), 'Sponsor'),
    item(line('edge-granted', 'stroke-width:3'), 'Granted (width = calls)'),
    item(line('edge-ungranted', 'stroke-width:2'), 'Used without a grant'),
    agentCalls.length ? item(arc('calls'), 'May call another agent') : null,
    agentCalls.some(isUngranted) ? item(arc('calls-ungranted'), 'Called an agent without a grant') : null,
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
  const agentCalls = model.edges.some(isAgentCall);
  return h('div', { class: 'page' },
    pageHead({
      title: 'Agent map',
      sub: 'Who is accountable for each agent, and which tool servers and other agents each agent can reach or has used in the last 30 days.',
      actions: [refreshButton()],
    }),
    h('div', { class: 'map-layout' },
      card({
        title: 'People, agents and tool servers',
        sub: agentCalls
          ? 'Columns are fixed: accountable people on the left, tool servers on the right. Arcs beside the agents point from an agent to the agents it calls.'
          : 'Columns are fixed: accountable people on the left, tool servers on the right.',
        body: [mapLegend(model), view],
      }),
      h('section', { class: 'card map-detail', 'aria-labelledby': 'map-detail-title', 'aria-live': 'polite' },
        h('div', { class: 'card-head' }, h('div', { class: 'card-head-text' }, detailTitle)), detailBody)),
    connections);
}

function connectionsTable(model) {
  if (!model.edges.length) return null;
  const order = { owner: 0, sponsor: 1, granted: 2, ungranted: 3, calls: 4, 'calls-ungranted': 5 };
  const rows = model.edges.slice().sort((x, y) => String(model.nodes.get(x.from).label).localeCompare(String(model.nodes.get(y.from).label)) || order[x.kind] - order[y.kind]);
  const label = { owner: 'Owner of', sponsor: 'Sponsor of', granted: 'Granted', ungranted: 'Used without a grant', calls: 'May call', 'calls-ungranted': 'Called without a grant' };
  const nameCell = (n) => (n.kind === 'agent' ? agentLink(n.id.slice(6), n.label) : n.label);
  return card({
    title: 'Connections',
    sub: 'The same graph as a table',
    flush: true,
    body: h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
      h('thead', {}, h('tr', {}, ['From', 'Relation', 'To', 'Calls (30 days)', 'Denied'].map((t, i) => h('th', { scope: 'col', class: i > 2 ? 'num' : null }, t)))),
      h('tbody', {}, rows.map((e) => {
        const usage = isUsage(e);
        return h('tr', {},
          h('td', { 'data-label': 'From', class: 'break' }, nameCell(model.nodes.get(e.from))),
          h('td', { 'data-label': 'Relation' }, isUngranted(e) ? plainChip(label[e.kind], { tone: 'critical', iconName: 'ban' }) : label[e.kind]),
          h('td', { 'data-label': 'To', class: 'break' }, nameCell(model.nodes.get(e.to))),
          h('td', { 'data-label': 'Calls', class: 'num' }, usage ? fmt(e.calls || 0) : '—'),
          h('td', { 'data-label': 'Denied', class: 'num' }, usage ? fmt(e.denied || 0) : '—'));
      })))),
  });
}

/* --------------------------------------------------------------- approvals */

async function renderApprovals({ match }) {
  const tab = match[1] === 'history' ? 'history' : 'pending';
  const person = isPerson();
  // Requests sent to the person signed in: agents acted for them.
  const [all, agents, mine] = await Promise.all([
    person ? api('v1/me/approvals') : api('v1/approvals'),
    person ? [] : api('v1/agents?include_deleted=true').catch(() => []),
    api('v1/me/approvals?status=pending').catch(() => []),
  ]);
  const agentsById = new Map(agents.map((a) => [a.id, a]));
  const mineIds = new Set(mine.map((r) => r.id));
  const pending = all.filter((r) => r.status === 'pending');
  const history = all.filter((r) => r.status !== 'pending');
  updateBadges({ pendingApprovals: pending.length });
  const approvalsMode = person ? 'enforce' : (await featureModes().catch(() => ({}))).approvals;
  const card = (r) => approvalCard(r, agentsById.get(r.agent_id), mineIds.has(r.id));
  const tabs = h('nav', { class: 'tabs', 'aria-label': 'Approval views' },
    h('a', { class: 'tab', href: '#/approvals', 'aria-current': tab === 'pending' ? 'page' : null },
      'Pending', h('span', { class: 'nav-badge', 'data-tone': pending.length ? 'warning' : '' }, fmt(pending.length))),
    h('a', { class: 'tab', href: '#/approvals/history', 'aria-current': tab === 'history' ? 'page' : null },
      'History', h('span', { class: 'nav-badge' }, fmt(history.length))));
  let content;
  if (tab === 'pending') {
    // Yours first: requests agents made while acting for you wait for your decision.
    const yours = pending.filter((r) => mineIds.has(r.id));
    const others = pending.filter((r) => !mineIds.has(r.id));
    content = pending.length
      ? h('div', { class: 'stack' },
        yours.length && !person ? h('div', { class: 'section-title' }, h('h2', {}, 'Waiting for you')) : null,
        yours.length ? h('div', { class: 'approval-list' }, yours.map(card)) : null,
        yours.length && others.length ? h('div', { class: 'section-title' }, h('h2', {}, "Everyone else's")) : null,
        others.length ? h('div', { class: 'approval-list' }, others.map(card)) : null)
      : h('section', { class: 'card' }, person
        ? emptyState('Nothing is waiting for you', 'When an agent acting for you needs your approval to do something, it appears here.')
        : emptyState('Nothing is waiting for approval',
          'When policy holds a tool call for a human (for example a tool its server marks destructive), it appears here.'));
  } else {
    content = h('section', { class: 'card', 'aria-label': 'Approval history' },
      history.length ? approvalHistoryTable(history) : emptyState('No decided approvals yet'));
  }
  return h('div', { class: 'page', 'data-title': tab === 'history' ? 'Approval history' : 'Approvals' },
    pageHead({
      title: 'Approvals',
      sub: person
        ? 'What agents acting for you want to do, and need you to approve first. Approve a call and the agent can make it once.'
        : 'Tool calls that policy held for a human decision. An approval is single-use: the agent retries the identical call and it goes through once.',
      actions: [refreshButton()],
    }),
    approvalsMode && approvalsMode !== 'enforce' ? callout('warning', 'eye', h('span', {},
      h('strong', {}, `Human approval is ${approvalsMode === 'off' ? 'off' : 'in monitor mode'}: `),
      approvalsMode === 'off' ? 'no call waits for approval. ' : 'calls that need approval go through, and the ledger records them. ',
      h('a', { href: '#/features' }, 'Features'), '.')) : null,
    tabs, content);
}

function approvalCard(r, agent, mine = false) {
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
  // The person it was sent to decides it, or approvers; administrators can always decide.
  const forPerson = r.deciders === 'person';
  const mayDecide = can('admin') || (forPerson ? mine : can('approve') || can('decide'));
  const deciders = forPerson ? (mine ? 'You decide this request.' : `${r.on_behalf_of} decides this request.`) : 'An approver or admin decides this request.';
  return h('section', { class: 'card approval', 'aria-labelledby': headingId, 'data-focus-key': `approval-${r.id}`, tabindex: '-1' },
    h('div', { class: 'card-head' },
      h('div', { class: 'card-head-text' },
        h('h2', { id: headingId, class: 'resource' }, r.resource),
        h('p', { class: 'card-sub' }, `${r.action} requested by `, isPerson() ? r.agent_name : agentLink(r.agent_id, r.agent_name),
          r.on_behalf_of ? [' for ', mine ? 'you' : isPerson() ? r.on_behalf_of : personLink(r.on_behalf_of)] : null, ' · ', timeEl(r.requested_at))),
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
      forPerson && !mine && mayDecide
        ? callout('neutral', 'info', `${r.on_behalf_of}, whom the agent acted for, decides this request. As an administrator, you can decide it instead.`)
        : null,
      mayDecide
        ? h('div', { class: 'decide' },
          h('div', { class: 'field' }, h('label', { for: noteId }, 'Note for the ledger ', h('span', { class: 'muted' }, '(optional)')), note),
          h('div', { class: 'btn-row' }, denyBtn, approveBtn))
        : h('p', { class: 'muted small' }, deciders)));
}

function approvalHistoryTable(rows) {
  return h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
    h('thead', {}, h('tr', {}, ['Outcome', 'Tool call', 'Agent', 'For', 'Decided by', 'Decided', 'Note', 'Requested'].map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', {}, rows.map((r) => h('tr', {},
      h('td', { 'data-label': 'Outcome' }, chip('approval', r.status, { title: r.used_at ? `Used ${fullFmt.format(new Date(r.used_at))}` : null })),
      h('td', { 'data-label': 'Tool call' }, h('span', { class: 'resource' }, r.resource)),
      h('td', { 'data-label': 'Agent', class: 'break' }, isPerson() ? r.agent_name : agentLink(r.agent_id, r.agent_name)),
      h('td', { 'data-label': 'For', class: 'break' }, r.on_behalf_of ? (isPerson() ? r.on_behalf_of : personLink(r.on_behalf_of)) : h('span', { class: 'muted' }, '—')),
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
      actions: [
        can('admin') ? h('button', { type: 'button', class: 'btn btn--primary', 'data-focus-key': 'register-server', onclick: guarded(registerToolserver) }, icon('plus'), 'Register tool server') : null,
        refreshButton(),
      ],
    }),
    servers.length
      ? h('div', { class: 'stack' }, servers.map(serverCard))
      : h('section', { class: 'card' }, emptyState('No tool servers registered',
        can('admin') ? 'Register an MCP server to publish it through the gateway.' : 'An admin registers MCP servers here, with the CLI or with a ToolServer manifest.')));
}

const TRUST_LEVELS = [['unverified', 'Unverified'], ['verified', 'Verified']];

// Packages developers run, one per line as type:identifier@version (the CLI's --package).
function formatPackages(packages) {
  return (packages || []).map((p) => `${p.registry_type}:${p.identifier}${p.version ? `@${p.version}` : ''}`).join('\n');
}

function parsePackages(text) {
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
const CLASSIFICATIONS = [['public', 'Public'], ['internal', 'Internal'], ['confidential', 'Confidential'], ['restricted', 'Restricted']];

/** Register a tool server (no `ts`, starting from `draft` if given) or edit one. Resolves
 * to the saved server, or null. */
function toolserverForm(ts, draft = null) {
  const editing = Boolean(ts);
  ts = ts || draft;
  const options = (pairs) => pairs.map(([value, label]) => ({ value, label }));
  return ask({
    title: editing ? `Edit ${ts.name}` : 'Register a tool server',
    text: editing
      ? 'Changes are recorded in the evidence ledger. A new upstream URL takes effect when the gateway reloads its generated configuration.'
      : 'Published on the gateway, the server is at /mcp/<name>, where agents whose grants cover it call its tools. Listed for developers, it is in the MCP registry their MCP clients read.',
    iconName: editing ? 'edit' : 'toolservers', confirm: editing ? 'Save changes' : 'Register server',
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, value: ts?.name || '', placeholder: 'crm', hint: `${NAME_HINT} It becomes the gateway path /mcp/<name>.` },
      { id: 'url', label: 'Upstream URL', mono: true, value: ts?.url || '', placeholder: 'http://crm-mcp:8000/mcp', hint: 'The streamable HTTP MCP endpoint, required on the gateway. Agents never call it directly, only through the gateway.' },
      { id: 'description', label: 'Description', type: 'textarea', value: ts?.description || '' },
      { id: 'owner', label: 'Owner', value: ts?.owner || '', placeholder: 'Team or person' },
      { type: 'row', fields: [
        { id: 'trust_level', label: 'Trust level', type: 'select', value: ts?.trust_level || 'unverified', options: options(TRUST_LEVELS) },
        { id: 'data_classification', label: 'Data classification', type: 'select', value: ts?.data_classification || 'internal', options: options(CLASSIFICATIONS) },
      ] },
      { id: 'labels', label: 'Labels', value: formatLabels(ts?.labels), placeholder: 'team=cx', mono: true },
      { type: 'section', label: 'Who uses it' },
      { id: 'gateway', label: 'Agents, through the gateway', type: 'checkbox', value: ts ? ts.gateway : true, hint: 'Published at /mcp/<name>, with every control.' },
      { id: 'developers', label: "Developers, in the MCP registry", type: 'checkbox', value: Boolean(ts?.developers), hint: 'Listed in the registry GitHub Copilot and VS Code read (Developer tools).' },
      { id: 'packages', label: 'Packages developers run', type: 'code', rows: 2, value: formatPackages(ts?.packages), placeholder: 'npm:@playwright/mcp@0.0.41', hint: 'For a server developers run on their machines: one per line, type:identifier@version (npm, pypi, oci, nuget, cargo, mcpb).' },
      { id: 'registry_name', label: 'Name in the registry', mono: true, value: ts?.registry_name || '', placeholder: 'com.contoso/crm', hint: 'By default <namespace>/<name>.' },
    ].filter(Boolean),
    submit: (v) => {
      const body = {
        url: v.url, description: v.description, owner: orNull(v.owner),
        trust_level: v.trust_level, data_classification: v.data_classification, labels: parseLabels(v.labels),
        gateway: v.gateway, developers: v.developers, packages: parsePackages(v.packages), registry_name: orNull(v.registry_name),
      };
      if (editing) return api(`v1/toolservers/${encodeURIComponent(ts.name)}`, { method: 'PATCH', body });
      return api('v1/toolservers', { method: 'POST', body: { name: v.name, ...body } });
    },
  });
}

async function registerToolserver() {
  const created = await toolserverForm(null);
  if (!created) return;
  toast(created.gateway
    ? `Registered ${created.name}. Agents reach it at ${created.gateway_url || `/mcp/${created.name}`}.`
    : `Registered ${created.name} for developers.`);
  await refresh();
}

async function editToolserver(ts) {
  const saved = await toolserverForm(ts);
  if (!saved) return;
  toast(`Saved ${saved.name}.`);
  await refresh();
}

async function deleteToolserver(ts) {
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
  if (!can('admin') && can('contain') && ts.status !== 'pending') {
    actions.push(ts.status === 'blocked'
      ? h('button', { type: 'button', class: 'btn btn--primary', 'data-focus-key': `ts-unblock-${ts.name}`, onclick: () => serverAction(ts, 'unblock') }, icon('undo'), 'Unblock')
      : h('button', { type: 'button', class: 'btn btn--danger-quiet', 'data-focus-key': `ts-block-${ts.name}`, onclick: () => serverAction(ts, 'block') }, icon('power'), 'Block server'));
  }
  if (can('admin')) {
    if (ts.status === 'pending') actions.push(h('button', { type: 'button', class: 'btn btn--primary', 'data-focus-key': `ts-approve-${ts.name}`, onclick: () => serverAction(ts, 'approve') }, icon('check'), 'Approve'));
    actions.push(h('button', { type: 'button', class: 'btn', 'data-focus-key': `ts-edit-${ts.name}`, onclick: guarded(() => editToolserver(ts)) }, icon('edit'), 'Edit'));
    if (ts.status === 'blocked') actions.push(h('button', { type: 'button', class: 'btn btn--primary', 'data-focus-key': `ts-unblock-${ts.name}`, onclick: () => serverAction(ts, 'unblock') }, icon('undo'), 'Unblock'));
    else actions.push(h('button', { type: 'button', class: 'btn btn--danger-quiet', 'data-focus-key': `ts-block-${ts.name}`, onclick: () => serverAction(ts, 'block') }, icon('power'), 'Block server'));
    actions.push(h('button', { type: 'button', class: 'btn btn--danger-quiet', 'data-focus-key': `ts-delete-${ts.name}`, onclick: () => deleteToolserver(ts) }, icon('trash'), 'Delete'));
  }
  const headingId = nextId('server');
  const trustChip = ts.trust_level === 'verified'
    ? plainChip('Verified', { tone: 'good', iconName: 'shield-check' })
    : plainChip(humanize(ts.trust_level || 'unverified'), { tone: 'warning', iconName: 'shield' });
  return h('section', { class: 'card', 'aria-labelledby': headingId },
    h('div', { class: 'card-body' },
      h('div', { class: 'server-head' },
        h('div', { class: 'server-title' },
          h('div', { class: 'title-row' }, h('h2', { id: headingId, class: 'tool-name' }, ts.name), chip('server', ts.status), trustChip,
            plainChip(humanize(ts.data_classification || 'unclassified'), { iconName: 'lock', title: 'Data classification' }),
            ts.developers ? plainChip(ts.gateway ? 'Listed for developers' : 'Developers only', { iconName: 'developers', title: 'In the MCP registry developers\' MCP clients read' }) : null),
          ts.description ? h('p', { style: 'color:var(--ink-2)' }, ts.description) : null),
        h('div', { class: 'btn-row' }, actions)),
      poisoned.length ? callout('critical', 'octagon', h('span', {}, h('strong', {}, `${plural(poisoned.length, 'tool')} quarantined. `),
        'Hidden instructions were found in the description, so the tool is hidden from agents and calls to it are denied. Block the server if the definition is malicious.')) : null,
      changed.length ? callout('warning', 'triangle', h('span', {}, h('strong', {}, `${plural(changed.length, 'tool')} changed since approval. `),
        'Calls are refused until an administrator approves the new definition.')) : null,
      facts([
        ts.gateway ? ['Gateway URL', ts.gateway_url ? copyable(ts.gateway_url, 'gateway URL') : h('span', { class: 'muted' }, 'Gateway public URL not configured')] : ['Gateway', h('span', { class: 'muted' }, 'Not published: only for developers')],
        ['Upstream', ts.url ? h('code', { class: 'break' }, ts.url) : null],
        (ts.packages || []).length ? ['Packages', h('div', { class: 'chip-row' }, ts.packages.map((pk) => plainChip(formatPackages([pk]), { mono: true })))] : null,
        ['Owner', ts.owner],
        ts.gateway ? ['Catalog', `${plural(tools.length, 'tool')} · ${fmt(poisoned.length)} poisoned · ${fmt(changed.length)} changed`] : null,
        ts.gateway ? ['Catalog synced', timeEl(ts.tools_synced_at, { empty: 'Not yet observed' })] : null,
      ]),
      ts.gateway ? h('div', {}, toggle) : null),
    ts.gateway ? catalog : null);
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
        h('td', { 'data-label': '' }, changed && can('admin')
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

const FINDING_STATUS = [
  ['open', 'Open'], ['mine', 'Yours'], ['accepted', 'Risk accepted'], ['resolved', 'Resolved'], ['dismissed', 'Dismissed'], ['all', 'All'],
];
const LEVEL_WORDS = { owner: 'its owner', sponsors: 'its sponsors', team: 'its team' };
const FINDING_DONE = { resolve: 'Resolved', dismiss: 'Dismissed', reopen: 'Reopened', acknowledge: 'Acknowledged' };

// What the signed-in person may do to findings: approvers, administrators and (from triage)
// the secops role act on all of them; the people an issue reached acknowledge it.
function mayTriage() {
  return can('approve') || can('triage');
}

function findingTabs(current) {
  if (isPerson()) return null;
  return h('nav', { class: 'tabs', 'aria-label': 'Finding views' },
    h('a', { class: 'tab', href: '#/findings', 'aria-current': current === 'findings' ? 'page' : null }, 'Findings'),
    h('a', { class: 'tab', href: '#/findings/teams', 'aria-current': current === 'teams' ? 'page' : null }, 'Teams'));
}

async function renderFindings({ params }) {
  const person = isPerson();
  const statuses = person ? FINDING_STATUS.filter(([k]) => !['mine', 'dismissed'].includes(k)) : FINDING_STATUS;
  const state = {
    status: statuses.some(([k]) => k === params.get('status')) ? params.get('status') : 'open',
    severity: params.get('severity') || '',
    category: params.get('category') || '',
  };
  // People without a role see the issues sent to them; everyone else, every finding, or theirs.
  const source = (status) => (person ? `v1/me/issues?status=${encodeURIComponent(status)}`
    : status === 'mine' ? 'v1/me/issues?status=open' : `v1/findings?status=${encodeURIComponent(status)}`);
  const [initial, agents] = await Promise.all([
    api(source(state.status)),
    person ? [] : api('v1/agents?include_deleted=true').catch(() => []),
  ]);
  let list = initial;
  const agentsById = new Map(agents.map((a) => [a.id, a]));
  const badge = () => { if (state.status === 'open') updateBadges({ findings: summarizeFindings(list) }); };
  badge();

  const statusHost = h('div', { class: 'seg', role: 'group', 'aria-label': 'Finding status' });
  const sevHost = h('div', { class: 'seg', role: 'group', 'aria-label': 'Severity' });
  const category = h('select', { id: 'finding-category', 'data-focus-key': 'finding-category' },
    [['', 'All categories'], ['threat', 'Threats'], ['posture', 'Posture']].map(([v, l]) => h('option', { value: v, selected: v === state.category }, l)));
  const countEl = h('p', { class: 'result-count', 'aria-live': 'polite' });
  const listHost = h('div', { class: 'finding-list' });
  const listTitle = h('h2', { class: 'sr-only', tabindex: '-1', id: 'finding-list-title' }, 'Findings');

  const sync = () => setHashQuiet('/findings', { status: state.status === 'open' ? '' : state.status, severity: state.severity, category: state.category });

  async function reload() {
    list = await api(source(state.status));
    badge();
  }

  async function act(f, action, rows) {
    try {
      if (action === 'accept') {
        if (!await acceptRisk(f)) return;
      } else {
        await api(`v1/findings/${encodeURIComponent(f.id)}/${action}`, { method: 'POST' });
        toast(`${FINDING_DONE[action]}: ${f.title}`);
      }
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
  }

  function apply() {
    statusHost.replaceChildren(...statuses.map(([key, label]) => h('button', {
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
    const word = person || state.status === 'mine' ? 'issue' : 'finding';
    const which = ['all', 'mine'].includes(state.status) ? '' : `${statusMeta('finding', state.status)[2].toLowerCase()} `;
    countEl.textContent = plural(rows.length, `${which}${word}`);
    const yours = person || state.status === 'mine';
    listHost.replaceChildren(...(rows.length
      ? rows.map((f) => findingCard(f, agentsById, (action) => act(f, action, rows), { yours }))
      : [h('section', { class: 'card' }, emptyFindings(state.status, person))]));
  }

  category.addEventListener('change', () => { state.category = category.value; apply(); sync(); });
  apply();
  return h('div', { class: 'page', 'data-title': person ? 'Your issues' : 'Findings' },
    pageHead({
      title: person ? 'Your issues' : 'Findings',
      sub: person
        ? 'Issues about agents you own or sponsor, and those sent to your teams. Acknowledge one to take it on: it then goes no further. Fix what it says and it closes by itself.'
        : 'Posture gaps from scheduled scans and threats detected at runtime, most severe first. Each goes to the people responsible: the agent\'s owner, then its sponsors, then its team.',
      actions: [refreshButton()],
    }),
    findingTabs('findings'),
    h('div', { class: 'filters' }, statusHost,
      h('div', { class: 'field', style: 'flex:0 1 180px' }, h('label', { for: 'finding-category', class: 'sr-only' }, 'Category'), category)),
    h('div', { class: 'filters' }, sevHost, countEl),
    listTitle,
    listHost);
}

function emptyFindings(status, person) {
  if (status === 'mine' || (person && status === 'open')) {
    return emptyState('Nothing is waiting for you', 'Issues about agents you own or sponsor, and those sent to your teams, appear here.');
  }
  if (status === 'open') return emptyState('No open findings', 'Posture scans and runtime detections raise findings here.');
  return emptyState('No findings match these filters');
}

// Who an issue is with, and what they did about it.
function issueLine(f) {
  if (f.status === 'accepted') {
    return h('p', { class: 'finding-issue' }, icon('shield-check'), h('span', {},
      h('strong', {}, 'Risk accepted '), 'until ', timeEl(f.accepted_until, { absolute: true }), f.accepted_reason ? `: ${f.accepted_reason}` : ''));
  }
  if (f.status !== 'open') return null;
  if (!f.level) return null;
  const who = (f.assignees || []).join(', ');
  if (f.acknowledged_at) {
    return h('p', { class: 'finding-issue' }, icon('user-check'), h('span', {},
      h('strong', {}, `${f.acknowledged_by?.replace(/^[a-z]+:/, '') || 'Someone'} took it on `), timeEl(f.acknowledged_at)));
  }
  return h('p', { class: 'finding-issue' }, icon('user'), h('span', {},
    'With ', h('strong', {}, LEVEL_WORDS[f.level] || f.level), who ? ` (${who})` : '',
    f.escalate_at ? [', goes further ', timeEl(f.escalate_at), ' unless someone acknowledges it'] : ''));
}

function findingActions(f, act, { yours = false, detail = false } = {}) {
  const triage = mayTriage();
  const buttons = [];
  if (!detail) {
    buttons.push(h('a', { class: 'btn btn--sm btn--ghost', href: `#/findings/${encodeURIComponent(f.id)}` }, 'Details', icon('arrow')));
  }
  if (f.status === 'open') {
    if (f.level && !f.acknowledged_at && (triage || yours)) {
      buttons.push(h('button', { type: 'button', class: 'btn btn--sm', onclick: () => act('acknowledge') }, icon('user-check'), 'Acknowledge'));
    }
    if (triage) {
      buttons.push(
        h('button', { type: 'button', class: 'btn btn--sm', onclick: () => act('accept') }, icon('shield-check'), 'Accept risk'),
        h('button', { type: 'button', class: 'btn btn--sm', onclick: () => act('dismiss') }, icon('minus'), 'Dismiss'),
        h('button', { type: 'button', class: 'btn btn--sm btn--primary', onclick: () => act('resolve') }, icon('check'), 'Resolve'));
    }
  } else if (triage) {
    buttons.push(h('button', { type: 'button', class: 'btn btn--sm', onclick: () => act('reopen') }, icon('undo'), 'Reopen'));
  }
  return buttons;
}

async function acceptRisk(f) {
  const later = new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10);
  const done = await ask({
    title: 'Accept the risk?',
    text: `${f.title}. It goes to nobody until the date you choose, then opens again if it still holds. A year at most: then someone decides again.`,
    iconName: 'shield-check', confirm: 'Accept risk',
    fields: [
      { id: 'reason', label: 'Why it is acceptable', type: 'textarea', required: true, hint: 'Recorded in the evidence ledger, and shown with the finding.' },
      { id: 'until', label: 'Until', required: true, value: later, mono: true, hint: 'A date (YYYY-MM-DD), or a number of days.' },
    ],
    submit: (v) => api(`v1/findings/${encodeURIComponent(f.id)}/accept`, {
      method: 'POST', body: { reason: v.reason, until: /^\d+$/.test(v.until) ? Number(v.until) : v.until },
    }),
  });
  if (done) toast(`Risk accepted until ${done.accepted_until.slice(0, 10)}: ${f.title}`);
  return done;
}

function findingCard(f, agentsById, act, { yours = false } = {}) {
  const tone = toneOf('severity', f.severity);
  const agent = f.agent_id ? agentsById.get(f.agent_id) : null;
  const headingId = `finding-title-${f.id}`;
  const subject = f.agent_id && !isPerson() ? agentLink(f.agent_id, agent?.name || f.subject) : h('code', {}, agent?.name || f.subject);
  return h('article', { class: 'card finding', 'data-tone': tone, 'aria-labelledby': headingId, tabindex: '-1', 'data-focus-key': `finding-${f.id}` },
    h('div', { class: 'finding-stripe', 'aria-hidden': 'true' }),
    h('div', { class: 'finding-main' },
      h('div', { class: 'finding-top' }, chip('severity', f.severity), plainChip(humanize(f.category)),
        f.status !== 'open' ? chip('finding', f.status) : null,
        f.verified === false ? plainChip('Unverified', { tone: 'warning', iconName: 'triangle', title: 'The sync that checks it failed: it may no longer hold.' }) : null,
        h('span', { class: 'ledger-type muted' }, f.type)),
      h('h3', { id: headingId, class: 'break' }, f.title),
      f.description ? h('p', { class: 'finding-desc small' }, f.description) : null,
      f.remediation ? h('p', { class: 'finding-fix' }, h('strong', {}, 'How to fix: '), f.remediation) : null,
      issueLine(f),
      h('div', { class: 'finding-actions' },
        h('div', { class: 'finding-meta' },
          h('span', {}, 'Subject: ', subject),
          h('span', {}, `Seen ${f.occurrences === 1 ? 'once' : `${fmt(f.occurrences)} times`}`),
          h('span', {}, 'First ', timeEl(f.first_seen)),
          h('span', {}, 'Last ', timeEl(f.last_seen)),
          f.resolved_at ? h('span', {}, `${f.status === 'dismissed' ? 'Dismissed' : f.status === 'accepted' ? 'Accepted' : 'Resolved'} by ${f.resolved_by || 'unknown'} `, timeEl(f.resolved_at)) : null),
        h('div', { class: 'btn-row' }, findingActions(f, act, { yours })))));
}

/* ------------------------------------------------------------ one finding */

async function renderFinding({ match }) {
  const id = decodeURIComponent(match[1]);
  const f = await api(`v1/findings/${encodeURIComponent(id)}`);
  const person = isPerson();
  const act = guarded(async (action) => {
    if (action === 'accept') {
      if (!await acceptRisk(f)) return;
    } else {
      await api(`v1/findings/${encodeURIComponent(f.id)}/${action}`, { method: 'POST' });
      toast(`${FINDING_DONE[action]}: ${f.title}`);
    }
    refreshBadges();
    await refresh();
  });
  const subject = f.agent_id && !person ? agentLink(f.agent_id, f.agent_name || f.subject) : h('code', {}, f.agent_name || f.subject);
  const crumbs = h('nav', { class: 'crumbs', 'aria-label': 'Breadcrumb' },
    h('a', { href: '#/findings' }, person ? 'Your issues' : 'Findings'), icon('chevron'), h('span', { 'aria-current': 'page' }, f.type));
  return h('div', { class: 'page', 'data-title': f.title },
    pageHead({ title: f.title, crumbs, actions: [refreshButton()] }),
    h('div', { class: 'chip-row' }, chip('severity', f.severity), chip('finding', f.status), plainChip(humanize(f.category)),
      f.verified === false ? plainChip('Unverified', { tone: 'warning', iconName: 'triangle' }) : null),
    f.verified === false ? callout('warning', 'triangle', h('span', {}, h('strong', {}, 'Unverified: '),
      'the latest sync that checks it failed, so it may no longer hold. It stays open until a sync succeeds.')) : null,
    card({
      title: 'What it is',
      body: h('div', { class: 'stack' },
        f.description ? h('p', {}, f.description) : null,
        f.remediation ? h('p', { class: 'finding-fix' }, h('strong', {}, 'How to fix: '), f.remediation) : null,
        facts([
          ['Subject', subject],
          ['Seen', `${f.occurrences === 1 ? 'once' : `${fmt(f.occurrences)} times`}, first `, timeEl(f.first_seen), ', last ', timeEl(f.last_seen)],
          f.status === 'accepted' ? ['Risk accepted until', [timeEl(f.accepted_until, { absolute: true }), f.accepted_reason ? `: ${f.accepted_reason}` : '']] : null,
          f.acknowledged_at ? ['Acknowledged', [`by ${f.acknowledged_by} `, timeEl(f.acknowledged_at)]] : null,
          f.resolved_at && f.status !== 'open' ? [humanize(f.status), [`by ${f.resolved_by || 'unknown'} `, timeEl(f.resolved_at)]] : null,
        ].map((row) => row && [row[0], Array.isArray(row[1]) ? h('span', {}, row[1]) : h('span', {}, ...row.slice(1))])),
        h('div', { class: 'btn-row' }, findingActions(f, act, { yours: f.yours, detail: true }))),
    }),
    chainCard(f),
    notificationsCard(f),
    historyCard(f));
}

function chainCard(f) {
  const steps = f.chain || [];
  const body = steps.length
    ? h('ol', { class: 'levels' }, steps.map((step) => h('li', { 'data-reached': step.reached ? 'true' : 'false', 'aria-current': step.current ? 'step' : null },
      icon(step.current ? 'user' : step.reached ? 'check-circle' : 'minus'),
      h('div', {}, h('strong', {}, humanize(step.level)), h('div', { class: 'cell-sub break' }, step.who.join(', ')),
        step.current && f.status === 'open' && f.escalate_at && !f.acknowledged_at
          ? h('div', { class: 'cell-sub' }, 'Goes to the next step ', timeEl(f.escalate_at), ' unless someone acknowledges it') : null))))
    : emptyState('Nobody to send it to', 'Give the agent an owner or sponsors, or mark a team as the default team: issues with nobody else go to it.');
  return card({
    title: 'Who it goes to',
    sub: 'Step by step, until someone acknowledges it: an agent\'s owner, then its sponsors, then its team. Each step is told by email and in its team\'s chat.',
    body,
  });
}

function notificationsCard(f) {
  const rows = f.notifications || [];
  if (!rows.length) return null;
  return card({
    title: 'Messages',
    sub: 'Emails and chat messages about it, retried until they go.',
    flush: true,
    body: h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
      h('caption', { class: 'sr-only' }, 'Messages'),
      h('thead', {}, h('tr', {}, ['To', 'Step', 'Status'].map((t) => h('th', { scope: 'col' }, t)))),
      h('tbody', {}, rows.map((n) => h('tr', {},
        h('td', { 'data-label': 'To', class: 'break' }, h('span', { class: 'cell-title' }, n.recipient), h('div', { class: 'cell-sub' }, n.channel === 'email' ? 'Email' : humanize(n.channel))),
        h('td', { 'data-label': 'Step' }, humanize(n.level)),
        h('td', { 'data-label': 'Status' }, chip('notification', n.status),
          n.sent_at ? h('div', { class: 'cell-sub' }, timeEl(n.sent_at)) : null,
          n.last_error ? h('div', { class: 'cell-sub break' }, n.last_error) : null,
          n.next_attempt_at && n.attempts ? h('div', { class: 'cell-sub' }, 'Tries again ', timeEl(n.next_attempt_at)) : null)))))),
  });
}

function historyCard(f) {
  const rows = f.history || [];
  if (!rows.length) return null;
  return card({
    title: 'History',
    sub: 'From the evidence ledger, newest first.',
    body: h('ul', { class: 'timeline', role: 'list' }, rows.map((e) => h('li', {},
      h('div', { class: 'cell-title' }, humanize(e.type.replace(/^finding\./, ''))),
      h('div', { class: 'cell-sub break' }, e.actor, ' · ', timeEl(e.ts),
        e.details?.to ? ` · to ${e.details.to}` : '',
        e.details?.why ? ` · ${e.details.why}` : '',
        e.details?.assignees ? ` · ${e.details.assignees.join(', ')}` : '')))),
  });
}

/* ------------------------------------------------------------------- teams */

async function renderTeams() {
  if (isPerson()) { location.replace('#/findings'); return h('div'); }
  const [teams, destinations] = await Promise.all([api('v1/teams'), api('v1/destinations').catch(() => [])]);
  const chats = destinations.filter((d) => ['teams', 'slack'].includes(d.kind));
  const admin = can('admin');
  const hasDefault = teams.some((t) => t.default);
  const body = teams.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
    h('caption', { class: 'sr-only' }, 'Teams'),
    h('thead', {}, h('tr', {}, ['Team', 'Members', 'Reached at', ''].map((t) => h('th', { scope: 'col' }, t || h('span', { class: 'sr-only' }, 'Actions'))))),
    h('tbody', {}, teams.map((t) => h('tr', { 'data-team': t.name },
      h('td', { 'data-label': 'Team', class: 'break' }, h('span', { class: 'cell-title' }, t.name),
        t.default ? h('div', {}, plainChip('Default team', { tone: 'good', iconName: 'check-circle' })) : null,
        t.description ? h('div', { class: 'cell-sub' }, t.description) : null),
      h('td', { 'data-label': 'Members', class: 'break' }, t.members.length ? t.members.join(', ') : h('span', { class: 'muted' }, 'None')),
      h('td', { 'data-label': 'Reached at', class: 'break' },
        t.emails.length ? h('div', {}, t.emails.join(', ')) : t.members.some((m) => m.includes('@')) ? h('div', { class: 'cell-sub' }, "Its members' email addresses") : null,
        t.destinations.length ? h('div', { class: 'chip-row' }, t.destinations.map((d) => plainChip(d, { iconName: 'secops' }))) : null,
        !t.emails.length && !t.destinations.length && !t.members.some((m) => m.includes('@')) ? h('span', { class: 'muted' }, 'In AgentGov only') : null),
      h('td', { 'data-label': '' }, admin ? h('div', { class: 'btn-row' },
        h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `team-edit-${t.name}`, onclick: guarded(() => teamForm(t, chats)) }, icon('edit'), 'Edit'),
        h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', 'data-focus-key': `team-delete-${t.name}`, onclick: guarded(() => deleteTeam(t)) }, icon('trash'), 'Delete')) : null))))))
    : emptyState('No teams', 'Add the teams that own agents, and the one that takes the issues nobody else does.');
  return h('div', { class: 'page', 'data-title': 'Teams' },
    pageHead({
      title: 'Findings',
      sub: "Teams own agents (as an agent's owner or sponsor), and take the issues about them that their owners and sponsors didn't acknowledge in time.",
      actions: [
        admin ? h('button', { type: 'button', class: 'btn btn--primary', 'data-focus-key': 'add-team', onclick: guarded(() => teamForm(null, chats)) }, icon('plus'), 'Add team') : null,
        refreshButton(),
      ],
    }),
    findingTabs('teams'),
    teams.length && !hasDefault ? callout('warning', 'alert-circle', h('span', {}, h('strong', {}, 'No default team: '),
      'issues about agents without a team of their own, and those that are about nothing else, go to nobody. Mark one team as the default.')) : null,
    card({ title: 'Teams', flush: Boolean(teams.length), body }));
}

async function teamForm(t, chats) {
  const editing = Boolean(t);
  const saved = await ask({
    title: editing ? `Edit team ${t.name}` : 'Add a team',
    text: 'Agents name it as their owner, a sponsor or their team, and blueprints as their agents\' team. Changes are recorded in the evidence ledger.',
    iconName: editing ? 'edit' : 'user', confirm: editing ? 'Save changes' : 'Add team', wide: true,
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'cx-platform', hint: NAME_HINT },
      { id: 'description', label: 'Description', type: 'textarea', value: t?.description || '' },
      {
        id: 'members', label: 'Members', type: 'textarea', value: (t?.members || []).join(', '), placeholder: 'alice@example.com, bob@example.com',
        hint: 'Email addresses or user names, separated by commas: they see the team\'s issues in AgentGov and acknowledge them.',
      },
      {
        id: 'emails', label: 'Email its issues to', value: (t?.emails || []).join(', '), placeholder: 'cx-platform@example.com',
        hint: "A list's or a shared mailbox's address, or people's own. Empty: its members' addresses. Needs a mail server (AGENTGOV_SMTP_URL).",
      },
      chats.length ? { type: 'section', label: 'Post its issues to' } : null,
      ...chats.map((d) => ({ id: `chat-${d.name}`, label: `${d.name} (${humanize(d.kind)})`, type: 'checkbox', value: (t?.destinations || []).includes(d.name) })),
      { id: 'default', label: 'The default team: it takes the issues that have no team of their own', type: 'checkbox', value: Boolean(t?.default) },
    ].filter(Boolean),
    extra: chats.length ? null : h('p', { class: 'hint' }, 'To post its issues in a Teams or Slack channel, add the channel as a destination on the Security operations page first.'),
    submit: (v) => {
      const body = {
        description: v.description, members: parseList(v.members), emails: parseList(v.emails),
        destinations: chats.filter((d) => v[`chat-${d.name}`]).map((d) => d.name), default: v.default,
      };
      if (editing) return api(`v1/teams/${encodeURIComponent(t.name)}`, { method: 'PATCH', body });
      return api('v1/teams', { method: 'POST', body: { name: v.name, ...body } });
    },
  });
  if (!saved) return;
  toast(editing ? `Saved team ${saved.name}.` : `Added team ${saved.name}.`);
  await refresh();
}

async function deleteTeam(t) {
  const done = await ask({
    title: `Delete team ${t.name}?`,
    text: 'Teams that blueprints or agents name cannot be deleted: name another team or person there first.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete team', busy: 'Deleting…',
    submit: () => api(`v1/teams/${encodeURIComponent(t.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted team ${t.name}.`);
  await refresh();
}

/* ---------------------------------------------------------------- policies */

async function renderPolicies() {
  const [blueprints, policies, agents, servers, providers] = await Promise.all([
    api('v1/blueprints'), api('v1/policies'), api('v1/agents'), api('v1/toolservers'), api('v1/models/providers'),
  ]);
  const usage = countBy(agents, (a) => a.blueprint || '');
  const exportBtn = h('button', { type: 'button', class: 'btn', 'data-focus-key': 'export-yaml' }, icon('download'), 'Export manifests');
  exportBtn.addEventListener('click', async () => {
    exportBtn.disabled = true;
    try {
      const blob = await saveDownload('v1/export', `agentgov-manifests-${fileStamp()}.yaml`);
      toast(`Exported features, identity issuers, blueprints, tool servers, model providers, policies and agents as YAML (${fmtBytes(blob.size)}).`);
    } catch (err) {
      toast(err.message, { tone: 'critical' });
    } finally {
      exportBtn.disabled = false;
    }
  });
  const admin = can('admin');
  const sectionAction = (label, focusKey, onclick) => (admin
    ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': focusKey, onclick: guarded(onclick) }, icon('plus'), label)
    : null);
  return h('div', { class: 'page' },
    pageHead({
      title: 'Policies',
      sub: 'Blueprints decide what each class of agent may call. Organisation Rego policies add rules on top of the built-in library, and OPA enforces both at the gateway.',
      actions: [
        admin ? h('button', { type: 'button', class: 'btn', 'data-focus-key': 'import-yaml', onclick: guarded(importManifests) }, icon('upload'), 'Import manifests') : null,
        exportBtn, refreshButton(),
      ],
    }),
    h('div', { class: 'policy-layout' },
      h('div', { class: 'stack' },
        h('section', { class: 'stack', 'aria-labelledby': 'bp-title' },
          h('div', { class: 'section-title' },
            h('div', {}, h('h2', { id: 'bp-title' }, 'Blueprints'), h('p', {}, 'IT-approved templates: permissions, risk tier, sponsor and review rules')),
            sectionAction('New blueprint', 'new-blueprint', () => blueprintFormFlow(null, servers))),
          blueprints.length
            ? h('div', { class: 'bp-grid' }, blueprints.map((b) => blueprintCard(b, usage[b.name] || 0, servers)))
            : h('section', { class: 'card' }, emptyState('No blueprints yet', admin ? 'Create one to give a class of agents its tools.' : 'An admin creates blueprints here, with the CLI or with a Blueprint manifest.'))),
        h('section', { class: 'stack', 'aria-labelledby': 'rego-title' },
          h('div', { class: 'section-title' },
            h('div', {}, h('h2', { id: 'rego-title' }, 'Organisation policies'),
              h('p', {}, 'Rego modules under agentgov.custom that can add denials, approval requirements and redactions')),
            sectionAction('Add policy', 'new-policy', () => policyFormFlow(null))),
          policies.length
            ? policies.map(policyCard)
            : h('section', { class: 'card' }, emptyState('No organisation policies', 'Only the built-in library (package agentgov.mcp) is enforced.')))),
      whatIfCard(agents, servers, providers)));
}

/** Create a blueprint (no `b`) or edit one. */
async function blueprintFormFlow(b, servers) {
  const editing = Boolean(b);
  const teams = await api('v1/teams').catch(() => []);
  const saved = await ask({
    title: editing ? `Edit blueprint ${b.name}` : 'New blueprint',
    text: editing
      ? 'Every agent on this blueprint gets the change as soon as OPA loads the updated policy bundle.'
      : 'A blueprint grants tools to every agent that uses it and sets their sponsor and review rules.',
    iconName: editing ? 'edit' : 'policies', confirm: editing ? 'Save changes' : 'Create blueprint',
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'customer-support', hint: NAME_HINT },
      { id: 'description', label: 'Description', type: 'textarea', value: b?.description || '' },
      {
        id: 'permissions', label: 'Tool grants', type: 'code', rows: 4, value: formatGrants(b?.permissions), placeholder: 'crm: search_customers, get_*',
        hint: `One server per line; tool names can use * wildcards, and * alone means every tool.${servers.length ? ` Registered servers: ${servers.map((ts) => ts.name).join(', ')}.` : ''}`,
      },
      { type: 'row', fields: [
        { id: 'risk_tier', label: 'Risk tier', type: 'select', value: b?.risk_tier || 'medium', options: RISK_TIERS.map((t) => ({ value: t, label: humanize(t) })) },
        { id: 'attestation_days', label: 'Review every (days)', type: 'number', min: 1, value: b ? (b.attestation_days ?? '') : '90', hint: 'Empty: no periodic review.' },
      ] },
      { id: 'require_sponsor', label: 'Require a sponsor before activation', type: 'checkbox', value: b ? b.require_sponsor : true },
      {
        id: 'require_workload_identity', label: 'Require a workload identity: no client secrets', type: 'checkbox', value: b ? b.require_workload_identity : false,
        hint: 'Its agents authenticate with an identity from an identity issuer (Access page) before they can be activated.',
      },
      { type: 'section', label: 'Models' },
      {
        id: 'model_access', label: 'Model access', type: 'code', rows: 2, value: formatModelAccess(b?.model_access), placeholder: 'openai: gpt-4o-mini, gpt-4.1*',
        hint: 'Models its agents may call through the gateway: one provider per line; model names can use * wildcards.',
      },
      { id: 'daily_token_budget', label: 'Daily token budget per agent', type: 'number', min: 0, value: b?.daily_token_budget ?? '', hint: 'Input and output tokens per UTC day. Empty: no budget.' },
      { type: 'section', label: 'Agent to agent' },
      {
        id: 'agent_access', label: 'Agents its agents may call', value: (b?.agent_access || []).join(', '), placeholder: 'billing-agent, kb-*', mono: true,
        hint: 'Over A2A, through the gateway: agent names separated by commas; names can use * wildcards. Empty: none.',
      },
      { type: 'section', label: 'People' },
      { id: 'acts_for', label: 'Its agents act for', type: 'select', value: b?.acts_for || 'either', options: Object.entries(ACTS_FOR).map(([value, label]) => ({ value, label })) },
      {
        id: 'people_groups', label: "People's groups", value: (b?.people_groups || []).join(', '), placeholder: 'support, /emea/sales', mono: true,
        hint: 'When its agents act for a person, the person must be in one of these groups. Empty: anyone.',
      },
      {
        id: 'approvals_by', label: 'Approval requests made for a person go to', type: 'select', value: b?.approvals_by || 'approvers', options: Object.entries(APPROVALS_BY).map(([value, label]) => ({ value, label })),
        hint: 'To the person while the approvals-by-person feature is on; administrators can always decide.',
      },
      {
        id: 'team', label: 'Team', type: 'select', value: b?.team || '',
        options: [{ value: '', label: 'The default team' }, ...teams.map((t) => ({ value: t.name, label: t.name }))],
        hint: 'Issues about its agents go to their owners, then their sponsors, then this team.',
      },
      { id: 'labels', label: 'Labels', value: formatLabels(b?.labels), placeholder: 'data=customer', mono: true },
    ].filter(Boolean),
    submit: (v) => {
      const days = v.attestation_days ? Number(v.attestation_days) : null;
      if (days !== null && !(Number.isInteger(days) && days > 0)) throw new Error('The review period must be a whole number of days, or empty.');
      const body = {
        description: v.description, permissions: parseGrants(v.permissions), risk_tier: v.risk_tier,
        attestation_days: days, require_sponsor: v.require_sponsor, labels: parseLabels(v.labels),
        require_workload_identity: v.require_workload_identity,
        model_access: parseModelAccess(v.model_access), daily_token_budget: parseBudget(v.daily_token_budget),
        agent_access: parseList(v.agent_access),
        acts_for: v.acts_for, people_groups: parseList(v.people_groups), approvals_by: v.approvals_by,
        team: v.team || null,
      };
      if (editing) return api(`v1/blueprints/${encodeURIComponent(b.name)}`, { method: 'PATCH', body });
      return api('v1/blueprints', { method: 'POST', body: { name: v.name, ...body } });
    },
  });
  if (!saved) return;
  toast(editing ? `Saved blueprint ${saved.name}.` : `Created blueprint ${saved.name}.`);
  await refresh();
}

async function deleteBlueprint(b) {
  const done = await ask({
    title: `Delete blueprint ${b.name}?`,
    text: 'Blueprints that agents still use cannot be deleted; move those agents to another blueprint first.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete blueprint', busy: 'Deleting…',
    submit: () => api(`v1/blueprints/${encodeURIComponent(b.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted blueprint ${b.name}.`);
  await refresh();
}

// Custom modules must declare `package agentgov.custom.<name>` (hyphens become underscores).
const policyPackage = (name) => `agentgov.custom.${(name || '<name>').replace(/-/g, '_')}`;
const POLICY_TEMPLATE = (name) => `# Rules here can add to deny, require_approval and redact. They see the same
# input as the built-in library; data.agentgov.context has helpers for the
# calling agent and tool server (see docs/policies.md).
package ${policyPackage(name)}

deny contains msg if {
\tinput.phase == "request"
\tinput.resource.name == "delete_everything"
\tmsg := "delete_everything is disabled by organisation policy"
}
`;

/** Add an organisation policy (no `p`) or replace one's source and settings. */
async function policyFormFlow(p) {
  const editing = Boolean(p);
  const saved = await ask({
    title: editing ? `Edit policy ${p.name}` : 'Add an organisation policy',
    text: 'The control plane compiles the module with the built-in library and evaluates it on sample calls before saving. Saved policies reach OPA with the next policy bundle.',
    iconName: editing ? 'edit' : 'policies', confirm: editing ? 'Save policy' : 'Add policy', busy: 'Checking…', wide: true,
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'prod-verified-only', hint: `${NAME_HINT} The module's package is agentgov.custom.<name>, with hyphens as underscores.` },
      { id: 'description', label: 'Description', value: p?.description || '' },
      { id: 'rego', label: 'Rego source', type: 'code', rows: 14, required: true, file: '.rego', value: p ? p.rego : POLICY_TEMPLATE('') },
      { id: 'enabled', label: 'Enabled', type: 'checkbox', value: p ? p.enabled : true, hint: 'Disabled policies are kept but not sent to OPA.' },
    ].filter(Boolean),
    onReady: (controls) => {
      if (editing) return;
      // Keep the template's package line in step with the name until the source is edited.
      const template = () => POLICY_TEMPLATE(controls.name.value.trim());
      let last = controls.rego.value;
      controls.name.addEventListener('input', () => {
        if (controls.rego.value !== last) return;
        controls.rego.value = template();
        last = controls.rego.value;
      });
    },
    submit: (v) => {
      const body = { description: v.description, rego: v.rego, enabled: v.enabled };
      if (editing) return api(`v1/policies/${encodeURIComponent(p.name)}`, { method: 'PUT', body });
      return api('v1/policies', { method: 'POST', body: { name: v.name, ...body } });
    },
  });
  if (!saved) return;
  toast(editing ? `Saved policy ${saved.name} (version ${saved.version}).` : `Added policy ${saved.name}.`);
  await refresh();
}

async function togglePolicy(p) {
  const enable = !p.enabled;
  const done = await ask({
    title: `${enable ? 'Enable' : 'Disable'} policy ${p.name}?`,
    text: enable
      ? 'The module is checked again, then OPA enforces it with the next policy bundle.'
      : 'OPA stops enforcing the module with the next policy bundle. Its source is kept.',
    tone: enable ? 'primary' : 'danger', iconName: enable ? 'check' : 'minus', confirm: enable ? 'Enable policy' : 'Disable policy',
    busy: enable ? 'Checking…' : 'Saving…',
    submit: () => api(`v1/policies/${encodeURIComponent(p.name)}`, { method: 'PUT', body: { enabled: enable } }),
  });
  if (!done) return;
  toast(`${enable ? 'Enabled' : 'Disabled'} policy ${p.name}.`);
  await refresh();
}

async function deletePolicy(p) {
  const done = await ask({
    title: `Delete policy ${p.name}?`,
    text: 'OPA stops enforcing it with the next policy bundle, and its source is removed. Export the manifests first if you may want it back.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete policy', busy: 'Deleting…',
    submit: () => api(`v1/policies/${encodeURIComponent(p.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted policy ${p.name}.`);
  await refresh();
}

/** Apply YAML manifests: what `agentgov apply -f` sends, from the browser. */
async function importManifests() {
  const result = await ask({
    title: 'Import manifests',
    text: 'Apply Blueprint, ToolServer, Policy and Agent manifests, as exported from this page or written for `agentgov apply`. Applying is idempotent: unchanged resources are left alone. Policies need their Rego inline under spec.rego.',
    iconName: 'upload', confirm: 'Apply manifests', busy: 'Applying…', wide: true,
    fields: [{ id: 'yaml', label: 'Manifests (YAML)', type: 'code', rows: 14, required: true, file: '.yaml,.yml', placeholder: 'apiVersion: agentgov/v1alpha1\nkind: Blueprint\nmetadata:\n  name: customer-support\nspec:\n  …' }],
    submit: (v) => api('v1/apply', { method: 'POST', text: v.yaml, contentType: 'application/yaml' }),
  });
  if (!result?.results) return;
  const changed = result.results.filter((r) => r.action !== 'unchanged');
  await ask({
    title: changed.length ? `Applied ${plural(changed.length, 'change')}` : 'Nothing to change',
    iconName: 'check-circle', confirm: 'Done', cancel: null,
    extra: h('ul', { class: 'apply-results', role: 'list' }, result.results.map((r) => h('li', {},
      h('code', {}, `${r.kind.toLowerCase()}/${r.name}`), plainChip(humanize(r.action), { tone: r.action === 'unchanged' ? null : 'good' })))),
  });
  refreshBadges();
  await refresh();
}

function permissionList(grants) {
  if (!grants?.length) return h('p', { class: 'muted small' }, 'No tools granted.');
  return h('ul', { class: 'perm-list', role: 'list' }, grants.map((g) => h('li', {},
    h('span', { class: 'perm-server' }, g.server),
    h('div', { class: 'chip-row' }, g.tools.map((t) => plainChip(t, { mono: true }))))));
}

// Who a blueprint's agents act for (acting-for-people), and who decides approvals made for a person.
const ACTS_FOR = {
  either: 'People, or itself',
  people: 'Only people: every call is for a person',
  itself: 'Only itself: never for a person',
};
const APPROVALS_BY = { approvers: 'Approvers', person: 'The person the agent acted for' };

function actsFor(x) {
  const groups = x.people_groups || [];
  const who = { either: 'People or itself', people: 'People only', itself: 'Itself only' }[x.acts_for] || humanize(x.acts_for || 'either');
  return x.acts_for !== 'itself' && groups.length
    ? h('span', {}, `${who}; people in `, h('span', { class: 'chip-row', style: 'display:inline-flex' }, groups.map((g) => plainChip(g, { mono: true }))))
    : who;
}

function blueprintCard(b, used, servers) {
  const labels = Object.entries(b.labels || {});
  return card({
    title: b.name, level: 'h3', id: `bp-${b.id}`,
    sub: b.description,
    actions: [plainChip(`${humanize(b.risk_tier)} risk tier`, { tone: toneOf('risk', b.risk_tier === 'minimal' ? 'low' : b.risk_tier), iconName: statusMeta('risk', b.risk_tier === 'minimal' ? 'low' : b.risk_tier)[1] })],
    foot: can('admin') ? h('div', { class: 'btn-row' },
      h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `bp-edit-${b.name}`, onclick: guarded(() => blueprintFormFlow(b, servers)) }, icon('edit'), 'Edit'),
      h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', 'data-focus-key': `bp-delete-${b.name}`, onclick: () => deleteBlueprint(b) }, icon('trash'), 'Delete')) : null,
    body: [
      facts([
        ['Used by', used ? h('a', { href: '#/agents' }, plural(used, 'agent')) : h('span', { class: 'muted' }, 'No agents')],
        ['Sponsor', b.require_sponsor ? 'Required before activation' : 'Not required'],
        b.require_workload_identity ? ['Authentication', 'A workload identity, never a client secret'] : null,
        ['Attestation', b.attestation_days ? `Every ${plural(b.attestation_days, 'day')}` : 'Not required'],
        ['Acts for', actsFor(b)],
        b.approvals_by === 'person' ? ['Approvals', APPROVALS_BY.person] : null,
        (b.agent_access || []).length ? ['May call agents', h('div', { class: 'chip-row' }, b.agent_access.map((x) => plainChip(x, { mono: true })))] : null,
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
    foot: can('admin') ? h('div', { class: 'btn-row' },
      h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `policy-edit-${p.name}`, onclick: guarded(() => policyFormFlow(p)) }, icon('edit'), 'Edit'),
      h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `policy-toggle-${p.name}`, onclick: () => togglePolicy(p) }, icon(p.enabled ? 'minus' : 'check'), p.enabled ? 'Disable' : 'Enable'),
      h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', 'data-focus-key': `policy-delete-${p.name}`, onclick: () => deletePolicy(p) }, icon('trash'), 'Delete')) : null,
    body: [
      facts([['Package', h('code', {}, p.package)], ['Updated', timeEl(p.updated_at)]]),
      h('details', { class: 'disclosure' }, h('summary', {}, icon('chevron'), 'View Rego source'),
        h('pre', { class: 'kv-pre rego', tabindex: '0' }, p.rego)),
    ],
  });
}

function whatIfCard(agents, servers, providers = []) {
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

  // A tool call: a tool server and one of its tools.
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

  // A model call: a model provider and a model.
  const providerInput = h('input', { type: 'text', id: 'wi-provider', list: 'wi-provider-list', autocomplete: 'off', spellcheck: 'false' });
  const modelInput = h('input', { type: 'text', id: 'wi-model', list: 'wi-model-list', autocomplete: 'off', spellcheck: 'false' });
  const providerList = h('datalist', { id: 'wi-provider-list' }, providers.map((p) => h('option', { value: p.name })));
  const modelList = h('datalist', { id: 'wi-model-list' });
  providerInput.value = (providers.find((p) => p.status === 'approved') || providers[0])?.name || '';
  // The models the chosen agent may call there, where they are names rather than globs.
  const grantedModels = () => {
    const agent = agents.find((a) => a.id === agentSel.value);
    return (agent?.effective_model_access || [])
      .filter((g) => g.provider === providerInput.value.trim())
      .flatMap((g) => g.models).filter((m) => !/[*?[]/.test(m));
  };
  const fillModels = () => modelList.replaceChildren(...grantedModels().map((m) => h('option', { value: m })));
  fillModels();
  modelInput.value = grantedModels()[0] || '';
  providerInput.addEventListener('change', fillModels);
  agentSel.addEventListener('change', fillModels);

  // A call to another agent over A2A: the agent called.
  const targetInput = h('input', { type: 'text', id: 'wi-target', list: 'wi-target-list', autocomplete: 'off', spellcheck: 'false' });
  const serving = agents.filter((a) => a.a2a_url && a.status !== 'deleted');
  const targetList = h('datalist', { id: 'wi-target-list' }, serving.map((a) => h('option', { value: a.name })));
  targetInput.value = serving[0]?.name || '';

  // The person the agent acts for, if any.
  const userInput = h('input', { type: 'text', id: 'wi-user', placeholder: 'No one: the agent alone', autocomplete: 'off', spellcheck: 'false' });
  const groupsInput = h('input', { type: 'text', id: 'wi-groups', placeholder: 'support, /emea/sales', autocomplete: 'off', spellcheck: 'false' });
  const kindTool = h('input', { type: 'radio', name: 'wi-kind', id: 'wi-kind-tool', value: 'tool', checked: true });
  const kindModel = h('input', { type: 'radio', name: 'wi-kind', id: 'wi-kind-model', value: 'model' });
  const kindAgent = h('input', { type: 'radio', name: 'wi-kind', id: 'wi-kind-agent', value: 'agent' });
  const phaseRequest = h('input', { type: 'radio', name: 'wi-phase', id: 'wi-phase-request', value: 'request', checked: true });
  const phaseResponse = h('input', { type: 'radio', name: 'wi-phase', id: 'wi-phase-response', value: 'response' });
  const pii = h('input', { type: 'checkbox', id: 'wi-pii', value: 'pii' });
  const secret = h('input', { type: 'checkbox', id: 'wi-secret', value: 'secret' });
  const injection = h('input', { type: 'checkbox', id: 'wi-injection' });
  const jailbreak = h('input', { type: 'checkbox', id: 'wi-jailbreak' });
  const toolCalls = h('input', { type: 'checkbox', id: 'wi-tool-calls' });
  const result = h('div', { class: 'stack', style: 'gap:12px', 'aria-live': 'polite' });
  const submit = h('button', { type: 'submit', class: 'btn btn--primary' }, icon('play'), 'Evaluate');

  const requestLabel = h('span', {});
  const responseLabel = h('span', {});
  const injectionLabel = h('span', {});
  const toolFields = h('div', { class: 'form-row' },
    h('div', { class: 'field' }, h('label', { for: 'wi-server' }, 'Tool server'), serverInput, serverList),
    h('div', { class: 'field' }, h('label', { for: 'wi-tool' }, 'Tool'), toolInput, toolList));
  const modelFields = h('div', { class: 'form-row' },
    h('div', { class: 'field' }, h('label', { for: 'wi-provider' }, 'Model provider'), providerInput, providerList),
    h('div', { class: 'field' }, h('label', { for: 'wi-model' }, 'Model'), modelInput, modelList));
  const agentFields = h('div', { class: 'field' }, h('label', { for: 'wi-target' }, 'Agent called'), targetInput, targetList,
    h('p', { class: 'hint' }, 'It calls the agent over A2A, through the gateway (SendMessage).'));
  const modelOnly = [
    h('label', { class: 'check', for: 'wi-jailbreak' }, jailbreak, 'A jailbreak in the prompt'),
    h('label', { class: 'check', for: 'wi-tool-calls' }, toolCalls, 'The conversation holds tool calls'),
  ];
  const injectionCheck = h('label', { class: 'check', for: 'wi-injection' }, injection, injectionLabel);
  const phaseField = h('fieldset', { class: 'field' }, h('legend', { class: 'field-label' }, 'Phase'),
    h('div', { class: 'radio-row' },
      h('label', { class: 'check', for: 'wi-phase-request' }, phaseRequest, requestLabel),
      h('label', { class: 'check', for: 'wi-phase-response' }, phaseResponse, responseLabel)));
  const kind = () => (kindModel.checked ? 'model' : kindAgent.checked ? 'agent' : 'tool');
  const isModel = () => kind() === 'model';
  const showKind = () => {
    const model = isModel();
    const agent = kind() === 'agent';
    toolFields.hidden = model || agent;
    modelFields.hidden = !model;
    agentFields.hidden = !agent;
    // AgentGov checks the requests agents send each other, not their answers.
    phaseField.hidden = agent;
    injectionCheck.hidden = agent;
    modelOnly.forEach((el) => { el.hidden = !model; });
    requestLabel.textContent = model ? 'Request (the prompt)' : 'Request (the tool call)';
    responseLabel.textContent = model ? 'Response (the answer)' : 'Response (the tool result)';
    injectionLabel.textContent = model ? 'Prompt injection in a tool result in the conversation' : 'Prompt injection in the result';
  };
  showKind();
  [kindTool, kindModel, kindAgent].forEach((r) => r.addEventListener('change', showKind));

  function buildInput() {
    const agentId = agentSel.value;
    const agent = agents.find((a) => a.id === agentId);
    const categories = [pii, secret].filter((c) => c.checked).map((c) => c.value);
    const phase = phaseResponse.checked ? 'response' : 'request';
    const caller = agentId === '__unregistered'
      ? { client_id: 'agent-not-registered' }
      : { agent_id: agent?.id, client_id: agent?.identity?.client_id || undefined };
    const detections = { categories, prompt_injection: injection.checked, injection_score: injection.checked ? 0.95 : 0 };
    const name = userInput.value.trim();
    const user = name ? { user: { id: name, username: name, groups: parseList(groupsInput.value), roles: [], via: 'exchange' } } : {};
    if (kind() === 'agent') {
      return {
        path: 'agentgov/a2a/decision',
        input: {
          kind: 'a2a', method: 'SendMessage', agent: caller, ...user, target: targetInput.value.trim(),
          // The person heads the chain of a call made for them.
          chain: name ? [{ type: 'person', id: name, name }] : [], detections: { categories },
        },
      };
    }
    if (isModel()) {
      return {
        path: 'agentgov/models/decision',
        input: {
          kind: 'model', phase, agent: caller, ...user, provider: providerInput.value.trim(), model: modelInput.value.trim(),
          detections: { ...detections, jailbreak: jailbreak.checked }, tool_calls: toolCalls.checked,
        },
      };
    }
    return {
      path: 'agentgov/mcp/decision',
      input: { phase, method: 'tools/call', agent: caller, ...user, resource: { server: serverInput.value.trim(), name: toolInput.value.trim() }, detections },
    };
  }

  async function evaluate(example) {
    const { path, input } = buildInput();
    const missing = {
      agent: () => !input.target,
      model: () => !input.provider || !input.model,
      tool: () => !input.resource.server || !input.resource.name,
    }[kind()]();
    if (missing) {
      const what = { agent: 'the agent it calls', model: 'a model provider and a model', tool: 'a tool server and a tool' }[kind()];
      result.replaceChildren(callout('warning', 'alert-circle', `Choose ${what} to evaluate.`));
      return;
    }
    submit.disabled = true;
    try {
      const res = await api('v1/policies/evaluate', { method: 'POST', body: { path, input } });
      fill(result, whatIfResult(res, input, example));
    } catch (err) {
      result.replaceChildren(callout('critical', 'alert-circle', h('span', {}, h('strong', {}, "Couldn't evaluate. "), err.message)));
    } finally {
      submit.disabled = false;
    }
  }

  const form = h('form', { class: 'whatif-form', novalidate: true },
    h('fieldset', { class: 'field' }, h('legend', { class: 'field-label' }, 'Call'),
      h('div', { class: 'radio-row' },
        h('label', { class: 'check', for: 'wi-kind-tool' }, kindTool, 'A tool call'),
        h('label', { class: 'check', for: 'wi-kind-model' }, kindModel, 'A model call'),
        h('label', { class: 'check', for: 'wi-kind-agent' }, kindAgent, 'A call to another agent'))),
    h('div', { class: 'field' }, h('label', { for: 'wi-agent' }, 'Agent'), agentSel),
    h('div', { class: 'form-row' },
      h('div', { class: 'field' }, h('label', { for: 'wi-user' }, 'On behalf of'), userInput),
      h('div', { class: 'field' }, h('label', { for: 'wi-groups' }, 'Their groups'), groupsInput)),
    toolFields, modelFields, agentFields,
    phaseField,
    h('fieldset', { class: 'field' }, h('legend', { class: 'field-label' }, 'Detections ', h('span', { class: 'muted' }, '(what Presidio and the detectors found)')),
      h('label', { class: 'check', for: 'wi-pii' }, pii, 'Personal data (pii)'),
      h('label', { class: 'check', for: 'wi-secret' }, secret, 'Credentials (secret)'),
      injectionCheck,
      ...modelOnly),
    h('div', { class: 'btn-row' }, submit));
  form.addEventListener('submit', (e) => { e.preventDefault(); evaluate(false); });
  if (agents.length || servers.length) evaluate(true);
  else result.replaceChildren(h('p', { class: 'muted small' }, 'Register an agent and a tool server to try a scenario.'));

  return h('section', { class: 'card whatif', 'aria-labelledby': 'whatif-title' },
    h('div', { class: 'card-head' }, h('div', { class: 'card-head-text' },
      h('h2', { id: 'whatif-title' }, 'What if'),
      h('p', { class: 'card-sub' }, 'Ask the live OPA what it would decide for a tool call, a model call or a call to another agent. Nothing is recorded.'))),
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
    (r.monitored || []).length
      ? h('div', { class: 'stack', style: 'gap:6px' }, h('span', { class: 'field-label' }, 'Monitored: would have been stopped'),
        h('ul', { class: 'reasons', role: 'list' }, r.monitored.map((m) => h('li', {}, icon('eye'), h('span', {}, m)))))
      : null,
    facts([
      input.kind === 'a2a' ? null : ['Redact', (r.redact || []).length ? h('div', { class: 'chip-row' }, r.redact.map((c) => plainChip(c, { mono: true }))) : 'Nothing'],
      ['Agent seen as', r.agent ? [r.agent.name, ` · ${r.agent.status} · ${r.agent.risk_level} risk`] : h('span', { class: 'muted' }, 'Not a registered agent')],
      input.kind === 'a2a' ? ['Agent called', r.target ? `${r.target.name} · ${r.target.status}` : h('span', { class: 'muted' }, 'Not a registered agent')] : null,
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
function traceLink(e) {
  return h('a', { class: 'trace-link', href: e.trace_url, target: '_blank', rel: 'noopener noreferrer', title: `Trace ${e.trace_id}` },
    'Open trace', icon('external'), h('span', { class: 'sr-only' }, ' (opens in a new tab)'));
}

// Who handed the work down, from the person at its head to the agent called.
function chainView(chain) {
  return h('span', { class: 'break' }, chain.flatMap((link, i) => [
    i ? [h('span', { class: 'muted', 'aria-hidden': 'true' }, ' › '), h('span', { class: 'sr-only' }, ', then ')] : null,
    link.type === 'person' ? personLink(link.name)
      : String(link.id || '').startsWith('agt_') && !isPerson() ? agentLink(link.id, link.name) : link.name,
  ]));
}

function ledgerDetail(e) {
  const chain = e.details?.chain || [];
  return h('div', { class: 'stack', style: 'gap:10px; padding: 4px 0 6px' },
    facts([
      ['Event ID', h('code', {}, e.id)],
      ['Time', timeEl(e.ts, { absolute: true })],
      ['Severity', humanize(e.severity)],
      ['Action', e.action ? h('code', {}, e.action) : null],
      e.on_behalf_of ? ['On behalf of', personLink(e.on_behalf_of)] : null,
      chain.length ? ['Chain', chainView(chain)] : null,
      e.trace_id ? ['Trace', h('span', {}, h('code', {}, e.trace_id), e.trace_url ? [' ', traceLink(e)] : null)] : null,
      ['Hash', h('code', { class: 'hash break' }, e.hash)],
      ['Previous hash', h('code', { class: 'hash break' }, e.prev_hash)],
    ]),
    Object.keys(e.details || {}).length ? jsonBlock(e.details) : null);
}

const clockFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
const shortDayFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });

// What agents did for a person: the ledger, filtered to them.
function personLink(name) {
  return h('a', { href: `#/ledger?${new URLSearchParams({ user: name })}`, title: `What agents did for ${name}` }, name);
}

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
      e.resource ? h('div', { class: 'cell-sub' }, h('code', {}, e.resource), e.trace_url ? [' · ', traceLink(e)] : null) : null,
      compact && e.reason ? h('div', { class: 'cell-sub clamp-2', title: e.reason }, e.reason) : null);
    const row = h('tr', {},
      h('td', { 'data-label': 'Seq', class: 'nowrap' }, toggle),
      h('td', { 'data-label': 'Time', class: 'nowrap' }, ledgerTime(e.ts)),
      event,
      compact ? null : h('td', { 'data-label': 'Agent', class: 'break col-agent' },
        e.agent_name ? agentLink(e.agent_id, e.agent_name) : null,
        actorIsAgent ? null : h('div', { class: e.agent_name ? 'cell-sub nowrap' : null }, e.agent_name ? `by ${e.actor}` : e.actor),
        e.on_behalf_of ? h('div', { class: 'cell-sub nowrap' }, 'for ', personLink(e.on_behalf_of)) : null),
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
  const state = { agent: params.get('agent') || '', user: params.get('user') || '', type: params.get('type') || '', decision: params.get('decision') || '' };
  const agents = await api('v1/agents?include_deleted=true').catch(() => []);
  const query = (before) => {
    const p = new URLSearchParams({ limit: String(PAGE_SIZE) });
    if (state.agent) p.set('agent', state.agent);
    if (state.user) p.set('user', state.user);
    if (state.type) p.set('type', state.type);
    if (state.decision) p.set('decision', state.decision);
    if (before) p.set('before_seq', String(before));
    return api(`v1/ledger?${p}`);
  };

  const agentInput = h('input', { type: 'text', id: 'ledger-agent', list: 'ledger-agent-list', value: state.agent, placeholder: 'Any agent', autocomplete: 'off', spellcheck: 'false', 'data-focus-key': 'ledger-agent' });
  const agentList = h('datalist', { id: 'ledger-agent-list' }, agents.map((a) => h('option', { value: a.name })));
  const userInput = h('input', { type: 'text', id: 'ledger-user', value: state.user, placeholder: 'Anyone', autocomplete: 'off', spellcheck: 'false', 'data-focus-key': 'ledger-user' });
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
  userInput.addEventListener('change', () => { state.user = userInput.value.trim(); reload(); });
  typeSel.addEventListener('change', () => { state.type = typeSel.value; reload(); });
  decisionSel.addEventListener('change', () => { state.decision = decisionSel.value; reload(); });
  const clearBtn = h('button', {
    type: 'button', class: 'btn btn--ghost', 'data-focus-key': 'ledger-clear',
    onclick: () => {
      Object.assign(state, { agent: '', user: '', type: '', decision: '' });
      agentInput.value = '';
      userInput.value = '';
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
      h('div', { class: 'field' }, h('label', { for: 'ledger-user' }, 'On behalf of'), userInput),
      h('div', { class: 'field' }, h('label', { for: 'ledger-type' }, 'Event type'), typeSel),
      h('div', { class: 'field' }, h('label', { for: 'ledger-decision' }, 'Decision'), decisionSel),
      h('div', { class: 'field', style: 'flex:0 0 auto; align-self:flex-end' }, clearBtn),
      countEl),
    h('section', { class: 'card', 'aria-label': 'Ledger entries' }, tableHost));
}

/* ------------------------------------------------------------------ access */

const KEY_ROLES = [
  ['auditor', 'Auditor: reads everything, including the ledger, and changes nothing'],
  ['approver', 'Approver: reads everything and decides approval requests and findings'],
  ['secops', "Security operations: the security team's SIEM or SOAR. Reads everything, and does what the hand-off to security operations allows"],
  ['registrar', 'Registrar: registers agents and tool servers for review (CI pipelines, developers)'],
  ['admin', 'Admin: everything'],
  ['service', 'Service: internal components such as OPA and the governance processor'],
];

async function renderAccess() {
  const [view, keys, issuers, features] = await Promise.all([
    api('v1/access'), api('v1/apikeys'), api('v1/identity-issuers'), featureModes().catch(() => ({})),
  ]);
  return h('div', { class: 'page' },
    pageHead({
      title: 'Access',
      sub: 'Who and what can use AgentGov: people who sign in with single sign-on, API keys for the CLI, CI pipelines and other automation, and the identity issuers whose tokens agents authenticate with instead of client secrets.',
      actions: [refreshButton()],
    }),
    view.bootstrap_token ? callout('neutral', 'key', h('span', {}, h('strong', {}, 'The bootstrap admin token is set. '),
      'Anyone who has it is an admin. Keep it for setup and emergencies, and give people and automation their own roles.')) : null,
    signInsCard(view),
    apiKeysCard(keys),
    features['workload-identity'] === 'off' ? callout('warning', 'power', h('span', {},
      h('strong', {}, "Agents' own identities are off: "), 'no issuer is trusted, so agents with a workload identity can\'t authenticate. ',
      h('a', { href: '#/features' }, 'Features'), '.')) : null,
    issuersCard(issuers));
}

/* ------------------------------------------------- agents' own identities */

// Identity issuers by kind: name, a subject its tokens carry, and its issuer.
const ISSUER_KINDS = {
  kubernetes: ['Kubernetes', 'system:serviceaccount:agents:support-bot', 'https://kubernetes.default.svc.cluster.local'],
  spiffe: ['SPIFFE', 'spiffe://example.org/ns/agents/sa/support-bot', 'spiffe://example.org'],
  oidc: ['OpenID Connect', '6f1c5e1a-…', 'https://login.microsoftonline.com/<tenant>/v2.0'],
};
const ISSUER_KEYS_HINT = {
  kubernetes: "The cluster's issuer discovery URL, when Keycloak can't read its keys from the issuer itself. Empty: Keycloak's own cluster.",
  spiffe: 'The SPIFFE bundle endpoint (from SPIRE, say) with the trust domain\'s keys.',
  oidc: "The JWKS URL. Empty: found from the issuer's discovery document.",
};

const issuerKind = (kind) => (ISSUER_KINDS[kind] || [kind])[0];

// Microsoft Entra ID, whose app-only tokens name an agent identity by its object ID
// (v2 tokens' issuer, or v1's).
const isEntra = (issuer) => /^https:\/\/(login\.microsoftonline\.(com|us)|sts\.windows\.net)\//.test(issuer?.issuer || '');

function issuerSync(i) {
  if (i.sync?.error) {
    return [plainChip('Out of sync', { tone: 'critical', iconName: 'octagon', title: i.sync.error }),
      h('div', { class: 'cell-sub break' }, i.sync.error)];
  }
  if (i.sync?.synced_at) return [plainChip('Synced', { tone: 'good', iconName: 'check-circle' }), h('div', { class: 'cell-sub' }, timeEl(i.sync.synced_at))];
  return h('span', { class: 'muted', title: 'Keycloak gets it within seconds when the control plane is connected to it' }, 'Not yet');
}

function issuersCard(issuers) {
  const body = issuers.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
    h('caption', { class: 'sr-only' }, 'Identity issuers'),
    h('thead', {}, h('tr', {}, ['Issuer', 'Status', 'Agents', 'In Keycloak', ''].map((t) => h('th', { scope: 'col', class: t === 'Agents' ? 'num' : null }, t || h('span', { class: 'sr-only' }, 'Actions'))))),
    h('tbody', {}, issuers.map((i) => h('tr', { 'data-issuer': i.name },
      h('td', { 'data-label': 'Issuer', class: 'break' }, h('span', { class: 'cell-title' }, i.name),
        h('div', { class: 'cell-sub' }, `${issuerKind(i.kind)}: `, h('code', {}, i.issuer)),
        i.audience ? h('div', { class: 'cell-sub' }, 'Audience: ', h('code', {}, i.audience)) : null,
        i.description ? h('div', { class: 'cell-sub' }, i.description) : null),
      h('td', { 'data-label': 'Status' }, chip('server', i.status)),
      h('td', { 'data-label': 'Agents', class: 'num' }, fmt(i.agents || 0)),
      h('td', { 'data-label': 'In Keycloak' }, issuerSync(i)),
      h('td', { 'data-label': '' }, can('contain') ? h('div', { class: 'btn-row' },
        can('admin') ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `issuer-edit-${i.name}`, onclick: guarded(() => issuerForm(i)) }, icon('edit'), 'Edit') : null,
        h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `issuer-block-${i.name}`, onclick: guarded(() => blockIssuer(i)) },
          icon(i.status === 'blocked' ? 'undo' : 'ban'), i.status === 'blocked' ? 'Unblock' : 'Block'),
        can('admin') ? h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', 'data-focus-key': `issuer-delete-${i.name}`, onclick: guarded(() => deleteIssuer(i)) }, icon('trash'), 'Delete') : null) : null))))))
    : emptyState('No identity issuers', 'Add one, and agents can authenticate with an identity they already have, such as a Kubernetes service account, a SPIFFE ID or a Microsoft Entra Agent ID, instead of a client secret.');
  return card({
    title: 'Agent identity issuers',
    sub: "Agents that run where they already have an identity authenticate with their issuer's tokens: there's no secret to store, leak or rotate. Blocking an issuer stops all of its agents authenticating.",
    actions: can('admin') ? [h('button', { type: 'button', class: 'btn btn--sm btn--primary', 'data-focus-key': 'add-issuer', onclick: guarded(() => issuerForm(null)) }, icon('plus'), 'Add issuer')] : null,
    flush: issuers.length > 0,
    body,
  });
}

async function issuerForm(i) {
  const editing = Boolean(i);
  const oidcOnly = (field) => !editing || i.kind === 'oidc' ? field : null;
  const saved = await ask({
    title: editing ? `Edit ${i.name}` : 'Add an identity issuer',
    text: editing
      ? `A ${issuerKind(i.kind)} issuer. Keycloak gets the change within seconds; it is recorded in the evidence ledger.`
      : "AgentGov makes it an identity provider in Keycloak. Each agent then names its subject there, and authenticates with the issuer's token for that subject.",
    iconName: editing ? 'edit' : 'key', confirm: editing ? 'Save changes' : 'Add issuer', wide: true,
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'prod-cluster', hint: NAME_HINT },
      editing ? null : {
        id: 'kind', label: 'Kind', type: 'select', value: 'kubernetes', options: [
          { value: 'kubernetes', label: "Kubernetes: its pods' service account tokens" },
          { value: 'spiffe', label: 'SPIFFE: JWT-SVIDs, from SPIRE say' },
          { value: 'oidc', label: 'OpenID Connect: Microsoft Entra ID (Agent ID), Okta, AWS, Google, GitHub Actions…' },
        ],
      },
      {
        id: 'issuer', label: 'Issuer', required: true, mono: true, value: i?.issuer || '', placeholder: ISSUER_KINDS[i?.kind || 'kubernetes'][2],
        hint: 'As its tokens name it (their iss claim). For SPIFFE, the trust domain.',
      },
      { id: 'keys_url', label: 'Keys URL', mono: true, value: i?.keys_url || '', hint: ISSUER_KEYS_HINT[i?.kind || 'kubernetes'] },
      oidcOnly({
        id: 'audience', label: 'Audience', mono: true, value: i?.audience || '', placeholder: 'api://agentgov',
        hint: "Only when its tokens can't carry Keycloak's realm URL as their audience: the one they carry. Microsoft Entra ID's name an app, such as api://agentgov.",
      }),
      oidcOnly({ id: 'allow_reuse', label: 'A token may authenticate more than once', type: 'checkbox', value: i?.allow_reuse || false, hint: "Otherwise Keycloak takes each token once, so a stolen one is worth less. Tokens without a jti claim, such as Microsoft Entra ID's, need it." }),
      { id: 'description', label: 'Description', type: 'textarea', value: i?.description || '' },
      { id: 'labels', label: 'Labels', value: formatLabels(i?.labels), placeholder: 'env=prod', mono: true },
    ].filter(Boolean),
    onReady: (controls) => {
      if (editing) return;
      const field = (id) => controls[id]?.closest('.field');
      const show = () => {
        const kind = controls.kind.value;
        controls.issuer.placeholder = ISSUER_KINDS[kind][2];
        const hint = field('keys_url')?.querySelector('.hint');
        if (hint) hint.textContent = ISSUER_KEYS_HINT[kind];
        for (const id of ['audience', 'allow_reuse']) if (field(id)) field(id).hidden = kind !== 'oidc';
      };
      controls.kind.addEventListener('change', show);
      show();
    },
    submit: (v) => {
      const kind = editing ? i.kind : v.kind;
      const body = {
        issuer: v.issuer, keys_url: orNull(v.keys_url), description: v.description, labels: parseLabels(v.labels),
        ...(kind === 'oidc' ? { audience: orNull(v.audience), allow_reuse: v.allow_reuse } : {}),
      };
      if (editing) return api(`v1/identity-issuers/${encodeURIComponent(i.name)}`, { method: 'PATCH', body });
      return api('v1/identity-issuers', { method: 'POST', body: { name: v.name, kind, ...body } });
    },
  });
  if (!saved) return;
  toast(editing ? `Saved ${saved.name}.` : `Added ${saved.name}. Give agents a workload identity from it on their edit form.`);
  await refresh();
}

async function blockIssuer(i) {
  const block = i.status !== 'blocked';
  const done = await ask({
    title: block ? `Block ${i.name}?` : `Unblock ${i.name}?`,
    text: block
      ? `Keycloak stops taking its tokens within seconds, so ${plural(i.agents || 0, 'agent')} can't get a new access token; the ones they have expire within minutes.`
      : 'Its agents can authenticate with its tokens again.',
    tone: block ? 'danger' : 'primary', iconName: block ? 'ban' : 'undo', confirm: block ? 'Block' : 'Unblock',
    submit: () => api(`v1/identity-issuers/${encodeURIComponent(i.name)}/${block ? 'block' : 'unblock'}`, { method: 'POST' }),
  });
  if (!done) return;
  toast(block ? `Blocked ${i.name}.` : `Unblocked ${i.name}.`);
  await refresh();
}

async function deleteIssuer(i) {
  const done = await ask({
    title: `Delete ${i.name}?`,
    text: i.agents
      ? `${plural(i.agents, 'agent')} authenticate with it. Give them another identity, or a client secret, first.`
      : 'Its identity provider goes from Keycloak too.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete issuer', busy: 'Deleting…',
    submit: () => api(`v1/identity-issuers/${encodeURIComponent(i.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted ${i.name}.`);
  await refresh();
}

function signInsCard(view) {
  const people = view.people || [];
  const signedIn = people.filter((p) => p.status === 'signed_in').length;
  let body;
  if (!people.length) {
    body = view.sso_enabled
      ? emptyState('Nobody has signed in yet', 'People appear here after their first sign-in with single sign-on.')
      : emptyState('Single sign-on is not set up', 'People sign in with API keys until an identity provider is connected.');
  } else {
    body = h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
      h('caption', { class: 'sr-only' }, 'People'),
      h('thead', {}, h('tr', {}, ['Person', 'Roles', 'Status', 'Last sign-in', 'Sign-ins', ''].map((t) => h('th', { scope: 'col' }, t || h('span', { class: 'sr-only' }, 'Actions'))))),
      h('tbody', {}, people.map((person) => h('tr', {},
        h('td', { 'data-label': 'Person', class: 'break' }, h('span', { class: 'cell-title' }, person.name),
          h('div', { class: 'cell-sub', title: 'Subject at the identity provider' }, person.subject)),
        h('td', { 'data-label': 'Roles' }, person.roles.length
          ? h('div', { class: 'chip-row' }, person.roles.map((r) => plainChip(humanize(r))))
          : h('span', { class: 'muted' }, 'None')),
        h('td', { 'data-label': 'Status' }, chip('person', person.status, { title: person.status === 'refused' ? 'Refused at the last attempt: no AgentGov role' : null }),
          person.status === 'signed_in'
            ? h('div', { class: 'cell-sub' }, `${plural(person.active_sessions, 'session')} until `, timeEl(person.session_expires_at, { absolute: true }))
            : person.status === 'refused' ? h('div', { class: 'cell-sub' }, 'tried ', timeEl(person.last_refused)) : null),
        h('td', { 'data-label': 'Last sign-in', class: 'nowrap' }, timeEl(person.last_sign_in, { empty: 'Never' })),
        h('td', { 'data-label': 'Sign-ins', class: 'num' }, fmt(person.sign_ins)),
        h('td', { 'data-label': '' }, can('admin') && person.active_sessions
          ? h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', 'data-focus-key': `sign-out-${person.subject}`, onclick: () => signPersonOut(person) }, icon('signout'), 'Sign out')
          : null))))));
  }
  return card({
    title: 'People',
    sub: `${plural(signedIn, 'person', 'people')} signed in now. Roles come from the identity provider at each sign-in: to take someone's access away, remove their role there, then sign them out here.`,
    flush: people.length > 0,
    body,
  });
}

async function signPersonOut(person) {
  const self = me?.via === 'session' && me?.name === person.name;
  const done = await ask({
    title: `Sign ${person.name} out?`,
    text: `This ends ${plural(person.active_sessions, 'session')}${self ? ', including yours' : ''}. A new sign-in reads their roles from the identity provider again, so it only succeeds if they still have an AgentGov role.`,
    tone: 'danger', iconName: 'signout', confirm: 'Sign out', busy: 'Signing out…',
    submit: () => api(`v1/access/people/${encodeURIComponent(person.subject)}/sign-out`, { method: 'POST' }),
  });
  if (!done) return;
  toast(`Signed ${person.name} out (${plural(done.ended, 'session')} ended).`);
  await refresh();
}

function apiKeysCard(keys) {
  const active = keys.filter((k) => !k.revoked_at).length;
  return card({
    title: 'API keys',
    sub: `${plural(active, 'active key')}${keys.length > active ? `, ${fmt(keys.length - active)} revoked` : ''}. Requests made with a key are recorded in the ledger as <role>:<name>.`,
    actions: can('admin') ? [h('button', { type: 'button', class: 'btn btn--sm btn--primary', 'data-focus-key': 'create-key', onclick: guarded(createApiKey) }, icon('plus'), 'Create API key')] : null,
    flush: keys.length > 0,
    body: keys.length
      ? h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
        h('caption', { class: 'sr-only' }, 'API keys'),
        h('thead', {}, h('tr', {}, ['Name', 'Role', 'Key', 'Created', 'Last used', 'Status', ''].map((t) => h('th', { scope: 'col' }, t || h('span', { class: 'sr-only' }, 'Actions'))))),
        h('tbody', {}, keys.map((k) => h('tr', {},
          h('td', { 'data-label': 'Name', class: 'break' }, h('span', { class: 'cell-title' }, k.name)),
          h('td', { 'data-label': 'Role' }, humanize(k.role)),
          h('td', { 'data-label': 'Key' }, h('code', { title: 'The first characters of the key' }, `${k.prefix}…`)),
          h('td', { 'data-label': 'Created', class: 'nowrap' }, timeEl(k.created_at)),
          h('td', { 'data-label': 'Last used', class: 'nowrap' }, timeEl(k.last_used_at, { empty: 'Never' })),
          h('td', { 'data-label': 'Status' }, chip('apikey', k.revoked_at ? 'revoked' : 'active', { title: k.revoked_at ? `Revoked ${fullFmt.format(new Date(k.revoked_at))}` : null })),
          h('td', { 'data-label': '' }, !k.revoked_at && can('admin')
            ? h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', 'data-focus-key': `revoke-${k.id}`, onclick: () => revokeApiKey(k) }, icon('ban'), 'Revoke')
            : null))))))
      : emptyState('No API keys', 'Until you create role-scoped keys, the CLI and automation need the bootstrap admin token.'),
  });
}

async function createApiKey() {
  const created = await ask({
    title: 'Create an API key',
    text: 'The key is shown once, right after it is created. The control plane keeps only a hash of it.',
    iconName: 'key', confirm: 'Create key', busy: 'Creating…',
    fields: [
      { id: 'name', label: 'Name', required: true, placeholder: 'ci-pipeline', hint: 'Who or what uses the key. Approver keys named after a sponsor can attest that sponsor\'s agents.' },
      { id: 'role', label: 'Role', type: 'select', value: 'auditor', options: KEY_ROLES.map(([value, label]) => ({ value, label })) },
    ],
    submit: (v) => api('v1/apikeys', { method: 'POST', body: { name: v.name, role: v.role } }),
  });
  if (!created) return;
  const base = API_ROOT.href.replace(/\/$/, '');
  await ask({
    title: `API key for ${created.name}`,
    text: "Copy the key now: it can't be shown again. If it is lost, revoke it and create another.",
    iconName: 'key', confirm: 'Done', cancel: null, wide: true,
    extra: h('div', { class: 'stack', style: 'gap:12px' },
      facts([['Key', copyable(created.token, 'API key')], ['Role', humanize(created.role)]]),
      h('div', { class: 'stack', style: 'gap:6px' }, h('span', { class: 'field-label' }, 'Use it with the CLI'),
        h('pre', { class: 'kv-pre' }, `export AGENTGOV_URL=${base}\nexport AGENTGOV_TOKEN=${created.token}\nagentgov whoami`))),
  });
  await refresh();
}

async function revokeApiKey(k) {
  const own = me?.via === 'api_key' && me?.name === k.name && me?.role === k.role;
  const done = await ask({
    title: `Revoke ${k.name}?`,
    text: `Requests made with this key are refused from now on. Revoked keys stay listed for the record.${own ? ' You are signed in with this key, so you will be signed out.' : ''}`,
    tone: 'danger', iconName: 'ban', confirm: 'Revoke key', busy: 'Revoking…',
    submit: () => api(`v1/apikeys/${encodeURIComponent(k.id)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Revoked ${k.name}.`);
  await refresh();
}

/* --------------------------------------------------------------- platforms */

// Agents built on Microsoft 365 Copilot and Copilot Studio. They never call the
// gateway, so AgentGov governs what their platform reports about them.
const PLATFORM_SOURCES = {
  'platform:microsoft-365': 'Microsoft 365',
  'platform:copilot-studio': 'Copilot Studio',
  'platform:entra-agent-id': 'Microsoft Entra Agent ID',
};
// The platforms whose agents AgentGov can block there (an Entra identity alone isn't one).
const BLOCKABLE_SOURCES = new Set(['copilot-studio', 'microsoft-365']);
const M365_SETTINGS = 'AGENTGOV_M365_TENANT_ID, AGENTGOV_M365_CLIENT_ID and AGENTGOV_M365_CLIENT_SECRET';
const INVENTORY_EXPORT = [
  'az login',
  `az graph query -q "PowerPlatformResources | where type == 'microsoft.copilotstudio/agents'" --first 1000 -o json > copilot-studio-agents.json`,
].join('\n');
const PACKAGE_TYPES = {
  custom: 'Built by your organisation', shared: 'Shared by a user', external: 'From a partner', microsoft: 'Built by Microsoft',
};
const AUDIENCE = { all: 'Everyone', some: 'Some users or groups', none: 'Nobody' };

function platformOf(a) {
  return PLATFORM_SOURCES[a?.source] || null;
}

function connectorKey(id) {
  return String(id || '').trim().replace(/\/+$/, '').split('/').pop();
}

function syncCounts(c) {
  const parts = [`${fmt(c.created)} new`, `${fmt(c.updated)} updated`, `${fmt(c.skipped)} skipped`];
  if (c.findings != null) parts.push(plural(c.findings, 'open finding'));
  return parts.join(', ');
}

async function renderPlatforms() {
  const [view, usage] = await Promise.all([api('v1/platforms'), api('v1/platforms/connectors')]);
  const sources = Object.fromEntries(view.sources.map((src) => [src.source, src]));
  return h('div', { class: 'page' },
    pageHead({
      title: 'Platforms',
      sub: "Agents built on Microsoft 365 Copilot and Copilot Studio. They don't call tools through AgentGov's gateway, so AgentGov governs what their platform reports: who owns them, who they are shared with and which connectors they use.",
      actions: [refreshButton()],
    }),
    platformsCallout(view),
    connectionsCard(view),
    h('div', { class: 'grid-halves' }, m365Card(sources['microsoft-365']), copilotStudioCard(sources['copilot-studio'], view.admin_actions)),
    connectorsCard(usage, view));
}

function platformsCallout(view) {
  const enforcing = view.threat_detection?.mode === 'enforce';
  if (!view.admin_actions && !enforcing) {
    return callout('neutral', 'info', h('span', {}, h('strong', {}, 'AgentGov reads these platforms; on its own it does not change them. '),
      "Blocking one of their agents here marks it in AgentGov only. To stop it, block it in the Microsoft 365 admin center or the Power Platform admin center, or connect the services below."));
  }
  const can = [
    view.admin_actions ? 'admins signed in through Microsoft Entra ID can quarantine and block these agents from here' : null,
    enforcing ? "AgentGov's policies decide about each tool call Copilot Studio agents make, so blocking one here stops its tool calls" : null,
  ].filter(Boolean);
  return callout('neutral', 'info', h('span', {}, h('strong', {}, 'AgentGov works alongside these platforms: '), `${can.join(', and ')}.`));
}

const CONNECTION_COUNTS = {
  'microsoft-365': (c) => syncCounts(c),
  'copilot-studio': (c) => syncCounts(c),
  'entra-agent-id': (c) => `${fmt(c.created)} new, ${fmt(c.updated)} updated, ${fmt(c.linked)} linked to agents`,
  'purview-audit': (c) => [`${plural(c.interactions, 'interaction')}`, `${plural(c.maker_events, 'maker change')}`,
    c.searching ? `${plural(c.searching, 'search', 'searches')} running` : null].filter(Boolean).join(', '),
  defender: (c) => `${plural(c.alerts, 'alert')} about agents, ${fmt(c.matched)} matched, ${fmt(c.resolved)} resolved`,
  'connector-policies': (c) => `${plural(c.connectors, 'connector')} applied to ${plural(c.targets, 'group or environment', 'groups or environments')}`,
};

function connectionHelp(c, view) {
  if (c.status === 'missing_permission') return `Grant AgentGov's app registration the application permission ${c.permission}, with admin consent, then sync.`;
  if (c.status === 'out_of_date') return 'The allowlist changed since it was pushed: push it again.';
  if (c.status === 'turned_off') return 'Turn it on again on the Features page.';
  if (c.key === 'threat-detection') {
    const origin = new URL(API_ROOT).origin;
    return c.status === 'off'
      ? `Needs ${c.needs.join(', ')}. Connect ${origin}/integrations/copilot-studio in the Power Platform admin center, then turn on Copilot Studio threat detection on the Features page.`
      : `Endpoint: ${origin}/integrations/copilot-studio`;
  }
  if (c.status === 'off' || c.status === 'import') return `Needs ${c.needs.join(', and ')}.`;
  return null;
}

function connectionLastRun(c, view) {
  if (c.key === 'threat-detection') {
    const t = view.threat_detection || {};
    if (!t.calls) return h('span', { class: 'muted' }, c.status === 'off' ? '—' : 'No calls yet');
    return h('div', {}, `${plural(t.calls, 'tool call')}, ${fmt(t.blocked || 0)} blocked`,
      t.would_block ? `, ${fmt(t.would_block)} would have been` : '',
      h('div', { class: 'cell-sub' }, 'Last call ', timeEl(t.last_call_at)));
  }
  const last = c.last_run;
  if (!last) return h('span', { class: 'muted' }, 'Never');
  const summary = last.ok ? (CONNECTION_COUNTS[c.key] || syncCounts)(last.counts || {}) : last.message;
  return h('div', {}, timeEl(last.at), h('div', { class: last.ok ? 'cell-sub' : 'cell-sub tone-text-critical' }, summary));
}

function connectionsCard(view) {
  const rows = view.connections || [];
  const appReady = rows.some((c) => c.via === 'app' && !['off', 'turned_off'].includes(c.status));
  const actions = can('admin') && appReady
    ? [h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'sync-all', onclick: (e) => syncConnections(e.currentTarget) }, icon('refresh'), 'Sync all')]
    : null;
  return card({
    title: 'Microsoft connections',
    sub: 'Each one is optional. AgentGov uses the ones it can reach and works without the others.',
    actions,
    flush: true,
    body: h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
      h('caption', { class: 'sr-only' }, 'Microsoft connections'),
      h('thead', {}, h('tr', {}, ['Connection', 'Status', 'Last run', ''].map((t) => h('th', { scope: 'col' }, t || h('span', { class: 'sr-only' }, 'Actions'))))),
      h('tbody', {}, rows.map((c) => {
        const help = connectionHelp(c, view);
        const syncable = can('admin') && c.via === 'app' && !['off', 'turned_off'].includes(c.status);
        return h('tr', { 'data-connection': c.key },
          h('td', { 'data-label': 'Connection' }, h('span', { class: 'cell-title' }, c.name), h('div', { class: 'cell-sub' }, c.gives)),
          h('td', { 'data-label': 'Status' }, chip('connection', c.status), help ? h('div', { class: 'cell-sub break' }, help) : null),
          h('td', { 'data-label': 'Last run' }, connectionLastRun(c, view)),
          h('td', { 'data-label': '' }, syncable
            ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `sync-${c.key}`, onclick: (e) => syncConnection(c, e.currentTarget) }, icon('refresh'), 'Sync now')
            : null));
      })))),
  });
}

async function syncConnection(c, button) {
  button.disabled = true;
  button.lastChild.textContent = 'Syncing…';
  try {
    const counts = await api(`v1/platforms/${encodeURIComponent(c.key)}/sync`, { method: 'POST' });
    toast(`${c.name}: ${(CONNECTION_COUNTS[c.key] || syncCounts)(counts)}.`);
  } catch (err) {
    toast(err.message, { tone: 'critical' });
  }
  refreshBadges();
  await refresh();
}

async function syncConnections(button) {
  button.disabled = true;
  button.lastChild.textContent = 'Syncing…';
  try {
    const results = await api('v1/platforms/sync', { method: 'POST' });
    const failed = Object.entries(results).filter(([, r]) => r.error);
    if (failed.length) toast(`Synced, but ${failed.map(([k]) => k).join(', ')} failed: see Microsoft connections.`, { tone: 'critical' });
    else toast('Synced every Microsoft connection AgentGov may use.');
  } catch (err) {
    toast(err.message, { tone: 'critical' });
  }
  refreshBadges();
  await refresh();
}

function sourceFacts(src, verb) {
  const last = src.last_sync;
  return facts([
    ['Agents', src.agents
      ? h('a', { href: `#/agents?source=${encodeURIComponent(`platform:${src.source}`)}` }, plural(src.agents, 'agent'))
      : h('span', { class: 'muted' }, 'None yet')],
    [`Last ${verb}`, last ? [chip('sync', last.ok ? 'ok' : 'failed'), ' ', timeEl(last.at)] : h('span', { class: 'muted' }, 'Never')],
    last?.ok ? ['Result', syncCounts(last.counts)] : null,
  ]);
}

function m365Card(src) {
  const last = src.last_sync;
  const actions = can('admin') && src.configured
    ? [h('button', { type: 'button', class: 'btn btn--sm btn--primary', 'data-focus-key': 'm365-sync', onclick: (e) => syncMicrosoft365(e.currentTarget) }, icon('refresh'), 'Sync now')]
    : null;
  return card({
    title: 'Microsoft 365',
    sub: "The organisation's agent catalog, read from Microsoft Graph on a schedule: custom agents, agents users share, and partners' agents.",
    actions,
    body: src.configured
      ? [last && !last.ok ? callout('critical', 'octagon', h('span', {}, h('strong', {}, 'The last sync failed. '), last.message)) : null, sourceFacts(src, 'sync')]
      : emptyState('Not connected', `To sync, set ${M365_SETTINGS} for a Microsoft Entra app that has the Microsoft Graph application permission CopilotPackages.Read.All. Microsoft requires a Microsoft Agent 365 licence for this API.`),
  });
}

async function syncMicrosoft365(button) {
  button.disabled = true;
  button.lastChild.textContent = 'Syncing…';
  try {
    const counts = await api('v1/platforms/microsoft-365/sync', { method: 'POST' });
    toast(`Synced the Microsoft 365 catalog: ${syncCounts(counts)}.`);
  } catch (err) {
    toast(err.message, { tone: 'critical' });
  }
  refreshBadges();
  await refresh();
}

function copilotStudioCard(src, adminActions) {
  const asYou = adminActions && can('admin') && me?.microsoft;
  const actions = can('admin') ? [
    asYou ? h('button', { type: 'button', class: 'btn btn--sm btn--primary', 'data-focus-key': 'studio-sync', onclick: (e) => syncCopilotStudio(e.currentTarget) }, icon('refresh'), 'Sync now') : null,
    h('button', { type: 'button', class: asYou ? 'btn btn--sm' : 'btn btn--sm btn--primary', 'data-focus-key': 'studio-import', onclick: guarded(importCopilotStudio) }, icon('upload'), 'Import inventory'),
  ].filter(Boolean) : null;
  return card({
    title: 'Copilot Studio',
    sub: asYou
      ? 'Copilot Studio and Agent Builder agents with the connectors they use, from the Power Platform inventory. Microsoft only lets a signed-in admin read it, so AgentGov syncs it as you.'
      : 'Copilot Studio and Agent Builder agents with the connectors they use, from the Power Platform inventory. Microsoft only lets a signed-in admin read the inventory, so export it and import the file here'
        + (adminActions && can('admin') ? ', or sign in to AgentGov with Microsoft Entra ID to sync it from here.' : '.'),
    actions,
    body: src.last_sync
      ? sourceFacts(src, 'update')
      : emptyState('Nothing imported yet', 'Export the inventory as a Power Platform or AI administrator (a reader role is enough), then import the file:',
        h('pre', { class: 'kv-pre' }, INVENTORY_EXPORT)),
  });
}

async function syncCopilotStudio(button) {
  button.disabled = true;
  button.lastChild.textContent = 'Syncing…';
  try {
    const counts = await api('v1/platforms/copilot-studio/sync', { method: 'POST' });
    toast(`Synced the Copilot Studio inventory: ${syncCounts(counts)}.`);
  } catch (err) {
    toast(err.message, { tone: 'critical' });
  }
  refreshBadges();
  await refresh();
}

async function importCopilotStudio() {
  const result = await ask({
    title: 'Import Copilot Studio agents',
    text: 'Load or paste the Power Platform inventory, as JSON. Export it as a Power Platform or AI administrator (a reader role is enough) with the Azure CLI, the Power Platform API or `pac resource-query`. Importing again updates the agents already here.',
    extra: h('pre', { class: 'kv-pre' }, INVENTORY_EXPORT),
    iconName: 'upload', confirm: 'Import', busy: 'Importing…', wide: true,
    fields: [{
      id: 'json', label: 'Inventory (JSON)', type: 'code', rows: 10, required: true, file: '.json',
      placeholder: '{"data": [{"name": "…", "type": "microsoft.copilotstudio/agents", "properties": {…}}]}',
    }],
    submit: (v) => {
      try {
        JSON.parse(v.json);
      } catch (err) {
        throw new Error(`That isn't valid JSON: ${err.message}`);
      }
      return api('v1/platforms/copilot-studio/import', { method: 'POST', text: v.json, contentType: 'application/json' });
    },
  });
  if (!result) return;
  toast(`Imported Copilot Studio agents: ${syncCounts(result)}.`);
  refreshBadges();
  await refresh();
}

function connectorsCard(usage, view) {
  const rows = usage.connectors || [];
  const active = usage.allowlist_active;
  const pushable = can('admin') && view?.admin_actions && me?.microsoft;
  const approved = rows.filter((r) => r.approved).length;
  const status = (r) => {
    if (r.approved) return chip('connector', 'approved', { title: [r.approved_by && `Approved by ${r.approved_by}`, r.approved_at && fullFmt.format(new Date(r.approved_at))].filter(Boolean).join(', ') || null });
    return active ? chip('connector', 'unapproved', { title: 'Agents that use it get a finding' }) : chip('connector', 'unchecked', { title: 'The allowlist is empty, so nothing is flagged yet' });
  };
  const listed = (items, max, render) => [
    ...items.slice(0, max).map(render),
    items.length > max ? h('span', { class: 'muted small' }, `and ${fmt(items.length - max)} more`) : null,
  ];
  return card({
    title: 'Connectors',
    sub: active
      ? 'The Power Platform connectors Copilot Studio agents use. An agent that uses a connector that is not approved gets a high-severity finding.'
      : 'The Power Platform connectors Copilot Studio agents use. The allowlist is empty, so none is flagged yet: approve the connectors your organisation allows, and agents that use any other connector get a finding.',
    actions: can('admin') ? [
      pushable ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'push-policy', onclick: guarded(pushConnectorPolicy) }, icon('upload'), 'Push to Power Platform') : null,
      h('button', { type: 'button', class: 'btn btn--sm btn--primary', 'data-focus-key': 'approve-connector', onclick: guarded(() => approveConnector(null, active)) }, icon('plus'), 'Approve a connector'),
    ].filter(Boolean) : null,
    flush: rows.length > 0,
    body: rows.length
      ? h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
        h('caption', { class: 'sr-only' }, 'Connectors'),
        h('thead', {}, h('tr', {}, ['Connector', 'Allowlist', 'Agents', 'Tools', 'Maker connections', ''].map((t) => h('th', { scope: 'col', class: t === 'Maker connections' ? 'num' : null }, t || h('span', { class: 'sr-only' }, 'Actions'))))),
        h('tbody', {}, rows.map((r) => h('tr', {},
          h('td', { 'data-label': 'Connector', class: 'break' }, h('code', { class: 'cell-title' }, r.connector_id),
            r.note ? h('div', { class: 'cell-sub' }, r.note) : null),
          h('td', { 'data-label': 'Allowlist' }, status(r)),
          h('td', { 'data-label': 'Agents' }, r.agents.length
            ? h('div', { class: 'chip-row' }, listed(r.agents, 3, (ag) => agentLink(ag.id, ag.name)))
            : h('span', { class: 'muted' }, 'None')),
          h('td', { 'data-label': 'Tools' }, r.operations.length
            ? h('div', { class: 'chip-row' }, listed(r.operations, 3, (op) => plainChip(op, { mono: true })))
            : h('span', { class: 'muted' }, '—')),
          h('td', { 'data-label': 'Maker connections', class: 'num' }, r.maker_connections
            ? h('span', { title: "Tools that run with the maker's credentials for every user" }, fmt(r.maker_connections))
            : h('span', { class: 'muted' }, '0')),
          h('td', { 'data-label': '' }, can('admin')
            ? (r.approved
              ? h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', 'data-focus-key': `unapprove-${r.connector_id}`, onclick: guarded(() => unapproveConnector(r, approved)) }, icon('ban'), 'Remove approval')
              : h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `approve-${r.connector_id}`, onclick: guarded(() => approveConnector(r, active)) }, icon('check'), 'Approve'))
            : null))))))
      : emptyState('No connectors yet', 'They appear here once Copilot Studio agents are imported. You can approve connectors before that.'),
  });
}

async function pushConnectorPolicy() {
  const preview = await api('v1/platforms/connector-policy');
  if (!preview.allowlist.length) {
    toast('Approve at least one connector first: Power Platform would block every connector.', { tone: 'critical' });
    return;
  }
  const free = preview.targets.filter((t) => !t.other_policies.length);
  const taken = preview.targets.filter((t) => t.other_policies.length);
  const key = (t) => `target:${t.scope}:${t.id}`;
  const label = (t) => (t.scope === 'group'
    ? `${t.name} (environment group)`
    : `Environment ${t.name}${t.agents ? ` (${plural(t.agents, 'Copilot Studio agent')})` : ''}`);
  const losing = preview.agents_losing_connectors;
  const extra = h('div', { class: 'stack' },
    callout('warning', 'triangle', h('span', {}, h('strong', {}, "Power Platform blocks every connector this policy doesn't list"),
      `, for apps and flows as well as agents, in the groups and environments you choose. It will allow: ${preview.allowlist.join(', ')}.`)),
    losing.length ? callout('serious', 'triangle', h('span', {}, h('strong', {}, `${plural(losing.length, 'agent')} would lose connectors: `),
      losing.map((a) => `${a.name} (${a.connectors.join(', ')})`).join('; '), '.')) : null,
    preview.out_of_date ? h('p', { class: 'hint' }, "Power Platform's copy of the policy differs from the allowlist; pushing replaces it.") : null,
    taken.length ? h('p', { class: 'hint' }, 'Not offered, because another connector policy applies there and an environment takes one: ',
      taken.map((t) => `${t.name} (${t.other_policies.join(', ')})`).join('; '), '.') : null,
    free.length ? null : h('p', { class: 'hint' }, 'No environment group or environment is free for this policy.'));
  const done = await ask({
    title: 'Push the connector allowlist to Power Platform?',
    text: `AgentGov saves it as the connector policy "${preview.policy_name}" and applies it where you choose, as you. Wherever the policy already applies, its list changes too. The ledger records it.`,
    tone: 'danger', iconName: 'upload', confirm: 'Push to Power Platform', busy: 'Pushing…', wide: true, extra,
    fields: free.map((t) => ({ id: key(t), type: 'checkbox', value: t.applied, label: label(t), hint: t.applied ? 'Already applied: its list is updated.' : null })),
    submit: (values) => {
      const targets = free.filter((t) => values[key(t)]).map((t) => ({ scope: t.scope, id: t.id }));
      if (!targets.length) throw new Error('Pick at least one environment group or environment.');
      return api('v1/platforms/connector-policy', { method: 'POST', body: { targets } });
    },
  });
  if (!done) return;
  toast(`Pushed ${plural(done.connectors.length, 'connector')} to Power Platform, applied to ${plural(done.targets.length, 'group or environment', 'groups or environments')}.`);
  await refresh();
}

async function approveConnector(row, active) {
  const first = active ? '' : ' This is the first approved connector: from now on, agents that use connectors which are not approved get a finding.';
  const done = await ask({
    title: row ? `Approve ${row.connector_id}?` : 'Approve a connector',
    text: (row ? `Copilot Studio agents may use ${row.connector_id} without a finding.` : 'Add a Power Platform connector to the allowlist.') + first,
    iconName: 'check', confirm: 'Approve', busy: 'Approving…',
    fields: [
      row ? null : { id: 'connector', label: 'Connector ID', required: true, mono: true, placeholder: 'shared_office365', hint: 'As the inventory or the connector reference names it, with or without /providers/Microsoft.PowerApps/apis/.' },
      { id: 'note', label: 'Note', type: 'textarea', value: row?.note || '', hint: 'Why it is allowed. Shown here and recorded in the evidence ledger.' },
    ].filter(Boolean),
    submit: (v) => api(`v1/platforms/connectors/${encodeURIComponent(connectorKey(row ? row.connector_id : v.connector))}/approval`, { method: 'PUT', body: { note: v.note || '' } }),
  });
  if (!done) return;
  toast(`Approved ${done.connector_id}.`);
  refreshBadges();
  await refresh();
}

async function unapproveConnector(row, approvedCount) {
  const users = row.agents.length ? `${plural(row.agents.length, 'agent')} that use it will get a finding.` : 'No imported agent uses it.';
  const last = approvedCount === 1 ? ' It is the last approved connector, so the allowlist stops being checked until you approve another.' : '';
  const done = await ask({
    title: `Remove ${row.connector_id} from the allowlist?`,
    text: approvedCount === 1 ? `No connector will be approved.${last}` : users,
    tone: 'danger', iconName: 'ban', confirm: 'Remove approval', busy: 'Removing…',
    submit: () => api(`v1/platforms/connectors/${encodeURIComponent(row.connector_id)}/approval`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`${row.connector_id} is no longer approved.`);
  refreshBadges();
  await refresh();
}

/** What Microsoft 365 or Copilot Studio reports about an agent (its page's main card). */
function entraCard(v) {
  const yesNo = (value) => (value == null ? null : value ? 'Yes' : 'No');
  const notes = [];
  const why = String(v.disabled_by_microsoft || '').replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase();
  if (v.disabled_by_microsoft) notes.push(callout('critical', 'octagon', `Microsoft disabled this identity (${why}), so the agent cannot sign in.`));
  if (v.in_directory === false) notes.push(callout('warning', 'triangle', 'This identity is no longer in Microsoft Entra ID.'));
  return card({
    title: v.source_name,
    sub: "The agent's identity in Microsoft Entra ID, as it was at the last sync",
    body: [...notes, facts([
      ['Name in Entra', v.display_name],
      ['Enabled', yesNo(v.enabled)],
      ['Created from', v.blueprint ? `${v.blueprint} (its agent identity blueprint)` : (v.blueprint_id ? h('code', {}, v.blueprint_id) : null)],
      ['Created', timeEl(v.created_at)],
      ['Entra agent ID', copyable(v.external_id, 'Entra agent ID')],
      ['Synced', timeEl(v.synced_at)],
    ])],
  });
}

/** Who used the agent lately and where, from the Microsoft Purview audit log. */
function usageRows(v) {
  const u = v.usage;
  if (!u) return [];
  return [
    ['Last used', timeEl(u.last_used_at)],
    (u.recent_users || []).length ? ['Recent users', h('div', { class: 'chip-row' }, u.recent_users.slice(0, 5).map((x) => plainChip(x)),
      u.recent_users.length > 5 ? h('span', { class: 'muted small' }, `and ${fmt(u.recent_users.length - 5)} more`) : null)] : null,
    Object.keys(u.hosts || {}).length ? ['Used in', h('div', { class: 'chip-row' }, Object.entries(u.hosts).map(([host, n]) => plainChip(`${host} · ${fmt(n)}`)))] : null,
  ];
}

function platformCard(a, v, where) {
  if (v.source === 'entra-agent-id') return entraCard(v);
  const studio = v.source === 'copilot-studio';
  // Only on the card for the record the control plane acts on.
  const acts = where && where.source === v.source;
  const blockedThere = studio ? v.quarantined : v.blocked;
  const actions = acts && me?.microsoft ? [blockedThere
    ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'platform-unblock', onclick: guarded(() => platformBlock(a, where, false)) }, icon('undo'), studio ? 'Release from quarantine' : 'Unblock in Microsoft 365')
    : h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', 'data-focus-key': 'platform-block', onclick: guarded(() => platformBlock(a, where, true)) }, icon('ban'), studio ? 'Quarantine' : 'Block in Microsoft 365')] : null;
  const yesNo = (value) => (value == null ? null : value ? 'Yes' : 'No');
  const notes = [];
  if (v.in_catalog === false) notes.push(callout('warning', 'triangle', `This agent is no longer in the Microsoft 365 catalog. Delete it here when you no longer need its record.`));
  if (v.blocked) notes.push(callout('neutral', 'ban', 'Blocked in Microsoft 365.'));
  if (v.quarantined) notes.push(callout('neutral', 'ban', 'Quarantined in Copilot Studio: it works only in its makers\' test pane.'));
  if (acts && !me?.microsoft) notes.push(h('p', { class: 'hint' }, `To ${studio ? 'quarantine' : 'block'} it in ${v.source_name} from here, sign in to AgentGov with Microsoft Entra ID.`));
  const rows = studio ? [
    ['Name in Copilot Studio', v.display_name],
    ['Created in', v.created_in],
    ['Authentication', String(v.authentication).toLowerCase() === 'none'
      ? plainChip('None: anyone can use it', { tone: 'serious', iconName: 'triangle' }) : v.authentication],
    ['Shared with', v.shared_with_everyone
      ? plainChip('Everyone in the organisation', { tone: 'warning', iconName: 'alert-circle' })
      : `${plural(v.viewers?.users ?? 0, 'person', 'people')}, ${plural(v.viewers?.groups ?? 0, 'group')}`],
    (v.channels || []).length ? ['Channels', h('div', { class: 'chip-row' }, v.channels.map((c) => plainChip(c)))] : null,
    v.orchestration ? ['Orchestration', v.orchestration] : null,
    v.model ? ['Model', h('code', {}, v.model)] : null,
    v.web_search_knowledge != null ? ['Web search for knowledge', yesNo(v.web_search_knowledge)] : null,
    ['Published', timeEl(v.published_at, { empty: 'Not published (draft)' })],
    v.owner_id ? ['Owner (Entra object ID)', h('code', {}, v.owner_id)] : null,
    v.environment_id ? ['Environment', h('code', {}, v.environment_id)] : null,
    ['Agent ID', copyable(v.external_id, 'Copilot Studio agent ID')],
    ['Imported', timeEl(v.synced_at)],
    ...usageRows(v),
  ] : [
    ['Name in Microsoft 365', v.display_name],
    ['Type', PACKAGE_TYPES[v.type] || humanize(v.type)],
    v.publisher ? ['Publisher', v.publisher] : null,
    v.built_with ? ['Built with', v.built_with] : null,
    v.classification ? ['Classification', v.classification] : null,
    ['Available to', AUDIENCE[v.available_to] || humanize(v.available_to)],
    ['Deployed to', AUDIENCE[v.deployed_to] || humanize(v.deployed_to)],
    v.request ? ['Request', `${humanize(v.request.type)} request, ${v.request.status}`] : null,
    v.version ? ['Version', v.version] : null,
    ['Package ID', copyable(v.external_id, 'package ID')],
    ['Changed', timeEl(v.last_modified)],
    ['Synced', timeEl(v.synced_at)],
    ...usageRows(v),
  ];
  return card({
    title: v.source_name,
    sub: studio ? 'As the Power Platform inventory reported it at the last import' : 'As the Microsoft 365 agent catalog reported it at the last sync',
    actions,
    body: [...notes, facts(rows), studio ? connectorList(v) : null],
  });
}

function connectorList(v) {
  const connectors = v.connectors || [];
  return h('div', { class: 'stack', style: 'gap:8px; margin-top:14px' },
    h('h3', { class: 'dialog-section' }, 'Connectors'),
    connectors.length ? h('ul', { class: 'perm-list', role: 'list' }, connectors.map((c) => h('li', {},
      h('span', { class: 'perm-server' }, h('code', {}, c.connector_id), ' ',
        v.allowlist_active ? chip('connector', c.approved ? 'approved' : 'unapproved') : null),
      h('div', { class: 'chip-row' }, (c.operations || []).map((op) => plainChip(op.operation_id || '(unnamed)', {
        mono: true,
        tone: op.maker_connection ? 'warning' : null,
        title: [op.used_as, op.maker_connection ? "runs with the maker's connection" : 'runs with the user\'s own connection', op.enabled ? null : 'disabled'].filter(Boolean).join(', '),
      })))))) : h('p', { class: 'muted small' }, 'No Power Platform connectors.'),
    connectors.some((c) => (c.operations || []).some((op) => op.maker_connection))
      ? h('p', { class: 'hint' }, "Highlighted tools run with their maker's connection, so every user reaches data with the maker's access.") : null,
    v.allowlist_active ? null : h('p', { class: 'hint' }, h('a', { href: '#/platforms' }, 'The connector allowlist'), ' is empty, so connectors are not checked yet.'));
}

/* ---------------------------------------------------------------- features */

const MODE_WORDS = {
  off: 'Off', on: 'On', monitor: 'Monitor', enforce: 'Enforce',
  inform: 'Inform', triage: 'Triage', contain: 'Contain', decide: 'Decide',
};

async function featureModes() {
  const view = await api('v1/features');
  return Object.fromEntries(view.features.map((f) => [f.key, f.mode]));
}

// What differs from the defaults: features monitored, and features turned off.
function featureSummary(list) {
  const monitored = list.filter((f) => f.mode === 'monitor' && f.default !== 'monitor').length;
  const off = list.filter((f) => f.mode === 'off' && f.default !== 'off').length;
  const parts = [monitored ? `${fmt(monitored)} monitored` : null, off ? `${fmt(off)} turned off` : null].filter(Boolean);
  return parts.length ? `Features: ${parts.join(', ')}` : 'Features: the defaults';
}

async function renderFeatures() {
  const view = await api('v1/features');
  const monitored = view.features.filter((f) => f.mode === 'monitor' && f.group === 'controls');
  return h('div', { class: 'page' },
    pageHead({
      title: 'Features',
      sub: 'Choose which parts of AgentGov you use, and how strictly. In monitor mode a control decides and records what it would have done, but lets the call through: try it on real traffic before you enforce it.',
      actions: [refreshButton()],
    }),
    monitored.length ? callout('warning', 'eye', h('span', {},
      h('strong', {}, `${plural(monitored.length, 'control')} in monitor mode. `),
      'Calls they would have stopped go through, and the ledger records them as warnings. ',
      h('a', { href: '#/ledger?decision=monitored' }, 'See what they would have stopped'), '.')) : null,
    Object.entries(view.groups).map(([group, title]) => {
      const list = view.features.filter((f) => f.group === group);
      return list.length ? featuresCard(title, list) : null;
    }));
}

function featuresCard(title, list) {
  return card({
    title,
    flush: true,
    body: h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable features-table' },
      h('caption', { class: 'sr-only' }, title),
      h('thead', {}, h('tr', {}, ['Feature', 'Mode', 'Now'].map((t) => h('th', { scope: 'col' }, t)))),
      h('tbody', {}, list.map((f) => h('tr', { 'data-feature': f.key },
        h('td', { 'data-label': 'Feature' },
          h('span', { class: 'cell-title' }, f.title), h('div', { class: 'cell-sub' }, f.description),
          f.needs ? h('div', { class: 'cell-sub' }, `Needs ${f.needs}.`) : null),
        h('td', { 'data-label': 'Mode' }, modeControl(f)),
        h('td', { 'data-label': 'Now' }, h('div', {}, f.effect), featureProvenance(f))))))),
  });
}

function featureProvenance(f) {
  if (f.set_by === 'deployment') {
    return h('div', { class: 'cell-sub' }, icon('lock'), ' Set by the deployment (AGENTGOV_FEATURES)');
  }
  if (f.set_by === 'admin') return h('div', { class: 'cell-sub' }, `Set by ${f.changed_by} `, timeEl(f.changed_at));
  return h('div', { class: 'cell-sub' }, 'The default');
}

function modeControl(f) {
  if (!can('admin') || f.set_by === 'deployment') return chip('mode', f.mode);
  const name = `mode-${f.key}`;
  return h('div', { class: 'segmented', role: 'radiogroup', 'aria-label': `${f.title}: mode` },
    f.modes.map((m) => {
      const id = `${name}-${m}`;
      const unavailable = f.unavailable?.[m];
      const input = h('input', {
        type: 'radio', id, name, value: m, checked: m === f.mode,
        disabled: Boolean(unavailable) && m !== f.mode, 'data-focus-key': id,
      });
      input.addEventListener('change', guarded(() => chooseMode(f, m)));
      return h('label', { for: id, title: unavailable || f.effects[m] || null }, input, h('span', {}, MODE_WORDS[m] || humanize(m)));
    }));
}

async function chooseMode(f, mode) {
  if (f.modes.indexOf(mode) < f.modes.indexOf(f.mode)) {
    const ok = await ask({
      title: `${f.title}: ${(MODE_WORDS[mode] || mode).toLowerCase()}?`,
      text: f.effects[mode],
      tone: 'danger', iconName: 'triangle', confirm: `Set to ${(MODE_WORDS[mode] || mode).toLowerCase()}`,
    });
    if (!ok) { await refresh(); return; }
  }
  try {
    const out = await api(`v1/features/${encodeURIComponent(f.key)}`, { method: 'PUT', body: { mode } });
    toast(`${f.title}: ${(MODE_WORDS[out.mode] || out.mode).toLowerCase()}. ${out.effect}`);
  } catch (err) {
    toast(err.message, { tone: 'critical' });
  }
  await refresh();
}

/* ------------------------------------------------------ security operations */

// Destinations by kind: name, whether it is a SIEM or a chat, a URL like its own, and the URL's hint.
const DEST_KINDS = {
  otlp: ['OpenTelemetry (OTLP)', 'siem', 'http://otel-collector:4318', "The collector's OTLP/HTTP endpoint. Events go to /v1/logs there."],
  webhook: ['Webhook (HTTP input)', 'siem', 'https://siem.example.com/ingest', "A SIEM's or log pipeline's HTTP input. Leave it empty when the URL is the credential: it then goes in the secret file."],
  'splunk-hec': ['Splunk HTTP Event Collector', 'siem', 'https://splunk.example.com:8088', "Splunk's HTTP Event Collector. Events go to /services/collector/event there."],
  slack: ['Slack', 'chat'],
  teams: ['Microsoft Teams', 'chat'],
};
const DEST_EVENTS = {
  siem: [
    ['decisions', 'Decisions', 'tool and model calls at the gateway'],
    ['approvals', 'Approvals', 'requested, decided, used'],
    ['findings', 'Findings', 'raised, resolved, dismissed'],
    ['access', 'Access', 'sign-ins and API keys'],
    ['changes', 'Changes', 'everything else: what AgentGov governs, and who changed it'],
  ],
  chat: [
    ['findings', 'Findings', 'from the minimum severity up'],
    ['approvals', 'Approval requests', 'whatever their severity'],
    ['blocks', 'Kill switches', 'agents, tool servers, model providers and identity issuers blocked, agents deleted'],
  ],
};
const DEST_SECRET = {
  otlp: 'Optional: HTTP headers to send, one per line, such as Authorization: Bearer <token>.',
  webhook: 'Optional: HTTP headers to send, one per line; and the URL, on a line of its own, when the URL is the credential (as with Sumo Logic).',
  'splunk-hec': "The HTTP Event Collector's token.",
  slack: "The incoming webhook's URL (https://hooks.slack.com/services/…).",
  teams: "The webhook URL of a Teams workflow that posts to the channel (the workflow \"When a Teams webhook request is received\").",
};
const destKind = (kind) => (DEST_KINDS[kind] || [kind])[0];
const destFamily = (kind) => (DEST_KINDS[kind] || [kind, 'siem'])[1];

async function renderSecops() {
  const [view, feature] = await Promise.all([api('v1/secops'), api(`v1/features/security-operations`)]);
  return h('div', { class: 'page' },
    pageHead({
      title: 'Security operations',
      sub: "What AgentGov hands to the security team's tools: the evidence ledger, as OCSF events, to their SIEMs; alerts to their Teams and Slack channels; and how much their secops role may do here.",
      actions: [refreshButton()],
    }),
    view.sending ? null : callout('neutral', 'power', h('span', {}, h('strong', {}, 'Nothing is sent. '),
      can('admin') ? 'Choose inform or above to send the destinations below their events and alerts.' : 'An administrator chooses how much is handed over.')),
    handoffCard(view, feature),
    destinationsCard(view),
    eventsApiCard(view));
}

function handoffCard(view, f) {
  const reached = view.levels.indexOf(view.level);
  return card({
    title: 'Hand-off',
    sub: "Each level includes the ones before it. The secops role is for the security team's tools (an API key) and analysts (the agentgov-secops role at sign-in). Everything it does is in the ledger under its name, and administrators can undo it.",
    body: h('div', { class: 'stack' },
      h('div', {}, modeControl(f), featureProvenance(f)),
      h('ol', { class: 'levels' }, f.modes.map((m, n) => h('li', { 'data-reached': n <= reached ? 'true' : 'false', 'aria-current': m === view.level ? 'step' : null },
        icon(n <= reached ? 'check-circle' : 'minus'),
        h('div', {}, h('strong', {}, MODE_WORDS[m] || humanize(m)), h('div', { class: 'cell-sub' }, f.effects[m] || '')))))),
  });
}

function destinationState(d) {
  const delivery = d.delivery;
  if (d.secret.need === 'required' && !d.secret.present) {
    return [plainChip('No secret file', { tone: 'warning', iconName: 'key' }), h('div', { class: 'cell-sub break' }, 'Put it in ', h('code', {}, d.secret.file))];
  }
  if (delivery.last_error) {
    return [plainChip(`Failing (${fmt(delivery.failures)})`, { tone: 'critical', iconName: 'octagon', title: delivery.last_error }),
      h('div', { class: 'cell-sub break' }, delivery.last_error),
      delivery.retry_at ? h('div', { class: 'cell-sub' }, 'Tries again ', timeEl(delivery.retry_at)) : null];
  }
  const sent = delivery.delivered_at
    ? h('div', { class: 'cell-sub' }, `${plural(delivery.delivered, destFamily(d.kind) === 'chat' ? 'alert' : 'event')} sent, last `, timeEl(delivery.delivered_at))
    : h('div', { class: 'cell-sub' }, 'Nothing sent yet');
  const behind = delivery.behind
    ? plainChip(`${fmt(delivery.behind)} ledger ${delivery.behind === 1 ? 'entry' : 'entries'} to go`, { tone: 'neutral', iconName: 'clock' })
    : plainChip('Up to date', { tone: 'good', iconName: 'check-circle' });
  return [behind, sent];
}

function destinationsCard(view) {
  const rows = view.destinations;
  const body = rows.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
    h('caption', { class: 'sr-only' }, 'Destinations'),
    h('thead', {}, h('tr', {}, ['Destination', 'Gets', 'Status', 'Delivery', ''].map((t) => h('th', { scope: 'col' }, t || h('span', { class: 'sr-only' }, 'Actions'))))),
    h('tbody', {}, rows.map((d) => h('tr', { 'data-destination': d.name },
      h('td', { 'data-label': 'Destination', class: 'break' }, h('span', { class: 'cell-title' }, d.name),
        h('div', { class: 'cell-sub' }, destKind(d.kind), d.format === 'ndjson' ? ', JSON lines' : ''),
        d.url ? h('div', { class: 'cell-sub' }, h('code', {}, d.url)) : null,
        d.description ? h('div', { class: 'cell-sub' }, d.description) : null),
      h('td', { 'data-label': 'Gets' }, h('div', { class: 'chip-row' }, d.events.map((e) => plainChip(humanize(e)))),
        d.min_severity !== 'info' ? h('div', { class: 'cell-sub' }, `${humanize(d.min_severity)} severity and up`) : null),
      h('td', { 'data-label': 'Status' }, chip('destination', d.status)),
      h('td', { 'data-label': 'Delivery' }, destinationState(d)),
      h('td', { 'data-label': '' }, can('admin') ? h('div', { class: 'btn-row' },
        h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `dest-test-${d.name}`, onclick: guarded(() => testDestination(d)) }, icon('play'), 'Test'),
        h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `dest-edit-${d.name}`, onclick: guarded(() => destinationForm(d)) }, icon('edit'), 'Edit'),
        h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `dest-pause-${d.name}`, onclick: guarded(() => pauseDestination(d)) },
          icon(d.status === 'paused' ? 'play' : 'minus'), d.status === 'paused' ? 'Resume' : 'Pause'),
        destFamily(d.kind) === 'siem' ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `dest-replay-${d.name}`, onclick: guarded(() => replayDestination(d)) }, icon('undo'), 'Replay') : null,
        h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', 'data-focus-key': `dest-delete-${d.name}`, onclick: guarded(() => deleteDestination(d)) }, icon('trash'), 'Delete')) : null))))))
    : emptyState('No destinations', 'Add a SIEM, through OpenTelemetry, an HTTP input or Splunk, to send it the ledger as OCSF events; or a Teams or Slack channel, to send it alerts.');
  return card({
    title: 'Destinations',
    sub: "Each gets what is new in the ledger, at least once and in order, and keeps its place while it is paused or failing. Its credential is a file the control plane reads, named after it: never in AgentGov's database.",
    actions: can('admin') ? [h('button', { type: 'button', class: 'btn btn--sm btn--primary', 'data-focus-key': 'add-destination', onclick: guarded(() => destinationForm(null)) }, icon('plus'), 'Add destination')] : null,
    flush: rows.length > 0,
    body,
  });
}

function eventsApiCard(view) {
  const url = new URL('v1/secops/events', API_ROOT).href;
  return card({
    title: 'Events API',
    sub: 'For SIEMs that collect rather than receive: the same OCSF events, from an API key with the secops role. Each page says where the next one starts.',
    body: h('div', { class: 'stack' },
      facts([
        ['Events', copyable(`${url}?after=0&limit=200`, 'events URL')],
        ['From the CLI', copyable('agentgov secops events --follow', 'CLI command')],
        ['Ledger entries', fmt(view.ledger_head)],
      ]),
      view.sending ? null : h('p', { class: 'hint' }, 'It answers once the hand-off is at inform or above.')),
  });
}

async function destinationForm(d) {
  const editing = Boolean(d);
  const kind0 = d?.kind || 'otlp';
  const eventFields = (family) => DEST_EVENTS[family].map(([key, label, hint]) => ({
    id: `ev-${family}-${key}`, label, hint, type: 'checkbox',
    value: editing ? d.events.includes(key) : true,
  }));
  const saved = await ask({
    title: editing ? `Edit ${d.name}` : 'Add a destination',
    text: editing
      ? `${destKind(d.kind)}. Changes apply to what it is sent next, and are recorded in the evidence ledger.`
      : "A SIEM gets the ledger as OCSF events; a chat gets alerts. Put its credential in its secret file, which the control plane reads when it sends.",
    iconName: editing ? 'edit' : 'secops', confirm: editing ? 'Save changes' : 'Add destination', wide: true,
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'soc-splunk', hint: NAME_HINT },
      editing ? null : {
        id: 'kind', label: 'Kind', type: 'select', value: kind0,
        options: Object.entries(DEST_KINDS).map(([value, [label, family]]) => ({ value, label: `${label}${family === 'chat' ? ': alerts' : ': OCSF events'}` })),
      },
      { id: 'url', label: 'URL', mono: true, value: d?.url || '', placeholder: DEST_KINDS[kind0][2] || '', hint: DEST_KINDS[kind0][3] || '' },
      { id: 'format', label: 'Body', type: 'select', value: d?.format || 'json', options: [
        { value: 'json', label: 'A JSON array of events' }, { value: 'ndjson', label: 'JSON lines: one event per line' },
      ] },
      { type: 'section', label: 'What it gets' },
      ...eventFields('siem'),
      ...eventFields('chat'),
      {
        id: 'min_severity', label: 'Minimum severity', type: 'select', value: d?.min_severity || (destFamily(kind0) === 'chat' ? 'high' : 'info'),
        options: ['info', 'low', 'medium', 'high', 'critical'].map((value) => ({ value, label: humanize(value) })),
        hint: 'For a chat, of findings: approval requests and kill switches always go.',
      },
      editing ? null : { id: 'backfill', label: 'Send it the ledger from its start, not from now', type: 'checkbox', value: false },
      { id: 'description', label: 'Description', type: 'textarea', value: d?.description || '' },
      { id: 'labels', label: 'Labels', value: formatLabels(d?.labels), placeholder: 'team=soc', mono: true },
    ].filter(Boolean),
    extra: h('p', { class: 'hint', id: 'dest-secret-hint' }),
    onReady: (controls) => {
      const field = (id) => controls[id]?.closest('.field');
      const secretHint = document.getElementById('dest-secret-hint');
      const show = () => {
        const kind = editing ? d.kind : controls.kind.value;
        const family = destFamily(kind);
        for (const [key] of DEST_EVENTS.siem) field(`ev-siem-${key}`).hidden = family !== 'siem';
        for (const [key] of DEST_EVENTS.chat) field(`ev-chat-${key}`).hidden = family !== 'chat';
        field('url').hidden = family === 'chat';
        field('format').hidden = kind !== 'webhook';
        if (field('backfill')) field('backfill').hidden = family === 'chat';
        controls.url.placeholder = DEST_KINDS[kind][2] || '';
        const hint = field('url').querySelector('.hint');
        if (hint) hint.textContent = DEST_KINDS[kind][3] || '';
        const name = editing ? d.name : (controls.name.value || '<name>');
        secretHint.textContent = `Secret file: ${d?.secret?.file || `<destination secrets>/${name}`}. ${DEST_SECRET[kind]}`;
        if (!editing && document.activeElement !== controls.min_severity) controls.min_severity.value = family === 'chat' ? 'high' : 'info';
      };
      if (!editing) {
        controls.kind.addEventListener('change', show);
        controls.name.addEventListener('input', show);
      }
      show();
    },
    submit: (v) => {
      const kind = editing ? d.kind : v.kind;
      const family = destFamily(kind);
      const events = DEST_EVENTS[family].map(([key]) => key).filter((key) => v[`ev-${family}-${key}`]);
      if (!events.length) throw new Error('Choose at least one kind of event to send it.');
      const body = {
        events, min_severity: v.min_severity, description: v.description, labels: parseLabels(v.labels),
        ...(family === 'siem' ? { url: orNull(v.url) } : {}),
        ...(kind === 'webhook' ? { format: v.format } : {}),
      };
      if (editing) return api(`v1/destinations/${encodeURIComponent(d.name)}`, { method: 'PATCH', body });
      return api('v1/destinations', { method: 'POST', body: { name: v.name, kind, ...body, ...(family === 'siem' && v.backfill ? { backfill: true } : {}) } });
    },
  });
  if (!saved) return;
  const missing = !saved.secret.present && saved.secret.need === 'required';
  toast(editing ? `Saved ${saved.name}.` : `Added ${saved.name}.${missing ? ` Put its credential in ${saved.secret.file}.` : ''}`);
  await refresh();
}

async function testDestination(d) {
  const out = await api(`v1/destinations/${encodeURIComponent(d.name)}/test`, { method: 'POST' });
  if (out.ok) toast(`Sent ${d.name} a test ${destFamily(d.kind) === 'chat' ? 'message' : 'event'}.`);
  else toast(`${d.name}: ${out.error}`, { tone: 'critical' });
  await refresh();
}

async function pauseDestination(d) {
  const pause = d.status !== 'paused';
  const done = await ask({
    title: pause ? `Pause ${d.name}?` : `Resume ${d.name}?`,
    text: pause ? 'It gets nothing until it is resumed, then everything it missed (alerts older than an hour excepted).' : 'It gets what it missed while it was paused, then what happens next.',
    tone: pause ? 'danger' : 'primary', iconName: pause ? 'minus' : 'play', confirm: pause ? 'Pause' : 'Resume',
    submit: () => api(`v1/destinations/${encodeURIComponent(d.name)}/${pause ? 'pause' : 'resume'}`, { method: 'POST' }),
  });
  if (!done) return;
  toast(pause ? `Paused ${d.name}.` : `Resumed ${d.name}.`);
  await refresh();
}

async function replayDestination(d) {
  const done = await ask({
    title: `Send ${d.name} the ledger again?`,
    text: 'From after the ledger entry you choose (0: from the start). The SIEM drops events it already has by their metadata.uid.',
    iconName: 'undo', confirm: 'Replay',
    fields: [{ id: 'after', label: 'After ledger entry', type: 'number', min: 0, value: 0, required: true }],
    submit: (v) => api(`v1/destinations/${encodeURIComponent(d.name)}/replay`, { method: 'POST', body: { after: Number(v.after) } }),
  });
  if (!done) return;
  toast(`${d.name} gets the ledger again from after entry ${done.delivery.cursor}.`);
  await refresh();
}

async function deleteDestination(d) {
  const done = await ask({
    title: `Delete ${d.name}?`,
    text: 'It gets nothing more. Its secret file stays where it is.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete destination', busy: 'Deleting…',
    submit: () => api(`v1/destinations/${encodeURIComponent(d.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted ${d.name}.`);
  await refresh();
}

/* ------------------------------------------------------------------ models */

const PROVIDER_KINDS = [
  ['openai', 'OpenAI'], ['anthropic', 'Anthropic'], ['gemini', 'Google Gemini'],
  ['openai-compatible', 'OpenAI-compatible server (vLLM, Ollama, LiteLLM, hosted APIs)'],
];

async function renderModels() {
  const [providers, usage, info, features] = await Promise.all([
    api('v1/models/providers'), api('v1/models/usage?days=7'), getInfo(), featureModes().catch(() => ({})),
  ]);
  const gateway = (info?.gateway_url || '').replace(/\/$/, '');
  return h('div', { class: 'page' },
    pageHead({
      title: 'Models',
      sub: "Model providers agents call through the gateway, at /llm/<provider>, with their AgentGov token instead of the provider's API key. Every prompt and answer is checked, and every call is metered.",
      actions: [
        can('admin') ? h('button', { type: 'button', class: 'btn btn--primary', 'data-focus-key': 'add-provider', onclick: guarded(() => providerForm(null)) }, icon('plus'), 'Add provider') : null,
        refreshButton(),
      ],
    }),
    features['model-gateway'] === 'off' ? callout('warning', 'power', h('span', {},
      h('strong', {}, 'The model gateway is off: '), 'no provider is published on the gateway. ', h('a', { href: '#/features' }, 'Features'), '.')) : null,
    providersCard(providers, gateway),
    budgetsCard(usage),
    spendCard(usage),
    usageCard(usage));
}

function providersCard(providers, gateway) {
  const body = providers.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
    h('caption', { class: 'sr-only' }, 'Model providers'),
    h('thead', {}, h('tr', {}, ['Provider', 'Status', 'Agents call', 'Prices (USD per 1M tokens)', ''].map((t) => h('th', { scope: 'col' }, t || h('span', { class: 'sr-only' }, 'Actions'))))),
    h('tbody', {}, providers.map((p) => h('tr', { 'data-provider': p.name },
      h('td', { 'data-label': 'Provider' }, h('span', { class: 'cell-title' }, p.name),
        h('div', { class: 'cell-sub' }, (PROVIDER_KINDS.find(([k]) => k === p.kind) || [p.kind, p.kind])[1], p.base_url ? ` at ${p.base_url}` : ''),
        h('div', { class: 'cell-sub' }, `Key file: ${p.key_file}`)),
      h('td', { 'data-label': 'Status' }, chip('server', p.status),
        h('div', { class: 'cell-sub' }, p.trust_level === 'verified' ? 'Verified: may receive personal data' : 'Unverified: personal data is masked')),
      h('td', { 'data-label': 'Agents call' }, copyable(`${gateway}${p.route}/v1/chat/completions`, `${p.name} endpoint`)),
      h('td', { 'data-label': 'Prices' }, Object.keys(p.prices || {}).length
        ? h('div', { class: 'chip-row' }, Object.entries(p.prices).map(([m, price]) => plainChip(`${m}: ${price.input} in, ${price.output} out`, { mono: true })))
        : h('span', { class: 'muted' }, 'None: cost is not counted')),
      h('td', { 'data-label': '' }, can('contain') ? h('div', { class: 'btn-row' },
        can('admin') ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `edit-${p.name}`, onclick: guarded(() => providerForm(p)) }, icon('edit'), 'Edit') : null,
        h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `block-${p.name}`, onclick: guarded(() => blockProvider(p)) },
          icon(p.status === 'blocked' ? 'undo' : 'ban'), p.status === 'blocked' ? 'Unblock' : 'Block'),
        can('admin') ? h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', 'data-focus-key': `delete-${p.name}`, onclick: guarded(() => deleteProvider(p)) }, icon('trash'), 'Delete') : null) : null))))))
    : emptyState('No model providers', "Add one, then put its API key where the gateway reads it. Agents call it with their own token and never see the key.");
  return card({ title: 'Providers', flush: Boolean(providers.length), body });
}

function budgetsCard(usage) {
  const rows = (usage.today || []).filter((b) => b.daily_token_budget != null);
  if (!rows.length) return null;
  return card({
    title: 'Budgets today',
    sub: `Tokens each agent used on ${usage.day} (UTC), against its daily budget`,
    body: h('ul', { class: 'risk-list', role: 'list' }, rows.map((b) => {
      const tone = b.over_budget ? 'critical' : 'accent';
      return h('li', {},
        h('a', { href: agentHref(b.agent_id), class: 'cell-title break' }, b.agent_name),
        h('span', { class: 'small' }, `${fmt(b.used_today)} of ${fmt(b.daily_token_budget)} tokens`,
          b.over_budget ? [' ', plainChip('Over budget', { tone: 'critical', iconName: 'ban', title: 'Its model calls are refused until the day ends (UTC)' })] : null),
        h('div', { class: 'meter', role: 'img', 'aria-label': `${fmt(b.used_today)} of ${fmt(b.daily_token_budget)} tokens`, style: `background: var(--neutral-tint)` },
          h('span', { style: `width:${b.daily_token_budget ? Math.min(100, (b.used_today / b.daily_token_budget) * 100) : 100}%; background:${TONE_COLOR[tone]}` })));
    })),
  });
}

// Usage added up per owner or per sponsor of the agents behind it.
function spendCard(usage) {
  const groups = { owner: usage.by_owner || [], sponsor: usage.by_sponsor || [] };
  if (!groups.owner.length) return null;
  const words = { owner: ['Owner', 'No owner'], sponsor: ['Sponsor', 'No sponsor'] };
  const table = (by) => h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
    h('caption', { class: 'sr-only' }, `Model usage per ${by}`),
    h('thead', {}, h('tr', {}, [words[by][0], 'Agents', 'Calls', 'Tokens', 'Cost'].map((c, i) => h('th', { scope: 'col', class: i ? 'num' : null }, c)))),
    h('tbody', {}, groups[by].map((g) => h('tr', {},
      h('td', { 'data-label': words[by][0] }, g[by] ? h('span', { class: 'break' }, g[by]) : h('span', { class: 'muted' }, words[by][1])),
      h('td', { 'data-label': 'Agents', class: 'num' }, fmt(g.agents)),
      h('td', { 'data-label': 'Calls', class: 'num' }, fmt(g.calls)),
      h('td', { 'data-label': 'Tokens', class: 'num' }, fmt(g.input_tokens + g.output_tokens)),
      h('td', { 'data-label': 'Cost', class: 'num' }, g.cost_usd ? `$${g.cost_usd.toFixed(4)}` : h('span', { class: 'muted' }, '—')))))));
  const body = h('div', {}, table('owner'));
  const choose = h('div', { class: 'segmented', role: 'radiogroup', 'aria-label': 'Add up per' },
    ['owner', 'sponsor'].map((by) => {
      const input = h('input', { type: 'radio', id: `spend-${by}`, name: 'spend-by', value: by, checked: by === 'owner', 'data-focus-key': `spend-${by}` });
      input.addEventListener('change', () => fill(body, table(by)));
      return h('label', { for: `spend-${by}` }, input, h('span', {}, words[by][0]));
    }));
  return card({
    title: 'Who is spending',
    sub: 'The last 7 days, per owner and per sponsor of the agents. An agent with several sponsors counts in full for each.',
    actions: [choose],
    flush: true,
    body,
  });
}

function usageCard(usage) {
  const t = usage.totals || {};
  const rows = usage.rows || [];
  return card({
    title: 'Usage, last 7 days',
    sub: rows.length ? `${plural(t.calls, 'call')}, ${fmt(t.refused)} refused · ${fmt(t.input_tokens)} tokens in, ${fmt(t.output_tokens)} out${t.cost_usd ? ` · $${t.cost_usd.toFixed(2)}` : ''}` : null,
    flush: Boolean(rows.length),
    body: rows.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
      h('caption', { class: 'sr-only' }, 'Model usage'),
      h('thead', {}, h('tr', {}, ['Day', 'Agent', 'Model', 'Calls', 'Tokens in', 'Tokens out', 'Cost'].map((c) => h('th', { scope: 'col', class: ['Calls', 'Tokens in', 'Tokens out', 'Cost'].includes(c) ? 'num' : null }, c)))),
      h('tbody', {}, rows.map((r) => h('tr', {},
        h('td', { 'data-label': 'Day' }, r.day),
        h('td', { 'data-label': 'Agent' }, r.agent_id ? agentLink(r.agent_id, r.agent_name) : h('span', { class: 'muted', title: 'Calls without an agent token (unknown callers in monitor mode)' }, 'Unidentified')),
        h('td', { 'data-label': 'Model' }, h('code', {}, `${r.provider}/${r.model || '?'}`)),
        h('td', { 'data-label': 'Calls', class: 'num' }, fmt(r.calls), r.refused ? h('div', { class: 'cell-sub' }, `${fmt(r.refused)} refused`) : null),
        h('td', { 'data-label': 'Tokens in', class: 'num' }, fmt(r.input_tokens)),
        h('td', { 'data-label': 'Tokens out', class: 'num' }, fmt(r.output_tokens)),
        h('td', { 'data-label': 'Cost', class: 'num' }, r.cost_usd ? `$${r.cost_usd.toFixed(4)}` : h('span', { class: 'muted' }, '—')))))))
      : emptyState('No model calls yet', 'Calls through the gateway show up here once the OpenTelemetry Collector forwards the gateway\'s access logs.'),
  });
}

function parsePrices(text) {
  const out = {};
  for (const line of String(text || '').split('\n').map((l) => l.trim()).filter(Boolean)) {
    const m = line.match(/^(.+?)\s*[:=]\s*([\d.]+)\s*,\s*([\d.]+)$/);
    if (!m) throw new Error(`Write each price as "model: input, output" in USD per million tokens ("${line}").`);
    out[m[1].trim()] = { input: Number(m[2]), output: Number(m[3]) };
  }
  return out;
}

function formatPrices(prices) {
  return Object.entries(prices || {}).map(([m, p]) => `${m}: ${p.input}, ${p.output}`).join('\n');
}

async function providerForm(p) {
  const editing = Boolean(p);
  const saved = await ask({
    title: editing ? `Edit ${p.name}` : 'Add a model provider',
    text: "The gateway reads the provider's API key from a file mounted into it; the key never enters AgentGov. Changes are recorded in the evidence ledger.",
    iconName: editing ? 'edit' : 'models', confirm: editing ? 'Save changes' : 'Add provider', wide: true,
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'openai', hint: `${NAME_HINT} Agents call it at /llm/<name>.` },
      { id: 'kind', label: 'Kind', type: 'select', value: p?.kind || 'openai', options: PROVIDER_KINDS.map(([value, label]) => ({ value, label })) },
      { id: 'base_url', label: 'Base URL', mono: true, value: p?.base_url || '', placeholder: 'http://vllm:8000/v1', hint: 'Only for an OpenAI-compatible server: its OpenAI API base, as an OpenAI SDK takes it.' },
      { id: 'key_file', label: 'Key file', mono: true, value: p && p.key_file !== `/model-keys/${p.name}` ? p.key_file : '', placeholder: '/model-keys/<name>', hint: 'Where the gateway reads the API key. Empty: /model-keys/<name>.' },
      { id: 'trust_level', label: 'Trust', type: 'select', value: p?.trust_level || 'unverified', options: [
        { value: 'unverified', label: 'Unverified: personal data in prompts is masked' },
        { value: 'verified', label: 'Verified (a data processing agreement covers it): personal data may be sent' },
      ] },
      { id: 'prices', label: 'Prices', type: 'code', rows: 2, value: formatPrices(p?.prices), placeholder: 'gpt-4o*: 2.5, 10', hint: 'One model pattern per line: USD per million input tokens, then output tokens.' },
      { id: 'description', label: 'Description', type: 'textarea', value: p?.description || '' },
    ].filter(Boolean),
    submit: (v) => {
      const body = {
        kind: v.kind, base_url: v.kind === 'openai-compatible' ? orNull(v.base_url) : null, key_file: orNull(v.key_file),
        trust_level: v.trust_level, prices: parsePrices(v.prices), description: v.description,
      };
      if (editing) return api(`v1/models/providers/${encodeURIComponent(p.name)}`, { method: 'PATCH', body });
      return api('v1/models/providers', { method: 'POST', body: { name: v.name, ...body } });
    },
  });
  if (!saved) return;
  toast(editing ? `Saved ${saved.name}.` : `Added ${saved.name}. Agents call it at ${saved.route} once the gateway has its key.`);
  await refresh();
}

async function blockProvider(p) {
  const block = p.status !== 'blocked';
  const done = await ask({
    title: block ? `Block ${p.name}?` : `Unblock ${p.name}?`,
    text: block ? 'Every model call to it is refused within a second, for every agent.' : 'Agents with access may call it again.',
    tone: block ? 'danger' : 'primary', iconName: block ? 'ban' : 'undo', confirm: block ? 'Block' : 'Unblock',
    submit: () => api(`v1/models/providers/${encodeURIComponent(p.name)}/${block ? 'block' : 'unblock'}`, { method: 'POST' }),
  });
  if (!done) return;
  toast(block ? `Blocked ${p.name}.` : `Unblocked ${p.name}.`);
  await refresh();
}

async function deleteProvider(p) {
  const done = await ask({
    title: `Delete ${p.name}?`,
    text: 'Its route goes from the gateway. Its usage history stays.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete provider', busy: 'Deleting…',
    submit: () => api(`v1/models/providers/${encodeURIComponent(p.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted ${p.name}.`);
  await refresh();
}

/* -------------------------------------------------------------------- go */

boot();

/* ---------------------------------------------------------- developer tools */

const SIGHTING_STATUS = {
  approved: ['Approved', 'good', 'check-circle', 'An approved tool server'],
  bypass: ['Past the gateway', 'critical', 'triangle', "A gateway server's own address: calls skip the gateway's controls"],
  blocked: ['Blocked', 'critical', 'ban', 'A blocked tool server'],
  unapproved: ['Not approved', 'warning', 'triangle', 'Not an approved tool server'],
};

async function renderDevelopers() {
  const [registry, sightings, features] = await Promise.all([
    api('v1/mcp/registry'), api('v1/mcp/sightings'), featureModes().catch(() => ({})),
  ]);
  return h('div', { class: 'page' },
    pageHead({
      title: 'Developer tools',
      sub: "Which MCP servers developers' MCP clients may use, served as an MCP registry for GitHub Copilot and VS Code, and which ones developers have set up on their machines.",
      actions: [refreshButton()],
    }),
    registryCard(registry),
    sightingsCard(sightings, features));
}

function registryCard(registry) {
  const servers = registry.servers || [];
  const where = (server) => [
    ...(server.remotes || []).map((r) => h('code', { class: 'break' }, r.url)),
    ...(server.packages || []).map((pk) => plainChip(`${pk.registryType}:${pk.identifier}${pk.version ? `@${pk.version}` : ''}`, { mono: true })),
  ];
  const download = h('button', { type: 'button', class: 'btn', 'data-focus-key': 'managed-settings' }, icon('download'), 'managed-settings.json');
  download.addEventListener('click', guarded(async () => {
    await saveDownload('v1/mcp/managed-settings', 'managed-settings.json');
    toast('Saved managed-settings.json: the same servers as an allowlist, by URL and command.');
  }));
  return card({
    title: 'MCP registry',
    sub: "Tool servers listed for developers. In GitHub's AI controls (MCP), set this as the MCP registry URL and choose Registry only: Copilot then runs only these servers.",
    actions: [download],
    body: [
      registry.enabled ? null : callout('warning', 'power', h('span', {}, h('strong', {}, 'The registry is off: '),
        "developers' clients can't read it. It is served without credentials, as they read it; turn on ", h('code', {}, 'mcp-registry'), ' on the ', h('a', { href: '#/features' }, 'Features'), ' page.')),
      facts([
        ['Registry URL', copyable(registry.url, 'registry URL')],
        ['Names', h('span', {}, h('code', {}, `${registry.namespace}/<server>`))],
      ]),
      servers.length
        ? h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
          h('caption', { class: 'sr-only' }, 'Servers in the MCP registry'),
          h('thead', {}, h('tr', {}, ['Name', 'Version', 'Developers connect to', 'Status'].map((c) => h('th', { scope: 'col' }, c)))),
          h('tbody', {}, servers.map((entry) => h('tr', {},
            h('td', { 'data-label': 'Name' }, h('code', { class: 'break' }, entry.server.name)),
            h('td', { 'data-label': 'Version' }, entry.server.version),
            h('td', { 'data-label': 'Developers connect to' }, h('div', { class: 'stack', style: 'gap:4px' }, where(entry.server))),
            h('td', { 'data-label': 'Status' }, entry.server._meta?.['dev.agentgov/server']?.throughGateway
              ? plainChip('Through the gateway', { tone: 'good', iconName: 'shield' })
              : plainChip('Developers only', { iconName: 'developers' })))))))
        : emptyState('No tool servers are listed for developers', 'Edit a tool server and tick Developers, or register one only for developers, with its address or its packages.'),
    ],
  });
}

function sightingsCard(groups, features) {
  const command = 'agentgov mcp scan --report';
  const body = groups.length
    ? h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
      h('caption', { class: 'sr-only' }, "MCP servers on developers' machines"),
      h('thead', {}, h('tr', {}, ['Status', 'Server', 'Set up as', 'Machines', 'Last reported', ''].map((c) => h('th', { scope: 'col', class: c === 'Machines' ? 'num' : null }, c || h('span', { class: 'sr-only' }, 'Actions'))))),
      h('tbody', {}, groups.map((g) => {
        const [label, tone, ic, title] = SIGHTING_STATUS[g.status] || [humanize(g.status), 'neutral', 'info', ''];
        const what = g.url || (g.command || []).join(' ') || g.identity;
        return h('tr', {},
          h('td', { 'data-label': 'Status' }, plainChip(label, { tone, iconName: ic, title }), g.server ? h('div', { class: 'cell-sub' }, g.server) : null),
          h('td', { 'data-label': 'Server' }, h('code', { class: 'break' }, what)),
          h('td', { 'data-label': 'Set up as' }, h('span', { class: 'break' }, g.names.join(', ')), h('div', { class: 'cell-sub' }, g.clients.join(', '))),
          h('td', { 'data-label': 'Machines', class: 'num' }, fmt(g.machines), h('div', { class: 'cell-sub' }, plural(g.users, 'person', 'people'))),
          h('td', { 'data-label': 'Last reported' }, timeEl(g.last_seen_at)),
          h('td', { 'data-label': '' }, g.status === 'unapproved' && can('admin') && registerDraft(g)
            ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `register-${g.identity}`, onclick: guarded(() => registerSighting(g)) }, icon('plus'), 'Register')
            : null));
      }))))
    : emptyState('No reports yet', h('span', {}, 'Developers, or your device management, run ', h('code', {}, command), ' with an API key of the registrar role.'));
  return card({
    title: "Set up on developers' machines",
    sub: 'The MCP servers in VS Code, Copilot, Claude, Cursor and other clients, as developers report them, against the approved tool servers. Credentials never leave their machines.',
    actions: [copyable(command, 'scan command')],
    flush: Boolean(groups.length),
    body: [
      features['mcp-discovery'] === 'off' ? callout('warning', 'power', h('span', {}, h('strong', {}, 'Reports are off. '), 'Turn on ', h('code', {}, 'mcp-discovery'), ' on the ', h('a', { href: '#/features' }, 'Features'), ' page.')) : null,
      body,
    ],
  });
}

// A tool server registration started from what developers set up: their address, or
// the package they run.
function registerDraft(g) {
  const [kind, ...rest] = g.identity.split(':');
  const value = rest.join(':');
  const name = (g.names[0] || '').toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63);
  if (kind === 'url') return { name, url: g.url || value, gateway: false, developers: true };
  if (['npm', 'pypi', 'oci'].includes(kind)) return { name, gateway: false, developers: true, packages: [{ registry_type: kind, identifier: value }] };
  return null;
}

async function registerSighting(g) {
  const created = await toolserverForm(null, registerDraft(g));
  if (!created) return;
  toast(`Registered ${created.name}. Its finding resolves once AgentGov compares the reports again.`);
  await refresh();
}
