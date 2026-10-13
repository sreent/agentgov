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
  ticket: 'M4 7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v3a2 2 0 0 0 0 4v3a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-3a2 2 0 0 0 0-4zM10 5v2M10 11v2M10 17v2',
  compliance: 'M7 3h7l5 5v13H7zM14 3v5h5M10 14l2 2 4-4',
  register: 'M6 4h12v17H6zM9 8h6M9 12h6M9 16h4',
  teams: 'M9 7a3 3 0 1 0 6 0a3 3 0 1 0-6 0M3 20c0-3.3 2.7-6 6-6h6c3.3 0 6 2.7 6 6M4 10a2 2 0 1 0 4 0a2 2 0 1 0-4 0M16 10a2 2 0 1 0 4 0a2 2 0 1 0-4 0',
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

// Auditors, and no other role: they read reports, so their first page is Compliance.
function isAuditor() {
  const roles = me?.roles || [];
  return roles.includes('auditor') && !roles.some((r) => ['admin', 'approver', 'secops'].includes(r));
}

// The page someone starts on, by what they do here.
function home() {
  if (isPerson()) return personHome();
  return isAuditor() ? '#/ledger/compliance' : '#/overview';
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
  // An edit made from an older copy (the form sends the version it was opened with).
  if (status === 412) return 'Someone else saved a change to this while you had it open, so yours would have undone theirs. Close this, open it again to see their change, and make yours on top.';
  if (status === 400 || status === 422) return `The control plane rejected the request. ${d}`.trim();
  if (status >= 502 && status <= 504) return d || `A service behind the control plane did not respond (HTTP ${status}).`;
  if (status >= 500) return `The control plane hit an error (HTTP ${status}). ${d}`.trim();
  return d || `The request failed (HTTP ${status}).`;
}

async function api(path, { method = 'GET', body, text, contentType = 'text/plain', raw = false, auth = true, signingIn = false, ifMatch } = {}) {
  // Required on writes authenticated by the session cookie (other sites cannot set it).
  const headers = { Accept: 'application/json', 'X-AgentGov-CSRF': '1' };
  if (auth && token) headers.Authorization = `Bearer ${token}`;
  // The version an edit was made from: the control plane refuses it if that's old (412).
  if (ifMatch != null) headers['If-Match'] = `"${ifMatch}"`;
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
  access: {
    requested: ['warning', 'clock', 'Requested'],
    active: ['good', 'check-circle', 'Active'],
    expired: ['serious', 'triangle', 'Expired'],
    denied: ['neutral', 'ban', 'Denied'],
    revoked: ['neutral', 'minus', 'Revoked'],
    renewed: ['neutral', 'check-double', 'Renewed'],
  },
  entra_access: {
    delivered: ['good', 'check-circle', 'Delivered'],
    delivering: ['warning', 'clock', 'Delivering'],
    partiallyDelivered: ['warning', 'triangle', 'Partly delivered'],
    deliveryFailed: ['critical', 'octagon', 'Delivery failed'],
  },
  rule: {
    waiting: ['neutral', 'clock', 'Waiting'],
    due: ['warning', 'alert-circle', 'Due'],
    acted: ['serious', 'check-double', 'Acted on'],
    exempt: ['neutral', 'shield-check', 'Held back'],
    cannot: ['neutral', 'ban', "Can't act"],
    monitored: ['neutral', 'eye', 'Would have acted'],
    off: ['neutral', 'minus', 'Off'],
  },
  classification: {
    'high-risk': ['serious', 'triangle', 'High-risk'],
    transparency: ['warning', 'eye', 'Transparency obligations'],
    minimal: ['good', 'check-circle', 'Minimal risk'],
    prohibited: ['critical', 'octagon', 'Prohibited practice'],
    'not-ai-system': ['neutral', 'minus', 'Not an AI system'],
    none: ['neutral', 'info', 'Not classified'],
  },
  compliance: {
    in_place: ['good', 'check-circle', 'In place'],
    partly: ['warning', 'alert-circle', 'Partly'],
    configured: ['warning', 'eye', 'Configured, not observed'],
    not_set_up: ['neutral', 'minus', 'Not set up'],
    attention: ['critical', 'octagon', 'Needs attention'],
    outside: ['neutral', 'info', 'Outside AgentGov'],
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
    partial: ['warning', 'triangle', 'Partly read'],
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
  ticket: {
    pending: ['neutral', 'clock', 'Opening'],
    open: ['good', 'check-circle', 'Kept in step'],
    closed: ['neutral', 'minus', 'Closed'],
    failed: ['critical', 'octagon', "Couldn't open"],
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
  if (f.type === 'section') return h('h3', { class: 'dialog-section', id: f.id ? `dlg-${f.id}` : null }, f.label);
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
  fields = [], extra, after, wide = false, submit, busy = 'Saving…', onReady,
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
      after || null,
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
    // How many are open, and whether any is critical or high: counted by the control
    // plane, however many there are.
    const count = async (query) => {
      const res = await api(`v1/findings?status=open&limit=1${query}`, { raw: true });
      return Number(res.headers.get('X-Total-Count') || 0);
    };
    const [waiting, open, critical, high] = await Promise.all([
      api('v1/inbox'), count(''), count('&severity=critical'), count('&severity=high'),
    ]);
    updateBadges({ pendingApprovals: waiting.total, findings: { open, by_severity: { critical, high } } });
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
  { re: /^\/findings\/teams$/, nav: 'teams', title: 'Teams', render: renderTeams },
  { re: /^\/findings\/types$/, nav: 'findings', title: 'Finding types', render: renderFindingTypes },
  { re: /^\/findings\/([^/]+)$/, nav: 'findings', title: 'Finding', render: renderFinding },
  { re: /^\/policies$/, nav: 'policies', title: 'Policies', render: renderPolicies },
  { re: /^\/ledger$/, nav: 'ledger', title: 'Ledger', render: renderLedger },
  { re: /^\/ledger\/compliance$/, nav: 'compliance', title: 'Compliance', render: renderCompliance },
  { re: /^\/ledger\/register$/, nav: 'register', title: 'Register', render: renderRegister },
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
  if (!page) { location.replace(home()); return; }
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
  // A group of the menu shows only with something in it.
  for (const list of document.querySelectorAll('#nav .nav-list')) {
    const empty = [...list.children].every((li) => li.hidden);
    list.hidden = empty;
    const label = list.getAttribute('aria-labelledby');
    if (label) document.getElementById(label).hidden = empty;
  }
  $('#nav-findings-label').textContent = isPerson() ? 'Your issues' : 'Findings';
  if (!location.hash || location.hash === '#' || location.hash === '#/') history.replaceState(null, '', home());
  route();
  refreshBadges();
  getInfo().then(async (info) => {
    if (!info) return;
    const who = me ? ` · signed in as ${me.actor}${me.via === 'session' ? ' (single sign-on)' : ''}` : '';
    // Whether the control plane reaches OPA now, not only whether it is set up.
    const components = await api('v1/components').catch(() => null);
    const opa = components?.control_plane?.opa;
    const opaWords = !info.opa ? 'not configured' : opa ? (opa.ok ? 'reachable' : 'unreachable') : 'set up';
    $('#nav-meta').textContent = `AgentGov ${info.version} · ${info.identity_provider ? 'Keycloak identities' : 'no identity provider'} · OPA ${opaWords}${who}`;
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

// An agent another platform runs, which AgentGov read from it (not through the gateway).
function isPlatformAgent(a) {
  return (a.source || '').startsWith('platform:');
}

// What the unmanaged agents are: found on platforms, seen in traffic, or both.
function unmanagedNote(all, onPlatforms) {
  if (!all) return 'No unregistered agents seen';
  if (onPlatforms === all) return 'Found on your platforms, not reviewed yet';
  if (!onPlatforms) return 'Seen at runtime, never registered';
  return `${fmt(onPlatforms)} found on your platforms, ${fmt(all - onPlatforms)} seen at runtime`;
}

async function renderOverview() {
  const [ov, info, features, start] = await Promise.all([
    api('v1/overview'), getInfo(), api('v1/features').then((v) => v.features).catch(() => null),
    api('v1/start').catch(() => null),
  ]);
  updateBadges({ findings: ov.findings });
  // The gateway's panels once agents may call through it, or have: until then they would
  // show nothing but zeros.
  const gateway = (features || []).some((f) => f.key === 'mcp-gateway' && f.mode !== 'off')
    || (ov.activity || []).some((d) => d.tool_calls || d.model_calls) || (ov.recent_blocks || []).length > 0;
  return h('div', { class: 'page' },
    pageHead({
      title: 'Overview',
      sub: gateway ? 'Agent inventory, policy decisions and evidence for this control plane.' : 'Your agents, what to look at, and the evidence for this control plane.',
      actions: [ledgerBadge(ov.ledger), refreshButton()],
    }),
    startCard(start),
    kpiTiles(ov),
    gateway ? h('div', { class: 'grid-2 grid-2--even' }, activityCard(ov.activity || []), decisionsCard(ov.decisions_24h || {})) : null,
    gateway ? h('div', { class: 'grid-2 grid-2--even' }, recentBlocksCard(ov.recent_blocks || []), riskyCard(ov.top_risky || []))
      : riskyCard(ov.top_risky || []),
    controlPlaneCard(ov, info, features, gateway));
}

// Where to look for each place's agents, from the checklist.
const START_LINKS = { gateway: '#/agents' };

// Until it is done or hidden: where the organisation's agents are, then each step to a
// first useful day (docs/administration.md#start-here).
function startCard(st) {
  if (!st || st.hidden || st.done) return null;
  const admin = can('admin');
  const choose = guarded(async () => {
    const done = await ask({
      title: 'Where are your agents?',
      text: 'AgentGov turns on what reads these places and turns off what reads the others. Change it here any time.',
      iconName: 'platforms', confirm: 'Save',
      fields: st.choices.map((c) => ({ id: c.place, type: 'checkbox', label: c.name, value: st.places.includes(c.place) })),
      submit: (v) => api('v1/start', { method: 'PUT', body: { places: st.choices.map((c) => c.place).filter((p) => v[p]) } }),
    });
    if (done) await refresh();
  });
  const hide = guarded(async () => {
    await api('v1/start', { method: 'PUT', body: { hidden: true } });
    await refresh();
  });
  if (!st.places.length) {
    return card({
      title: 'Start here', cls: 'start-card',
      body: h('div', { class: 'stack' },
        h('p', {}, 'Tell AgentGov where your agents are: Copilot Studio, Microsoft 365, AWS, Google Cloud, Salesforce, Databricks, Microsoft Foundry, or your own agents through its gateway. It turns on only what reads those places.'),
        admin ? h('div', { class: 'btn-row' }, h('button', { type: 'button', class: 'btn btn--primary', onclick: choose }, 'Where are your agents?'))
          : h('p', { class: 'muted' }, 'An administrator answers this.')),
    });
  }
  const links = {
    team: '#/findings/teams', review: '#/agents?status=discovered', owners: '#/agents?owner=none',
  };
  const next = st.steps.find((x) => !x.done);
  const rows = st.steps.map((x) => {
    const how = x.key === 'agents' && !x.done ? h('ul', { class: 'start-how' }, (x.how || []).map((w) =>
      h('li', {}, h('a', { href: START_LINKS[w.place] || '#/platforms' }, w.name), `: ${w.how}`))) : null;
    const target = links[x.key];
    return h('li', { class: 'start-step', 'data-done': String(x.done), 'aria-current': x === next ? 'step' : null },
      icon(x.done ? 'check-circle' : x === next ? 'arrow' : 'minus', { cls: x.done ? 't-good' : x === next ? null : 'muted' }),
      h('div', {},
        h('strong', {}, !x.done && target ? h('a', { href: target }, x.title) : x.title),
        x.detail ? h('span', { class: 'muted' }, ` · ${x.detail}`) : null,
        how));
  });
  return card({
    title: 'Start here', cls: 'start-card',
    sub: `${st.steps.filter((x) => x.done).length} of ${st.steps.length} done`,
    actions: admin ? [
      h('button', { type: 'button', class: 'btn btn--sm btn--ghost', onclick: choose }, 'Change where'),
      h('button', { type: 'button', class: 'btn btn--sm btn--ghost', onclick: hide }, 'Hide'),
    ] : null,
    body: h('ol', { class: 'start-steps' }, rows),
  });
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

function controlPlaneCard(ov, info, features, gateway = true) {
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
      // Tool servers and the gateway, once agents may call through it.
      gateway ? cell('Tool servers', plural(ts.total || 0, 'server'),
        `${plural(ts.tools || 0, 'tool')} in catalogs · ${fmt(ts.pending)} pending · ${fmt(ts.blocked)} blocked`, '#/toolservers') : null,
      cell('Policy bundle', ov.opa?.bundle_revision ? h('span', { class: 'hash', title: `Bundle revision ${ov.opa.bundle_revision}` }, `rev ${String(ov.opa.bundle_revision).slice(0, 12)}`) : 'Not built',
        opaNote(ov.opa)),
      cell('Replicas', replicasValue(ov.replicas), replicasNote(ov.replicas)),
      cell('Evidence ledger', ov.ledger ? plural(ov.ledger.checked, 'entry', 'entries') : 'Not verified',
        ov.witness?.rewound
          ? h('span', { style: 'color: var(--critical-ink)' }, 'Entries are missing: the database was restored')
          : ov.ledger?.head ? ['Head ', h('span', { class: 'hash', title: ov.ledger.head }, shortHash(ov.ledger.head))] : null, '#/ledger'),
      gateway ? cell('Gateway', info?.gateway_url ? copyable(info.gateway_url, 'gateway URL') : 'Not configured',
        features ? [
          features.find((f) => f.key === 'unknown-callers')?.mode === 'monitor' ? 'Unknown callers let through' : 'Unknown callers refused',
          ' · ', h('a', { href: '#/features' }, featureSummary(features)),
        ] : null)
        : cell('Features', features ? h('a', { href: '#/features' }, featureSummary(features)) : 'Unknown', 'No gateway: AgentGov reads your platforms')));
}

// The control plane's replicas, and the one that runs the scheduled work.
function replicasValue(replicas) {
  return replicas?.length ? plural(replicas.length, 'replica') : 'Unknown';
}

function replicasNote(replicas) {
  if (!replicas?.length) return null;
  if (replicas[0].database === 'sqlite') return 'One process, on SQLite';
  const leader = replicas.find((r) => r.leader);
  // The replica answering has lost its connection for hearing the others' changes.
  const apart = replicas.some((r) => r.this && r.listening === false);
  return [
    leader ? ['Leader ', h('code', {}, leader.name)] : 'No leader at the moment',
    apart ? h('span', { class: 'tone-text-warning' }, ' · this replica is out of touch with the others') : null,
  ];
}

// When the OPA instances last reported, and whether they all run the current bundle.
function opaNote(opa) {
  const instances = opa?.instances || [];
  if (!opa?.last_status_at) return 'No OPA instance has reported yet';
  const behind = instances.filter((i) => i.revision && i.revision !== opa.bundle_revision).length;
  return [
    instances.length > 1 ? `${instances.length} OPA instances; the last reported ` : 'OPA reported ',
    timeEl(opa.last_status_at),
    behind ? h('span', { class: 'tone-text-warning' }, ` · ${plural(behind, 'instance')} on an earlier bundle`) : null,
  ];
}

/* ------------------------------------------------------------------ agents */

const AGENT_STATUS_FILTERS = [
  ['all', 'All'], ['active', 'Active'], ['pending', 'Pending'], ['blocked', 'Blocked'],
  ['discovered', 'Discovered'], ['deleted', 'Deleted'],
];

// How the agents table sorts: by a column, or by "-" and a column the other way round.
const AGENT_SORTS = {
  name: (a) => a.name,
  status: (a) => AGENT_STATUS_FILTERS.findIndex(([k]) => k === a.status),
  risk: (a) => a.risk?.score ?? 0,
  owner: (a) => a.owner || '',
  blueprint: (a) => a.blueprint || platformOf(a) || '',
  last_seen: (a) => a.last_seen_at || '',
};
// The columns whose first sort puts the most first: the riskiest, the most recently seen.
const SORTS_DOWN = new Set(['risk', 'last_seen']);
const RISK_FILTERS = [['', 'Any risk'], ['elevated', 'High or critical'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']];
const WHERE_WORDS = { registered: 'Registered in AgentGov', discovered: 'Discovered at runtime' };

// Rows in the order a sort names, those without a value last either way; ties by name.
function sortRows(rows, sort, keys) {
  const down = sort.startsWith('-');
  const get = keys[sort.replace(/^-/, '')] || keys.name;
  const blank = (v) => v === '' || v == null;
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
function nextSort(sort, key) {
  if (sort === key) return `-${key}`;
  if (sort === `-${key}`) return key;
  return SORTS_DOWN.has(key) ? `-${key}` : key;
}

// Where an agent is, for the filter: on a platform, registered here, or discovered at runtime.
function agentWhere(a) {
  const source = a.source || 'registered';
  return source.startsWith('discovered:') ? 'discovered' : source;
}

// Re-render part of a page, keeping the focus on the control that had it.
function keepFocus(render) {
  const key = document.activeElement?.closest?.('[data-focus-key]')?.dataset.focusKey;
  render();
  if (key) document.querySelector(`#main [data-focus-key="${CSS.escape(key)}"]`)?.focus({ preventScroll: true });
}

// A spreadsheet's file of what a page shows: a header, then a line each. A cell a spreadsheet
// would take for a formula (names and titles come from the platforms) is kept as text.
function csvCell(value) {
  let text = value == null ? '' : Array.isArray(value) ? value.join('; ') : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function saveCsv(name, columns, rows) {
  const lines = [columns.map(([label]) => csvCell(label)).join(','),
    ...rows.map((row) => columns.map(([, get]) => csvCell(get(row))).join(','))];
  // A byte-order mark, so spreadsheets read it as UTF-8.
  const blob = new Blob([`﻿${lines.join('\r\n')}\r\n`], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = h('a', { href: url, download: `${name}-${fileStamp()}.csv`, hidden: true });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

const AGENT_CSV = [
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

async function renderAgents({ params }) {
  const state = {
    status: params.get('status') || 'all',
    owner: params.get('owner') || '',
    risk: params.get('risk') || '',
    source: params.get('source') || '',
    q: params.get('q') || '',
    sort: params.get('sort') || 'name',
  };
  const load = (q) => api(`v1/agents?include_deleted=true${q ? `&q=${encodeURIComponent(q)}` : ''}`);
  let agents = await load(state.q);
  // Those chosen for an action on many at once, by ID: only ever among those shown.
  const selected = new Set();
  const selecting = can('admin') || can('contain') || can('approve');
  let shown = [];

  const tableHost = h('div', {});
  const countEl = h('p', { class: 'result-count', 'aria-live': 'polite' });
  const chipHost = h('div', { class: 'seg', role: 'group', 'aria-label': 'Filter by status' });
  const adoptHost = h('div', {});
  const bulkHost = h('div', {});
  const search = h('input', {
    type: 'search', id: 'agent-search', placeholder: 'Search names and descriptions', value: state.q,
    'data-focus-key': 'agent-search', autocomplete: 'off',
  });
  const filter = (id, label) => {
    const control = h('select', { id, 'data-focus-key': id });
    return [control, h('div', { class: 'field', style: 'flex:0 1 220px' }, h('label', { for: id, class: 'sr-only' }, label), control)];
  };
  const [whereSelect, whereField] = filter('agent-where', 'Where it runs');
  const [riskSelect, riskField] = filter('agent-risk', 'Risk');
  const [ownerSelect, ownerField] = filter('agent-owner', 'Owner');
  const csvButton = h('button', {
    type: 'button', class: 'btn btn--sm btn--ghost', 'data-focus-key': 'agents-csv',
    title: 'The agents shown, as a spreadsheet', onclick: () => saveCsv('agentgov-agents', AGENT_CSV, shown),
  }, icon('download'), 'Download CSV');

  function sync() {
    setHashQuiet('/agents', {
      status: state.status === 'all' ? '' : state.status, owner: state.owner, risk: state.risk,
      source: state.source, q: state.q, sort: state.sort === 'name' ? '' : state.sort,
    });
  }

  // A filter's choices; the one chosen stays among them even when nothing matches it now.
  function fill(control, choices, current, labelOf = (v) => v) {
    const all = current && !choices.some(([v]) => v === current) ? [...choices, [current, labelOf(current)]] : choices;
    control.replaceChildren(...all.map(([value, label]) => h('option', { value, selected: value === current }, label)));
  }

  function apply() {
    const counts = countBy(agents, 'status');
    const live = agents.filter((a) => a.status !== 'deleted').length;
    chipHost.replaceChildren(...AGENT_STATUS_FILTERS.map(([key, label]) => {
      const n = key === 'all' ? live : counts[key] || 0;
      return h('button', {
        type: 'button', class: 'seg-btn', 'aria-pressed': String(state.status === key), 'data-focus-key': `status-${key}`,
        onclick: () => { state.status = key; keepFocus(apply); sync(); },
      }, label, h('span', { class: 'count' }, fmt(n)));
    }));
    const inStatus = agents.filter((a) => (state.status === 'all' ? a.status !== 'deleted' : a.status === state.status));
    const whereLabel = (w) => WHERE_WORDS[w] || PLATFORM_SOURCES[w] || w;
    const wheres = countBy(inStatus, agentWhere);
    fill(whereSelect, [['', 'Anywhere'], ...Object.keys(wheres).sort((x, y) => whereLabel(x).localeCompare(whereLabel(y)))
      .map((w) => [w, `${whereLabel(w)} (${fmt(wheres[w])})`])], state.source, whereLabel);
    fill(riskSelect, RISK_FILTERS, state.risk);
    const owners = countBy(inStatus.filter((a) => a.owner), 'owner');
    fill(ownerSelect, [['', 'Any owner'], ['none', 'Without an owner'],
      ...Object.keys(owners).sort((x, y) => x.localeCompare(y)).map((o) => [o, `${o} (${fmt(owners[o])})`])], state.owner);

    let rows = inStatus;
    if (state.owner === 'none') rows = rows.filter((a) => !a.owner && (a.status !== 'discovered' || isPlatformAgent(a)));
    else if (state.owner) rows = rows.filter((a) => a.owner === state.owner);
    if (state.risk === 'elevated') rows = rows.filter((a) => ['high', 'critical'].includes(a.risk?.level));
    else if (state.risk) rows = rows.filter((a) => (a.risk?.level || 'low') === state.risk);
    if (state.source) rows = rows.filter((a) => agentWhere(a) === state.source);
    rows = sortRows(rows, state.sort, AGENT_SORTS);
    shown = rows;
    for (const id of [...selected]) if (!rows.some((a) => a.id === id)) selected.delete(id);
    countEl.textContent = plural(rows.length, 'agent');
    csvButton.disabled = !rows.length;
    const adoptable = rows.filter((a) => a.status === 'discovered');
    adoptHost.replaceChildren(can('admin') && adoptable.length > 1 && !selected.size
      ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'adopt-many', onclick: guarded(() => adoptMany(adoptable)) },
        icon('user-check'), `Adopt ${plural(adoptable.length, 'agent')}…`)
      : '');
    const onSelect = (ids, on) => {
      for (const id of ids) { if (on) selected.add(id); else selected.delete(id); }
      keepFocus(apply);
    };
    bulkHost.replaceChildren(selecting && rows.length
      ? agentBulkBar(rows, selected, onSelect, () => { selected.clear(); keepFocus(apply); })
      : '');
    tableHost.replaceChildren(rows.length ? agentsTable(rows, {
      sort: state.sort,
      onSort: (key) => { state.sort = nextSort(state.sort, key); keepFocus(apply); sync(); },
      selected: selecting ? selected : null,
      onSelect,
    }) : emptyState('No agents match these filters',
      state.q ? `Nothing matches "${state.q}".` : 'Try another status, or clear the filters.',
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

  for (const [control, key] of [[whereSelect, 'source'], [riskSelect, 'risk'], [ownerSelect, 'owner']]) {
    control.addEventListener('change', () => { state[key] = control.value; keepFocus(apply); sync(); });
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
      chipHost),
    h('div', { class: 'filters' }, whereField, riskField, ownerField, countEl, adoptHost, csvButton),
    bulkHost,
    h('section', { class: 'card', 'aria-label': 'Agent list' }, tableHost));
}

// The control plane takes 500 at a time: more are sent in turns, and the answers put together.
const AT_ONCE = 500;
async function inTurns(path, body, key) {
  const out = { done: [], left: [] };
  for (let i = 0; i < body[key].length; i += AT_ONCE) {
    const part = await api(path, { method: 'POST', body: { ...body, [key]: body[key].slice(i, i + AT_ONCE) } });
    out.done.push(...part.done);
    out.left.push(...part.left);
  }
  return out;
}

// What an action on many at once did: a word when all were done; otherwise those left as
// they were, and why.
async function manyDone(result, verb, noun) {
  const done = result.done?.length || 0;
  const left = result.left || [];
  if (!left.length) {
    toast(`${verb} ${plural(done, noun)}.`);
    return;
  }
  // Those left for the same reason, together: often all of them.
  const byWhy = new Map();
  for (const x of left) {
    const why = cap(x.why);
    if (!byWhy.has(why)) byWhy.set(why, []);
    byWhy.get(why).push(x.title || x[noun]);
  }
  await ask({
    title: done ? `${verb} ${fmt(done)} of ${plural(done + left.length, noun)}` : `No ${noun} was ${verb.toLowerCase()}`,
    text: `${left.length === 1 ? 'This one was' : `These ${fmt(left.length)} were`} left as ${left.length === 1 ? 'it was' : 'they were'}:`,
    iconName: done ? 'info' : 'alert-circle', confirm: 'OK', cancel: null, wide: true,
    extra: h('ul', { class: 'apply-results', role: 'list' }, [...byWhy].map(([why, names]) => h('li', { class: 'left-group' },
      h('strong', {}, names.length > 1 ? `${why} (${fmt(names.length)})` : why),
      h('span', { class: 'muted break' }, names.join(', '))))),
  });
}

const AGENTS_AT_ONCE = {
  approve: { verb: 'Approved', text: 'Each becomes active and can call the tools its blueprint and grants allow. Each needs a sponsor at least: those without one stay pending.' },
  block: { verb: 'Blocked', text: 'This is the kill switch. The gateway refuses every call from them as soon as OPA loads the updated policy bundle, usually within seconds. You can unblock them later.' },
  unblock: { verb: 'Unblocked', text: 'Calls from them will be evaluated against policy again.' },
  delete: { verb: 'Deleted', text: 'They leave the inventory and policy denies all of their calls. Deleted agents can be restored.' },
  restore: { verb: 'Restored', text: 'They come back as pending review. Approve them to make them active again.' },
};

// The actions on the agents chosen: each offered when it fits some of them, and done to those.
// With none chosen, on a narrow screen (where the table has no header), a box to choose all.
function agentBulkBar(rows, selected, onSelect, clear) {
  const chosen = rows.filter((a) => selected.has(a.id));
  if (!chosen.length) {
    return h('div', { class: 'bulk-bar bulk-bar--idle bulk-bar--narrow' },
      h('label', { class: 'check' }, h('input', {
        type: 'checkbox', 'data-focus-key': 'choose-all-narrow', onchange: (e) => onSelect(rows.map((a) => a.id), e.target.checked),
      }), `Choose all ${plural(rows.length, 'agent')} shown`));
  }
  const admin = can('admin');
  const contain = admin || can('contain');
  const fits = (action) => chosen.filter((a) => (ACTIONS_BY_STATUS[a.status] || []).includes(action));
  const buttons = [];
  const offer = (action, label, iconName, cls = '') => {
    const n = fits(action).length;
    if (!n) return;
    buttons.push(h('button', {
      type: 'button', class: `btn btn--sm ${cls}`, 'data-focus-key': `many-${action}`,
      onclick: guarded(() => agentsAtOnce(chosen, action)),
    }, icon(iconName), n === chosen.length ? label : `${label} ${fmt(n)}`));
  };
  if (admin) offer('approve', 'Approve', 'check', 'btn--primary');
  if (admin) offer('adopt', 'Adopt', 'user-check');
  if (admin && chosen.some((a) => a.status !== 'deleted')) {
    buttons.push(h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'many-edit', onclick: guarded(() => agentsAtOnce(chosen, 'edit')) },
      icon('edit'), 'Edit…'));
  }
  if (can('approve') && chosen.some((a) => a.status !== 'deleted')) {
    buttons.push(h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'many-classify', onclick: guarded(() => agentsAtOnce(chosen, 'classify')) },
      icon('shield-check'), 'Classify…'));
  }
  if (contain) offer('block', 'Block', 'power', 'btn--danger');
  if (contain) offer('unblock', 'Unblock', 'undo');
  if (admin) offer('delete', 'Delete', 'trash', 'btn--danger-quiet');
  if (admin) offer('restore', 'Restore', 'undo');
  return h('div', { class: 'bulk-bar', role: 'region', 'aria-label': 'Chosen agents' },
    h('strong', { class: 'bulk-count', 'aria-live': 'polite' }, `${plural(chosen.length, 'agent')} chosen`),
    h('div', { class: 'btn-row' }, buttons),
    h('button', { type: 'button', class: 'btn btn--sm btn--ghost', 'data-focus-key': 'choose-none', onclick: clear }, icon('x'), 'Clear'));
}

// Names, in a list that scrolls when there are many.
function nameList(names) {
  return h('ul', { class: 'adopt-list', role: 'list' }, names.map((n) => h('li', { class: 'break' }, n)));
}

async function agentsAtOnce(chosen, action) {
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
    if (action === 'block') text += ` Block them there too.`;
  }
  if (fits.length < chosen.length) {
    text += ` ${plural(chosen.length - fits.length, 'other agent')} chosen ${chosen.length - fits.length === 1 ? 'isn\'t' : 'aren\'t'} in a state for it, and ${chosen.length - fits.length === 1 ? 'stays as it is' : 'stay as they are'}.`;
  }
  const result = await ask({
    title: `${verb} ${plural(fits.length, 'agent')}?`,
    text, tone: spec.tone, iconName: spec.icon, confirm: `${verb} ${plural(fits.length, 'agent')}`, busy: 'Working…',
    extra: nameList(fits.map((a) => a.name)),
    fields: [{ id: 'reason', label: 'Reason', type: 'textarea', hint: 'Recorded in the evidence ledger, for each of them.' }],
    submit: (v) => inTurns('v1/agents/bulk', { action, agents: fits.map((a) => a.id), ...(v.reason ? { reason: v.reason } : {}) }, 'agents'),
  });
  if (!result) return;
  await manyDone(result, AGENTS_AT_ONCE[action].verb, 'agent');
  refreshBadges();
  await refresh();
}

// Change several agents' owner, team, sponsors or blueprint at once: only what is filled in.
async function editMany(chosen) {
  const [teamList, blueprints] = await Promise.all([api('v1/teams').catch(() => []), api('v1/blueprints').catch(() => [])]);
  const KEEP = '__keep';
  const result = await ask({
    title: `Edit ${plural(chosen.length, 'agent')}`,
    text: 'Only what you fill in changes: the rest of each agent stays as it is.',
    iconName: 'edit', confirm: 'Save', busy: 'Saving…', wide: true,
    extra: nameList(chosen.map((a) => a.name)),
    fields: [
      { id: 'owner', label: 'Owner', placeholder: 'A team or a person', hint: 'Accountable for each of them.' },
      { id: 'team', label: 'Team', type: 'select', value: KEEP, options: [
        { value: KEEP, label: 'Leave each one\'s as it is' }, { value: '', label: 'None: their blueprint\'s' },
        ...teamList.map((t) => ({ value: t.name, label: t.name }))] },
      { type: 'row', fields: [
        { id: 'add', label: 'Add sponsors', placeholder: 'dana@example.com', hint: 'Separate people with commas.' },
        { id: 'remove', label: 'Remove sponsors', placeholder: 'alice@example.com', hint: 'Someone who left, say.' },
      ] },
      { id: 'blueprint', label: 'Blueprint', type: 'select', value: KEEP, options: [
        { value: KEEP, label: 'Leave each one\'s as it is' }, { value: '', label: 'No blueprint' },
        ...blueprints.map((b) => ({ value: b.name, label: `${b.name} (${b.risk_tier} risk tier)` }))] },
      { id: 'reason', label: 'Reason', type: 'textarea', hint: 'Recorded in the evidence ledger, for each of them.' },
    ],
    submit: (v) => {
      const fields = {};
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
async function adoptMany(candidates) {
  const boxes = candidates.map((a) => {
    const box = h('input', { type: 'checkbox', checked: true, value: a.id, 'aria-label': `Adopt ${a.name}` });
    return { a, box };
  });
  const known = candidates.filter((a) => a.maker?.email && a.maker.known && !a.maker.left).length;
  const list = h('ul', { class: 'adopt-list', role: 'list' }, boxes.map(({ a, box }) => h('li', {},
    h('label', { class: 'check' }, box, h('span', {}, h('span', { class: 'cell-title' }, a.name),
      h('span', { class: 'cell-sub' }, a.maker ? makerLine(a.maker) : 'Who made it isn\'t known'))))));
  const result = await ask({
    title: `Adopt ${plural(candidates.length, 'agent')}`,
    text: `Each becomes pending review, with an owner and sponsors; approve them afterwards. AgentGov knows who made ${fmt(known)} of them.`,
    iconName: 'user-check', confirm: 'Adopt', busy: 'Adopting…', wide: true,
    extra: list,
    fields: [
      { id: 'makers', type: 'checkbox', value: known > 0, label: 'Make each one\'s maker its owner and sponsor, where AgentGov knows them' },
      { id: 'owner', label: 'Owner', placeholder: 'A team or a person', hint: 'For the agents whose maker AgentGov doesn\'t know, or for all of them if the box above is clear.' },
      { id: 'sponsors', label: 'Sponsors', placeholder: 'alice@example.com, bob@example.com', hint: 'Separate people with commas: for the agents that have no maker to sponsor them.' },
      { id: 'reason', label: 'Reason', type: 'textarea', hint: 'Recorded in the evidence ledger.' },
    ],
    submit: async (v) => {
      const chosen = boxes.filter(({ box }) => box.checked).map(({ a }) => a.id);
      if (!chosen.length) throw new Error('Choose one agent at least.');
      if (!v.makers && !v.owner) throw new Error('Give them an owner, or make their makers their owners.');
      const body = { agents: chosen, makers: v.makers };
      if (v.owner) body.owner = v.owner;
      const sponsors = parseList(v.sponsors);
      if (sponsors.length) body.sponsors = sponsors;
      if (v.reason) body.reason = v.reason;
      return api('v1/agents/adopt', { method: 'POST', body });
    },
  });
  if (!result) return;
  const left = result.left || [];
  toast(left.length
    ? `Adopted ${plural(result.adopted.length, 'agent')}; ${fmt(left.length)} left: ${left.slice(0, 3).map((x) => `${x.agent} (${x.why})`).join('; ')}${left.length > 3 ? '…' : ''}`
    : `Adopted ${plural(result.adopted.length, 'agent')}. They are pending review.`, left.length ? { tone: 'critical' } : undefined);
  refreshBadges();
  await refresh();
}

const AGENT_COLUMNS = [['name', 'Agent'], ['status', 'Status'], ['risk', 'Risk'], ['owner', 'Owner'], ['blueprint', 'Blueprint'], ['last_seen', 'Last seen']];

// The agents table: sorted by the header pressed (onSort); with ``selected``, a box on each
// row to choose it for an action on many at once (onSelect(ids, chosen)).
function agentsTable(rows, { sort = 'name', onSort = null, selected = null, onSelect = null } = {}) {
  const head = [];
  if (selected) {
    const all = rows.every((a) => selected.has(a.id));
    const box = h('input', {
      type: 'checkbox', checked: all, 'data-focus-key': 'choose-all', 'aria-label': `Choose all ${plural(rows.length, 'agent')} shown`,
      onchange: (e) => onSelect(rows.map((a) => a.id), e.target.checked),
    });
    box.indeterminate = !all && rows.some((a) => selected.has(a.id));
    head.push(h('th', { scope: 'col', class: 'select-cell' }, box));
  }
  for (const [key, label] of AGENT_COLUMNS) {
    if (!onSort) { head.push(h('th', { scope: 'col' }, label)); continue; }
    const current = sort.replace(/^-/, '') === key;
    const down = sort.startsWith('-');
    head.push(h('th', { scope: 'col', 'aria-sort': current ? (down ? 'descending' : 'ascending') : null },
      h('button', { type: 'button', class: 'th-sort', 'data-focus-key': `sort-${key}`, onclick: () => onSort(key) },
        label, icon('chevron', { cls: current ? (down ? 'sort-down' : 'sort-up') : 'sort-none' }))));
  }
  const table = h('table', { class: 'data rtable' },
    h('thead', {}, h('tr', {}, head)),
    h('tbody', {}, rows.map((a) => {
      const href = agentHref(a.id);
      const tr = h('tr', { class: ['is-link', selected?.has(a.id) ? 'is-chosen' : null] },
        selected ? h('td', { 'data-label': 'Choose', class: 'select-cell' }, h('label', { class: 'select-hit' },
          h('input', {
            type: 'checkbox', checked: selected.has(a.id), 'data-focus-key': `choose-${a.id}`, 'aria-label': `Choose ${a.name}`,
            onchange: (e) => onSelect([a.id], e.target.checked),
          }))) : null,
        h('td', { 'data-label': 'Agent' }, h('a', { class: 'cell-title break', href }, a.name),
          a.description ? h('div', { class: 'cell-sub clamp-2' }, a.description) : null),
        h('td', { 'data-label': 'Status' }, chip('agent', a.status)),
        h('td', { 'data-label': 'Risk' }, riskChip(a.risk)),
        h('td', { 'data-label': 'Owner', class: 'break' }, a.owner || h('span', { class: 'muted' }, a.status === 'discovered' ? 'Unassigned' : 'No owner'),
          !a.owner && a.maker ? h('div', { class: 'cell-sub' }, makerLine(a.maker)) : null),
        h('td', { 'data-label': 'Blueprint' }, a.blueprint || (platformOf(a)
          ? h('span', { class: 'muted', title: 'Blueprints grant gateway tools; this agent runs on another platform' }, `${platformOf(a)} agent`)
          : h('span', { class: 'muted' }, 'None'))),
        h('td', { 'data-label': 'Last seen', class: 'nowrap' }, timeEl(a.last_seen_at, { empty: 'Never' })));
      tr.addEventListener('click', (e) => {
        if (e.target.closest('a, button, input, label, .select-cell') || getSelection().toString()) return;
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
  const [entries, openFindings, instructions, usage, a2a, held, packages, modes, matchedRules] = await Promise.all([
    api(`v1/ledger?agent=${encodeURIComponent(agent.id)}&limit=12`).catch((e) => e),
    api(`v1/findings?status=open&agent=${encodeURIComponent(agent.id)}`).catch((e) => e),
    api(`v1/agents/${encodeURIComponent(agent.id)}/instructions`).catch((e) => e),
    api(`v1/models/usage?agent=${encodeURIComponent(agent.id)}&days=7`).catch((e) => e),
    api(`v1/agents/${encodeURIComponent(agent.id)}/a2a`).catch((e) => e),
    api(`v1/agents/${encodeURIComponent(agent.id)}/access-packages`).catch((e) => e),
    api('v1/access-packages').catch(() => []),
    featureModes().catch(() => ({})),
    api(`v1/agents/${encodeURIComponent(agent.id)}/rules`).catch(() => []),
  ]);
  // What Microsoft Entra ID Governance assigns its Entra identity, when it has one.
  const entra = agent.external_ids?.entra_agent_id
    ? await api(`v1/agents/${encodeURIComponent(agent.id)}/entra-access-packages`).catch((e) => e)
    : null;
  // Agents on Microsoft 365 or Copilot Studio don't use the gateway: show what their platform reports.
  const views = agent.platforms || [];
  const where = views.length && agent.status !== 'deleted' ? await platformActionTarget(agent) : null;
  const main = views.length ? views.map((v) => platformCard(agent, v, where))
    : [permissionsCard(agent), agentAccessCard(agent, held, packages, modes['access-packages']), agentModelsCard(agent, usage), agentA2ACard(agent, a2a)];
  // With threat detection enforcing, AgentGov's policies decide about its tool calls.
  const enforced = views.some((v) => v.source === 'copilot-studio') && modes['copilot-studio-threat-detection'] === 'enforce';
  return h('div', { class: 'page', 'data-title': agent.name },
    agentHeader(agent),
    h('div', { class: 'detail-grid' },
      h('div', { class: 'stack' }, main, instructionsCard(agent, instructions), agentLedgerCard(agent, entries),
        views.length ? null : agentCardCard(agent)),
      h('div', { class: 'stack' }, riskCard(agent, enforced), peopleCard(agent), attestationCard(agent), classificationCard(agent), identityCard(agent),
        entra instanceof Error || !entra ? null : entraAccessCard(agent, entra),
        agentRulesCard(matchedRules),
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

// Sponsors attest their own agents, whatever their role (signed in, or with an approver's
// key named after them); admins any agent.
function mayAttest(a) {
  if (!ATTESTABLE.has(a.status)) return false;
  const sponsor = (a.sponsors || []).some((s) => String(s).toLowerCase() === String(me?.name || '').toLowerCase());
  return can('admin') || (sponsor && (me?.via === 'session' || can('approve')));
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
    // Its maker on its platform, where AgentGov knows them.
    const maker = a.suggested_owner;
    fields.push(
      { id: 'owner', label: 'Owner', placeholder: 'Team or person accountable for the agent', value: a.owner || maker || '',
        hint: maker && !a.owner ? `Suggested: ${maker}, ${suggestedWhy(a)}. Change it if someone else should own it.` : null },
      { id: 'sponsors', label: 'Sponsors', placeholder: 'alice@example.com, bob@example.com', value: (a.sponsors?.length ? a.sponsors : maker ? [maker] : []).join(', '), hint: 'Separate people with commas. Approval needs at least one sponsor.' },
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
  // Who gets its tokens: the agent itself, or people who sign in to it (a public client);
  // and how the agent authenticates, offered once there's an issuer to choose.
  const authentication = [
    { type: 'section', label: 'Authentication' },
    {
      id: 'client_type', label: 'Its tokens are for', type: 'select', value: a?.client_type || 'service',
      options: [
        { value: 'service', label: 'The agent itself (a confidential client)' },
        { value: 'public', label: "People who sign in to it on their machines, such as developers' MCP clients (a public client)" },
      ],
      hint: 'A public client has no secret: people sign in to it, and it acts for them with their own token.',
    },
    {
      id: 'redirect_uris', label: 'Sign-ins return to', mono: true, value: (a?.redirect_uris || []).join(', '), placeholder: 'http://127.0.0.1/*, http://localhost/*',
      hint: 'Where its sign-in may return, separated by commas, with * only at the end. Empty: the machine itself, at any port, where MCP clients such as VS Code and Claude Code listen for it.',
    },
    ...(issuers.length || identity ? [
      {
        id: 'workload_issuer', label: 'Authenticates with', type: 'select', value: identity?.issuer || '',
        options: [
          { value: '', label: 'A client secret' },
          ...issuers.map((i) => ({ value: i.name, label: `Its own identity from ${i.name} (${issuerKind(i.kind)}${i.status === 'blocked' ? ', blocked' : ''})` })),
        ],
        hint: 'An identity it already has, such as a Kubernetes service account, needs no secret to store or rotate.',
      },
      { id: 'workload_subject', label: 'Subject', mono: true, value: identity?.subject || '', hint: 'Its subject at the issuer: the sub claim of its tokens there.' },
    ] : []),
  ];
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
      hint: 'Where it serves A2A (its JSON-RPC endpoint). Other agents then call it at /a2a/<name> on the gateway, as their grants allow.',
    },
    {
      id: 'a2a_protection', label: 'Calls around the gateway are stopped by', type: 'select', value: a?.a2a_protection || '',
      options: [
        { value: '', label: 'Nothing we know of' },
        { value: 'network', label: 'The network: only the gateway can reach it' },
        { value: 'delegation', label: "The agent: it refuses calls without the gateway's delegation" },
      ],
      hint: "AgentGov checks only the calls that come through its gateway. Say what stops calls straight to the A2A endpoint: AgentGov can test it, and tells the agent's owners when it doesn't.",
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
      const subject = controls.workload_subject;
      const show = () => {
        // A public client has no identity of its own: people sign in to it.
        const isPublic = controls.client_type.value === 'public';
        controls.redirect_uris.closest('.field').hidden = !isPublic;
        if (!controls.workload_issuer) return;
        controls.workload_issuer.closest('.field').hidden = isPublic;
        const issuer = isPublic ? null : issuers.find((i) => i.name === controls.workload_issuer.value);
        subject.closest('.field').hidden = !issuer;
        if (!issuer) return;
        subject.placeholder = ISSUER_KINDS[issuer.kind]?.[1] || '';
        if (issuer.kind === 'spiffe') subject.placeholder = `${issuer.issuer}/ns/agents/sa/${a?.name || 'support-bot'}`;
        // An agent linked to Microsoft Entra Agent ID: its tokens' subject is its object ID.
        const entra = a?.external_ids?.entra_agent_id;
        if (isEntra(issuer) && entra && !subject.value) subject.value = entra;
      };
      controls.client_type.addEventListener('change', show);
      controls.workload_issuer?.addEventListener('change', show);
      show();
    },
    submit: async (v) => {
      const isPublic = v.client_type === 'public';
      if (!isPublic && v.workload_issuer && !v.workload_subject) throw new Error('Give its subject at the issuer, or choose a client secret.');
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
        a2a_protection: v.a2a_protection || null,
        framework: orNull(v.framework),
        platform: orNull(v.platform),
        models: parseList(v.models),
        labels: parseLabels(v.labels),
        client_type: v.client_type,
        redirect_uris: isPublic ? parseList(v.redirect_uris) : [],
      };
      if ('workload_issuer' in v) {
        body.workload_identity = v.workload_issuer && !isPublic ? { issuer: v.workload_issuer, subject: v.workload_subject } : null;
      }
      // Left unchanged, the tier follows the blueprint (as the API does).
      if (v.risk_tier && v.risk_tier !== a?.risk_tier) body.risk_tier = v.risk_tier;
      if (editing) return api(`v1/agents/${encodeURIComponent(a.id)}`, { method: 'PATCH', body, ifMatch: a.version });
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

/** Where people sign in to a public client, as their MCP clients find it. */
async function publicSignIn(a) {
  let creds;
  try {
    creds = await api(`v1/agents/${encodeURIComponent(a.id)}/credentials`, { method: 'POST', body: {} });
  } catch (err) {
    toast(err.message, { tone: 'critical' });
    return;
  }
  await ask({
    title: `How people sign in to ${a.name}`,
    text: "Their MCP client finds where to sign in from the gateway, once Developers sign in at the gateway is on, and asks them for this client ID if it can't register itself. They sign in in their browser, and the client acts for them with their own token, which the gateway takes for this agent and for them.",
    iconName: 'key', confirm: 'Done', cancel: null, wide: true,
    extra: facts([
      ['Client ID', copyable(creds.client_id, 'client ID')],
      ['Issuer', copyable(creds.issuer, 'issuer')],
      ['Sign-ins return to', h('span', { class: 'mono' }, (creds.redirect_uris || []).join(', '))],
      ['Authorization endpoint', copyable(creds.authorization_endpoint, 'authorization endpoint')],
      ['Token endpoint', copyable(creds.token_endpoint, 'token endpoint')],
      ['Gateway audience', copyable(creds.audience, 'gateway audience')],
    ]),
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

// Someone a platform names as an agent's maker or owner, as AgentGov knows them.
function makerName(m) {
  if (m.name && m.email) return `${m.name} (${m.email})`;
  return m.name || m.email || `Entra ID ${m.entra_id}`;
}

function makerRole(m) {
  const where = PLATFORM_SOURCES[`platform:${m.source}`] || m.source;
  const roles = m.roles || [];
  const words = roles.includes('owner') && roles.includes('creator') ? `Made it, and owns it in ${where}`
    : roles.includes('owner') ? `Owns it in ${where}` : `Made it in ${where}`;
  let note = null;
  if (m.left) note = `left ${relTime(m.left_at)}`;
  else if (m.enabled === false) note = 'account disabled';
  else if (m.entra_id && !m.looked_up) note = 'not looked up yet';
  else if (m.entra_id && !m.known) note = 'not a user in the directory';
  return note ? `${words} · ${note}` : words;
}

// One line for a maker where there is room for one: the list, the adopt dialog.
function makerLine(m) {
  const where = PLATFORM_SOURCES[`platform:${m.source}`] || m.source;
  const note = m.left ? ' (left)' : m.enabled === false ? ' (account disabled)' : '';
  return (m.roles || []).includes('creator') ? `Made by ${makerName(m)}${note}` : `Owner in ${where}: ${makerName(m)}${note}`;
}

// Who the person adopting an agent suggests is to it: "who owns it in Copilot Studio".
function suggestedWhy(a) {
  const pick = (a.makers || []).find((m) => (m.email || '').toLowerCase() === a.suggested_owner);
  return pick && (pick.roles || []).includes('owner') ? `who owns it in ${platformOf(a) || 'its platform'}` : 'who made it';
}

function makersBlock(a) {
  const makers = a.makers || [];
  if (!makers.length) return null;
  const unknown = makers.some((m) => m.entra_id && !m.looked_up);
  return [
    h('ul', { class: 'people', role: 'list' }, makers.map((m) => personRow(makerName(m), makerRole(m)))),
    unknown ? h('p', { class: 'hint' }, 'AgentGov knows people by name once it can look them up: ',
      h('a', { href: '#/platforms' }, 'connect Microsoft Entra users, or upload a list of users'), '.') : null,
  ];
}

function peopleCard(a) {
  const managed = a.status !== 'discovered';
  const sponsors = a.sponsors || [];
  // The owner and sponsors who have left: issues go past them.
  const gone = Object.fromEntries((a.left || []).map((g) => [g.name.toLowerCase(), g]));
  const role = (name, word) => {
    const g = gone[String(name).toLowerCase()];
    return g ? `${word} · ${g.how === 'left' ? 'has left' : 'account disabled'}` : word;
  };
  return card({
    title: 'Owner and sponsors',
    sub: 'The accountable team and the people who vouch for this agent',
    body: [
      (a.left || []).length ? callout('warning', 'alert-circle', `${a.left.map((g) => (g.how === 'left' ? `${g.name} has left` : `${g.name}'s account is disabled`)).join('; ')}, as Microsoft Entra ID says: its issues go to the next people responsible for it. Name others.`) : null,
      a.owner ? h('ul', { class: 'people', role: 'list' }, personRow(a.owner, role(a.owner, 'Owner')))
        : callout(managed ? 'warning' : 'neutral', managed ? 'alert-circle' : 'info',
          managed ? 'No owner. Assign an owning team or person.'
            : a.suggested_owner ? `Unmanaged agents have no owner until someone adopts them. Adopting it suggests ${a.suggested_owner}, ${suggestedWhy(a)}.`
              : 'Unmanaged agents have no owner until someone adopts them.'),
      makersBlock(a),
      sponsors.length ? h('ul', { class: 'people', role: 'list' }, sponsors.map((p) => personRow(p, role(p, 'Sponsor'))))
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
  const isPublic = a.client_type === 'public';
  if (credentialActions && isPublic) {
    credentialActions = [h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'show-sign-in', onclick: guarded(() => publicSignIn(a)) }, icon('key'), 'How people sign in')];
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
        platform ? null : ['Authenticates with', isPublic
          ? 'Nothing of its own: people sign in to it (a public client)'
          : workload
            ? ['Its own identity from ', h('a', { href: '#/access' }, workload.issuer)]
            : 'A client secret'],
        isPublic ? ['Sign-ins return to', h('span', { class: 'mono' }, (a.redirect_uris.length ? a.redirect_uris : ['http://127.0.0.1/*', 'http://localhost/*']).join(', '))] : null,
        workload ? ['Subject', copyable(workload.subject, 'subject')] : null,
        platform ? null : ['Synced', id.synced_at ? timeEl(id.synced_at) : h('span', { class: 'muted' }, 'Not synced yet')],
        ['Agent ID', copyable(a.id, 'agent ID')],
        ['Source', a.source],
        ['Framework', a.framework],
        ['Environment', a.environment],
        a.platform ? ['Platform', a.platform] : null,
        (a.models || []).length ? ['Models', h('div', { class: 'chip-row' }, a.models.map((m) => plainChip(m, { mono: true })))] : null,
        labels.length ? ['Labels', h('div', { class: 'chip-row' }, labels.map(([k, v]) => plainChip(`${k}=${v}`, { mono: true })))] : null,
        Object.keys(a.control_modes || {}).length ? ['Controls for it', h('div', { class: 'stack-tight' },
          Object.entries(a.control_modes).map(([key, c]) => h('div', {},
            h('a', { href: '#/features' }, key), `: ${(MODE_WORDS[c.mode] || c.mode).toLowerCase()} (${c.why})`)))] : null,
        external.length ? ['External IDs', h('div', { class: 'chip-row' }, external.map(([k, v]) => plainChip(`${k}: ${v}`, { mono: true })))] : null,
        ['Created', [timeEl(a.created_at), a.created_by ? ` by ${a.created_by}` : '']],
        ['Last seen', timeEl(a.last_seen_at, { empty: 'Never' })],
        a.deleted_at ? ['Deleted', timeEl(a.deleted_at)] : null,
      ]),
    ],
  });
}

// Calls around the gateway: what its owners say stops calls straight to its A2A endpoint,
// and what AgentGov found when it last called it itself.
const AROUND_SAYS = {
  network: 'The network: only the gateway can reach it',
  delegation: "The agent: it refuses calls without the gateway's delegation",
};
const AROUND_FOUND = {
  refused: ['good', 'shield-check', 'It refused the test call'],
  accepted: ['critical', 'alert-circle', 'It took the test call'],
  unreachable: [null, 'info', "AgentGov couldn't reach it"],
  inconclusive: ['warning', 'triangle', 'Inconclusive'],
};
function aroundGateway(around) {
  const says = AROUND_SAYS[around.protection];
  const test = around.test;
  const [tone, iconName, label] = test ? (AROUND_FOUND[test.state] || [null, 'info', test.state]) : [];
  return h('div', { class: 'stack', style: 'gap:4px' },
    says ? h('span', {}, `Stopped by ${says.charAt(0).toLowerCase()}${says.slice(1)}`)
      : h('span', { class: 'muted' }, "Its owners haven't said what stops calls straight to it"),
    test
      ? h('div', {}, plainChip(label, { tone, iconName }), ' ', h('span', { class: 'muted small' }, `${test.detail}, `), timeEl(test.checked_at))
      : h('span', { class: 'muted small' }, around.mode === 'test' ? 'Not tested yet: the next posture scan tests it.' : `Not tested (calls-around-gateway is ${around.mode}).`));
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
    view.serves ? ['Around the gateway', aroundGateway(view.around_gateway)] : null,
  ];
  const idle = !view.serves && !view.may_call.length && !view.agent_access.length;
  return card({
    title: 'Agent to agent',
    sub: 'Calls between agents through the gateway (A2A) are checked by policy, one by one; the agent called gets who handed the work down, with the person at its head. Calls straight to an agent skip the gateway.',
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
  aws: 'From AWS', 'google-cloud': 'From Google Cloud', salesforce: 'From Salesforce', databricks: 'From Databricks',
  'microsoft-foundry': 'From Microsoft Foundry',
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
  const [all, agents, mine, asked, packages, inbox] = await Promise.all([
    person ? api('v1/me/approvals') : api('v1/approvals'),
    person ? [] : api('v1/agents?include_deleted=true').catch(() => []),
    api('v1/me/approvals?status=pending').catch(() => []),
    person ? [] : api('v1/access-assignments?status=requested').catch(() => []),
    person ? [] : api('v1/access-packages').catch(() => []),
    // Everything else waiting for a decision this role can make.
    person ? null : api('v1/inbox').catch(() => null),
  ]);
  const agentsById = new Map(agents.map((a) => [a.id, a]));
  const mineIds = new Set(mine.map((r) => r.id));
  const pending = all.filter((r) => r.status === 'pending');
  const history = all.filter((r) => r.status !== 'pending');
  const more = (inbox?.kinds || []).filter((k) => k.count && !['calls', 'access'].includes(k.kind));
  const waiting = pending.length + asked.length + more.reduce((n, k) => n + k.count, 0);
  updateBadges({ pendingApprovals: inbox ? inbox.total : pending.length });
  const approvalsMode = person ? 'enforce' : (await featureModes().catch(() => ({}))).approvals;
  const approval = (r) => approvalCard(r, agentsById.get(r.agent_id), mineIds.has(r.id));
  const tabs = h('nav', { class: 'tabs', 'aria-label': 'Approval views' },
    h('a', { class: 'tab', href: '#/approvals', 'aria-current': tab === 'pending' ? 'page' : null },
      'Pending', h('span', { class: 'nav-badge', 'data-tone': waiting ? 'warning' : '' }, fmt(waiting))),
    h('a', { class: 'tab', href: '#/approvals/history', 'aria-current': tab === 'history' ? 'page' : null },
      'History', h('span', { class: 'nav-badge' }, fmt(history.length))));
  let content;
  if (tab === 'pending') {
    // Yours first: requests agents made while acting for you wait for your decision.
    const yours = pending.filter((r) => mineIds.has(r.id));
    const others = pending.filter((r) => !mineIds.has(r.id));
    const sections = [];
    if (pending.length) {
      // Headed as one kind among others when there are others.
      if (asked.length || more.length) sections.push(h('div', { class: 'section-title' }, h('h2', {}, 'Calls held for a decision')));
      sections.push(
        yours.length && !person ? h('div', { class: 'section-title' }, h('h3', {}, 'Waiting for you')) : null,
        yours.length ? h('div', { class: 'approval-list' }, yours.map(approval)) : null,
        yours.length && others.length ? h('div', { class: 'section-title' }, h('h3', {}, "Everyone else's")) : null,
        others.length ? h('div', { class: 'approval-list' }, others.map(approval)) : null);
    }
    if (asked.length) {
      sections.push(card({
        title: 'Access requests',
        sub: 'Access packages asked for agents. Someone other than who asked decides.',
        body: h('ul', { class: 'access-list', role: 'list' }, asked.map((r) => h('li', { class: 'access-row' },
          h('div', { class: 'access-main' },
            h('div', { class: 'cell-title' }, r.package, ' for ', agentLink(r.agent_id, r.agent_name)),
            h('div', { class: 'cell-sub break' }, `${r.requested_by}, for ${plural(r.days, 'day')}: ${r.reason} · `, timeEl(r.requested_at))),
          h('div', { class: 'btn-row' }, assignmentButtons(r, packages, { id: r.agent_id, name: r.agent_name }))))),
      }));
    }
    sections.push(...more.map(inboxCard));
    content = sections.length
      ? h('div', { class: 'stack' }, ...sections)
      : h('section', { class: 'card' }, person
        ? emptyState('Nothing is waiting for you', 'When an agent acting for you needs your approval to do something, it appears here.')
        : emptyState('Nothing is waiting for a decision',
          'Calls policy holds for a person, access asked for agents, risks people ask to accept, and agents and tool servers registered for review appear here.'));
  } else {
    content = h('section', { class: 'card', 'aria-label': 'Approval history' },
      history.length ? approvalHistoryTable(history) : emptyState('No decided approvals yet'));
  }
  return h('div', { class: 'page', 'data-title': tab === 'history' ? 'Approval history' : 'Approvals' },
    pageHead({
      title: 'Approvals',
      sub: person
        ? 'What agents acting for you want to do, and need you to approve first. Approve a call and the agent can make it once.'
        : 'Everything waiting for a decision you can make: calls policy held, access asked for agents, risks people ask to accept, and agents and tool servers to approve. An approved call is single-use: the agent retries the identical call and it goes through once.',
      actions: [refreshButton()],
    }),
    approvalsMode && approvalsMode !== 'enforce' ? callout('warning', 'eye', h('span', {},
      h('strong', {}, `Human approval is ${approvalsMode === 'off' ? 'off' : 'in monitor mode'}: `),
      approvalsMode === 'off' ? 'no call waits for approval. ' : 'calls that need approval go through, and the ledger records them. ',
      h('a', { href: '#/features' }, 'Features'), '.')) : null,
    tabs, content);
}

// One kind of decision from the inbox (GET /v1/inbox), beyond calls and access requests.
function inboxCard(k) {
  // Its count is of agents, its rows of platforms.
  const listed = k.kind === 'platform_agents' ? k.count : k.items.length;
  const more = k.count > listed ? h('p', { class: 'hint' }, `And ${fmt(k.count - listed)} more.`) : null;
  const row = (main, sub, buttons) => h('li', { class: 'access-row' },
    h('div', { class: 'access-main' }, h('div', { class: 'cell-title' }, main), sub ? h('div', { class: 'cell-sub break' }, sub) : null),
    buttons ? h('div', { class: 'btn-row' }, buttons) : null);
  const list = (rows) => h('div', {}, h('ul', { class: 'access-list', role: 'list' }, rows), more);
  if (k.kind === 'risks') {
    return card({
      title: k.title,
      sub: 'The people an issue reached ask for its risk to be accepted until a date, and say why. Accept or decline it on the issue; nobody accountable for the agent accepts its risk.',
      body: list(k.items.map((f) => row(
        h('a', { href: `#/findings/${encodeURIComponent(f.id)}` }, f.title),
        [f.agent_id ? [agentLink(f.agent_id, f.agent_name || f.subject), ' · '] : null,
          `${f.asked.by}, until ${String(f.asked.until).slice(0, 10)}: ${f.asked.reason}`],
        [h('a', { class: 'btn btn--sm', href: `#/findings/${encodeURIComponent(f.id)}` }, 'Decide')]))),
    });
  }
  if (k.kind === 'agents') {
    return card({
      title: k.title,
      sub: 'Registered for review. Approved, an agent becomes active and can authenticate; blocked, it can do nothing.',
      body: list(k.items.map((a) => row(
        agentLink(a.id, a.name),
        [`Owner ${a.owner || 'none'} · sponsors ${(a.sponsors || []).join(', ') || 'none'}`, a.blueprint ? ` · blueprint ${a.blueprint}` : null,
          ` · registered by ${a.created_by || 'someone'} `, timeEl(a.created_at)],
        [h('button', { type: 'button', class: 'btn btn--sm btn--primary', onclick: () => runLifecycle(a, 'approve') }, icon('check'), 'Approve'),
          h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', onclick: () => runLifecycle(a, 'block') }, icon('ban'), 'Block')]))),
    });
  }
  if (k.kind === 'toolservers') {
    return card({
      title: k.title,
      sub: 'Registered for review. Approved, agents whose grants cover it can call its tools through the gateway.',
      body: list(k.items.map((ts) => row(
        ts.name,
        [h('code', {}, ts.url), ts.owner ? ` · owner ${ts.owner}` : null, ` · registered by ${ts.created_by || 'someone'} `, timeEl(ts.created_at)],
        [h('button', { type: 'button', class: 'btn btn--sm btn--primary', onclick: () => serverAction(ts, 'approve') }, icon('check'), 'Approve'),
          h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', onclick: () => serverAction(ts, 'block') }, icon('ban'), 'Block')]))),
    });
  }
  if (k.kind === 'definitions') {
    return card({
      title: k.title,
      sub: 'Calls to these tools are refused until an administrator reads the new definition and approves it, in the tool server\'s catalog.',
      body: list(k.items.map((d) => row(
        h('code', {}, `${d.server}/${d.tool}`), ['Changed ', timeEl(d.since)],
        [h('a', { class: 'btn btn--sm', href: '#/toolservers' }, 'Review')]))),
    });
  }
  if (k.kind === 'platform_agents') {
    return card({
      title: k.title,
      sub: 'Found on the platforms AgentGov reads, with no owner, sponsors or review yet. Adopt the ones you keep; block or delete the others where they run.',
      body: list(k.items.map((p) => row(
        `${plural(p.count, 'agent')} in ${p.platform}`, null,
        [h('a', { class: 'btn btn--sm', href: '#/agents?status=discovered' }, 'Review them')]))),
    });
  }
  return null;
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
      { id: 'url', label: 'Upstream URL', mono: true, value: ts?.url || '', placeholder: 'http://crm-mcp:8000/mcp', hint: 'The streamable HTTP MCP endpoint, required on the gateway: agents reach it through the gateway, never directly. For a server outside the gateway, where agents reach it.' },
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
      { type: 'section', label: 'Outside the gateway' },
      {
        id: 'authorization_server', label: 'Its authorization server', mono: true, value: ts?.authorization_server || '', placeholder: 'https://id.wiki.example.com/realms/wiki',
        hint: "For a server outside the gateway that takes access tokens from an authorization server of its own: its issuer. Agents get identity assertions (ID-JAG) for it from AgentGov, as their grants allow, while Identity assertions is on, and trade them there for access tokens.",
      },
      { id: 'oauth_client_id', label: "AgentGov's agents' client there", mono: true, value: ts?.oauth_client_id || '', placeholder: 'agentgov-agents', hint: "The client ID agents have at that authorization server. Empty: each agent's own client ID." },
    ].filter(Boolean),
    submit: (v) => {
      const body = {
        url: v.url, description: v.description, owner: orNull(v.owner),
        trust_level: v.trust_level, data_classification: v.data_classification, labels: parseLabels(v.labels),
        gateway: v.gateway, developers: v.developers, packages: parsePackages(v.packages), registry_name: orNull(v.registry_name),
        authorization_server: orNull(v.authorization_server), oauth_client_id: orNull(v.oauth_client_id),
      };
      if (editing) return api(`v1/toolservers/${encodeURIComponent(ts.name)}`, { method: 'PATCH', body, ifMatch: ts.version });
      return api('v1/toolservers', { method: 'POST', body: { name: v.name, ...body } });
    },
  });
}

async function registerToolserver() {
  const created = await toolserverForm(null);
  if (!created) return;
  let said = `Registered ${created.name} for developers.`;
  if (created.gateway) said = `Registered ${created.name}. Agents reach it at ${created.gateway_url || `/mcp/${created.name}`}.`;
  else if (created.authorization_server) said = `Registered ${created.name}. Agents get identity assertions for it from AgentGov.`;
  toast(said);
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
            ts.developers ? plainChip(ts.gateway ? 'Listed for developers' : 'Developers only', { iconName: 'developers', title: 'In the MCP registry developers\' MCP clients read' }) : null,
            ts.authorization_server ? plainChip('Identity assertions', { iconName: 'key', title: 'Agents reach it outside the gateway, with identity assertions (ID-JAG) AgentGov gives them' }) : null),
          ts.description ? h('p', { style: 'color:var(--ink-2)' }, ts.description) : null),
        h('div', { class: 'btn-row' }, actions)),
      poisoned.length ? callout('critical', 'octagon', h('span', {}, h('strong', {}, `${plural(poisoned.length, 'tool')} quarantined. `),
        'Hidden instructions were found in the description, so the tool is hidden from agents and calls to it are denied. Block the server if the definition is malicious.')) : null,
      changed.length ? callout('warning', 'triangle', h('span', {}, h('strong', {}, `${plural(changed.length, 'tool')} changed since approval. `),
        'Calls are refused until an administrator approves the new definition.')) : null,
      facts([
        ts.gateway ? ['Gateway URL', ts.gateway_url ? copyable(ts.gateway_url, 'gateway URL') : h('span', { class: 'muted' }, 'Gateway public URL not configured')] : ['Gateway', h('span', { class: 'muted' }, ts.authorization_server ? 'Not published: agents reach it directly' : 'Not published: only for developers')],
        ts.authorization_server ? ['Authorization server', h('code', { class: 'break' }, ts.authorization_server)] : null,
        ts.authorization_server ? ["Agents' client there", ts.oauth_client_id ? h('code', {}, ts.oauth_client_id) : h('span', { class: 'muted' }, "Each agent's own client ID")] : null,
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
  ['open', 'Open'], ['mine', 'Yours'], ['asked', 'Exceptions asked'], ['accepted', 'Risk accepted'], ['resolved', 'Resolved'], ['dismissed', 'Dismissed'], ['all', 'All'],
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
    h('a', { class: 'tab', href: '#/findings/types', 'aria-current': current === 'types' ? 'page' : null }, 'Types'));
}

async function renderFindings({ params }) {
  const person = isPerson();
  const statuses = person ? FINDING_STATUS.filter(([k]) => !['mine', 'asked', 'dismissed'].includes(k)) : FINDING_STATUS;
  const state = {
    status: statuses.some(([k]) => k === params.get('status')) ? params.get('status') : 'open',
    severity: params.get('severity') || '',
    category: params.get('category') || '',
    type: params.get('type') || '',
    group: params.get('group') === 'agent',
  };
  // Those chosen for an action on many at once, by ID: only ever among those shown. Those
  // who triage do anything to them; the people an issue reached acknowledge theirs.
  const selected = new Set();
  const selecting = () => mayTriage() || person || state.status === 'mine';
  let shown = [];
  // People without a role see the issues sent to them; everyone else, every finding, or
  // theirs. Findings come a page at a time, newest first; the control plane says how many
  // there are in all.
  const PAGE = 500;
  const source = (status, offset) => (person ? `v1/me/issues?status=${encodeURIComponent(status)}`
    : status === 'mine' ? 'v1/me/issues?status=open'
    : status === 'asked' ? `v1/findings?status=open&asked=true&limit=${PAGE}&offset=${offset}`
    : `v1/findings?status=${encodeURIComponent(status)}&limit=${PAGE}&offset=${offset}${state.type ? `&type=${encodeURIComponent(state.type)}` : ''}`);
  async function fetchPage(status, offset = 0) {
    const res = await api(source(status, offset), { raw: true });
    const rows = await res.json();
    const counted = res.headers.get('X-Total-Count');
    return { rows, total: counted === null ? offset + rows.length : Number(counted) };
  }
  const [initial, agents, types] = await Promise.all([
    fetchPage(state.status),
    person ? [] : api('v1/agents?include_deleted=true').catch(() => []),
    person ? [] : api('v1/finding-types').catch(() => []),
  ]);
  let list = initial.rows;
  let total = initial.total;
  const agentsById = new Map(agents.map((a) => [a.id, a]));
  // The page may hold only the newest of them: the badge counts them all.
  const badge = () => { if (state.status === 'open') refreshBadges(); };
  badge();

  const statusHost = h('div', { class: 'seg', role: 'group', 'aria-label': 'Finding status' });
  const sevHost = h('div', { class: 'seg', role: 'group', 'aria-label': 'Severity' });
  const category = h('select', { id: 'finding-category', 'data-focus-key': 'finding-category' },
    [['', 'All categories'], ['threat', 'Threats'], ['posture', 'Posture']].map(([v, l]) => h('option', { value: v, selected: v === state.category }, l)));
  const typeSelect = person ? null : h('select', { id: 'finding-type', 'data-focus-key': 'finding-type' },
    h('option', { value: '' }, 'All types'),
    types.filter((t) => t.total || t.type === state.type).map((t) => h('option', { value: t.type, selected: t.type === state.type },
      t.open ? `${t.type} (${fmt(t.open)} open)` : t.type)));
  const countEl = h('p', { class: 'result-count', 'aria-live': 'polite' });
  const more = h('button', {
    type: 'button', class: 'btn btn--sm btn--ghost',
    onclick: async () => {
      try {
        const page = await fetchPage(state.status, list.length);
        list = list.concat(page.rows);
        total = page.total;
        apply();
      } catch (err) {
        toast(err.message, { tone: 'critical' });
      }
    },
  });
  const listHost = h('div', { class: 'finding-list' });
  const bulkHost = h('div', {});
  const listTitle = h('h2', { class: 'sr-only', tabindex: '-1', id: 'finding-list-title' }, 'Findings');
  const groupBox = h('input', {
    type: 'checkbox', id: 'finding-group', checked: state.group, 'data-focus-key': 'finding-group',
    onchange: () => { state.group = groupBox.checked; keepFocus(apply); sync(); },
  });
  const csvButton = h('button', {
    type: 'button', class: 'btn btn--sm btn--ghost', 'data-focus-key': 'findings-csv',
    title: 'The findings shown, as a spreadsheet', onclick: () => saveCsv(person ? 'agentgov-issues' : 'agentgov-findings', findingCsv(agentsById), shown),
  }, icon('download'), 'Download CSV');

  const sync = () => setHashQuiet('/findings', { status: state.status === 'open' ? '' : state.status, severity: state.severity, category: state.category, type: state.type, group: state.group ? 'agent' : '' });

  async function reload() {
    ({ rows: list, total } = await fetchPage(state.status));
    badge();
  }

  async function act(f, action, rows) {
    try {
      const answered = await answerIssue(f, action);
      if (answered === false) return;
      if (answered === null) {
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
    const which = ['all', 'mine', 'asked'].includes(state.status) ? '' : `${statusMeta('finding', state.status)[2].toLowerCase()} `;
    // An exception asked for is counted as such.
    const many = (n) => (state.status === 'asked' ? plural(n, 'exception asked for', 'exceptions asked for') : plural(n, `${which}${word}`));
    // Counted among those loaded: say so when there are more.
    const capped = total > list.length;
    countEl.textContent = !capped ? many(rows.length)
      : rows.length === list.length ? `The newest ${fmt(list.length)} of ${many(total)}`
        : `${many(rows.length)} among the newest ${fmt(list.length)} of ${fmt(total)}`;
    more.hidden = !capped;
    more.textContent = `Show ${fmt(Math.min(PAGE, total - list.length))} more`;
    const yours = person || state.status === 'mine';
    shown = rows;
    for (const id of [...selected]) if (!rows.some((f) => f.id === id)) selected.delete(id);
    csvButton.disabled = !rows.length;
    const choose = selecting() && rows.length ? {
      selected,
      onSelect: (ids, on) => {
        for (const id of ids) { if (on) selected.add(id); else selected.delete(id); }
        keepFocus(apply);
      },
    } : null;
    bulkHost.replaceChildren(choose ? findingBulkBar(rows, choose, {
      clear: () => { selected.clear(); keepFocus(apply); },
      run: async (action) => {
        const done = await findingsAtOnce(rows.filter((f) => selected.has(f.id)), action);
        if (!done) return;
        selected.clear();
        try { await reload(); } catch (err) { toast(err.message, { tone: 'critical' }); }
        apply();
        listTitle.focus();
        refreshBadges();
      },
    }) : '');
    const card = (f) => findingCard(f, agentsById, (action) => act(f, action, rows), { yours, choose });
    listHost.replaceChildren(...(!rows.length ? [h('section', { class: 'card' }, emptyFindings(state.status, person))]
      : state.group ? findingGroups(rows, agentsById, card, choose) : rows.map(card)));
  }

  category.addEventListener('change', () => { state.category = category.value; apply(); sync(); });
  typeSelect?.addEventListener('change', async () => {
    state.type = typeSelect.value;
    sync();
    try { await reload(); } catch (err) { toast(err.message, { tone: 'critical' }); }
    apply();
  });
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
      h('div', { class: 'field', style: 'flex:0 1 180px' }, h('label', { for: 'finding-category', class: 'sr-only' }, 'Category'), category),
      typeSelect ? h('div', { class: 'field', style: 'flex:0 1 260px' }, h('label', { for: 'finding-type', class: 'sr-only' }, 'Type'), typeSelect) : null),
    h('div', { class: 'filters' }, sevHost, countEl, more,
      h('label', { class: 'check', for: 'finding-group' }, groupBox, 'Group by agent'), csvButton),
    bulkHost,
    listTitle,
    listHost);
}

// The findings shown, by agent: the agents with the most severe first, then those with more.
function findingGroups(rows, agentsById, card, choose) {
  const groups = new Map();
  for (const f of rows) {
    const key = f.agent_id || `subject:${f.subject}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }
  // Not about one agent: about a platform, say.
  const nameOf = (list) => agentsById.get(list[0].agent_id)?.name || PLATFORM_SOURCES[list[0].subject] || list[0].subject || '';
  const worst = (list) => Math.min(...list.map((f) => SEVERITY_ORDER.indexOf(f.severity)));
  return [...groups.values()]
    .sort((a, b) => worst(a) - worst(b) || b.length - a.length || nameOf(a).localeCompare(nameOf(b)))
    .map((list, i) => {
      const first = list[0];
      const headingId = `finding-group-${i}`;
      let box = null;
      if (choose) {
        const all = list.every((f) => choose.selected.has(f.id));
        box = h('input', {
          type: 'checkbox', checked: all, 'data-focus-key': `choose-group-${first.agent_id || first.subject}`,
          'aria-label': `Choose the ${plural(list.length, 'finding')} about ${nameOf(list)}`,
          onchange: (e) => choose.onSelect(list.map((f) => f.id), e.target.checked),
        });
        box.indeterminate = !all && list.some((f) => choose.selected.has(f.id));
      }
      return h('section', { class: 'finding-group', 'aria-labelledby': headingId },
        h('div', { class: 'finding-group-head' },
          box ? h('label', { class: 'check finding-choose' }, box) : null,
          h('h2', { id: headingId, class: 'finding-group-title break' },
            first.agent_id && !isPerson() ? agentLink(first.agent_id, nameOf(list)) : nameOf(list) || 'Not about an agent'),
          chip('severity', SEVERITY_ORDER[worst(list)]),
          h('span', { class: 'muted small' }, plural(list.length, 'finding'))),
        h('div', { class: 'finding-list' }, list.map(card)));
    });
}

// Who an issue is with, in a few words, for a spreadsheet.
function withWhom(f) {
  if (f.status === 'accepted') return `risk accepted until ${String(f.accepted_until).slice(0, 10)}`;
  if (f.status !== 'open' || !f.level) return '';
  const who = (f.assignees || []).join(', ');
  return `${who}${who ? ' ' : ''}(${LEVEL_WORDS[f.level] || f.level})${f.acknowledged_at ? ', acknowledged' : ''}`;
}

function findingCsv(agentsById) {
  return [
    ['Severity', (f) => f.severity],
    ['Status', (f) => f.status],
    ['Agent', (f) => agentsById.get(f.agent_id)?.name || f.subject],
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

// What can be done to many findings at once, and to which of them.
const FINDINGS_AT_ONCE = {
  acknowledge: { label: 'Acknowledge', icon: 'user-check', verb: 'Acknowledged', done: 'acknowledged', fits: (f) => f.status === 'open' && f.level && !f.acknowledged_at },
  resolve: { label: 'Resolve', icon: 'check', verb: 'Resolved', done: 'resolved', fits: (f) => f.status === 'open', triage: true },
  accept: { label: 'Accept risk', icon: 'shield-check', verb: 'Accepted the risk of', done: 'accepted', fits: (f) => f.status === 'open', triage: true },
  dismiss: { label: 'Dismiss', icon: 'minus', verb: 'Dismissed', done: 'dismissed', fits: (f) => f.status === 'open', triage: true },
  reopen: { label: 'Reopen', icon: 'undo', verb: 'Reopened', done: 'reopened', fits: (f) => f.status !== 'open', triage: true },
};

function findingBulkBar(rows, choose, { clear, run }) {
  const chosen = rows.filter((f) => choose.selected.has(f.id));
  const all = chosen.length === rows.length;
  const box = h('input', {
    type: 'checkbox', checked: all, id: 'choose-all-findings', 'data-focus-key': 'choose-all',
    onchange: (e) => choose.onSelect(rows.map((f) => f.id), e.target.checked),
  });
  box.indeterminate = !all && chosen.length > 0;
  const buttons = [];
  if (chosen.length) {
    const triage = mayTriage();
    for (const [action, spec] of Object.entries(FINDINGS_AT_ONCE)) {
      if (spec.triage && !triage) continue;
      const n = chosen.filter(spec.fits).length;
      if (!n) continue;
      buttons.push(h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `many-${action}`, onclick: guarded(() => run(action)) },
        icon(spec.icon), n === chosen.length ? spec.label : `${spec.label} ${fmt(n)}`, ['accept', 'dismiss'].includes(action) ? '…' : ''));
    }
  }
  return h('div', { class: ['bulk-bar', chosen.length ? null : 'bulk-bar--idle'], role: 'region', 'aria-label': 'Chosen findings' },
    h('label', { class: 'check', for: 'choose-all-findings' }, box,
      chosen.length ? h('strong', { 'aria-live': 'polite' }, `${fmt(chosen.length)} of ${fmt(rows.length)} chosen`) : `Choose all ${fmt(rows.length)} shown`),
    buttons.length ? h('div', { class: 'btn-row' }, buttons) : null,
    chosen.length ? h('button', { type: 'button', class: 'btn btn--sm btn--ghost', 'data-focus-key': 'choose-none', onclick: clear }, icon('x'), 'Clear') : null);
}

// Do one thing to the findings chosen; resolves to whether it was done.
async function findingsAtOnce(chosen, action) {
  const spec = FINDINGS_AT_ONCE[action];
  const fits = chosen.filter(spec.fits);
  const fields = [];
  let text = {
    acknowledge: 'Take them on: they go no further up their chains.',
    resolve: 'Mark them resolved. A check that finds one again opens it again.',
    reopen: 'They open again, and go to the people responsible for them.',
    accept: 'They go to nobody until the date you choose, then each opens again if it still holds. A year at most: then someone decides again. Those about agents you own or sponsor are left to someone else.',
    dismiss: 'Dismiss what is wrong: to live with real risks, accept them. They go to nobody; given a date, each opens again then if it still holds. A threat opens again when it happens again.',
  }[action];
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
  if (others) text += ` ${plural(others, 'other finding')} chosen can't be ${spec.done}, and ${others === 1 ? 'stays as it is' : 'stay as they are'}.`;
  const result = await ask({
    title: `${spec.label} ${plural(fits.length, 'finding')}?`,
    text, iconName: spec.icon, confirm: `${spec.label} ${plural(fits.length, 'finding')}`, busy: 'Working…',
    extra: nameList(fits.map((f) => f.title)),
    fields,
    submit: (v) => {
      const body = { action, findings: fits.map((f) => f.id) };
      if (v.reason) body.reason = v.reason;
      if (v.until) body.until = /^\d+$/.test(v.until) ? Number(v.until) : v.until;
      return inTurns('v1/findings/bulk', body, 'findings');
    },
  });
  if (!result) return false;
  await manyDone(result, spec.verb, 'finding');
  return true;
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
    // The people it reached answer it: on its page, all the ways they can.
    if (yours && detail && f.level) {
      buttons.push(h('button', { type: 'button', class: 'btn btn--sm', onclick: () => act('not-mine') }, icon('arrow'), 'Not mine'));
    }
    if (yours && detail && !f.details?.exception_request) {
      buttons.push(h('button', { type: 'button', class: 'btn btn--sm', onclick: () => act('exception') }, icon('shield-check'), 'Ask for an exception'));
    }
    if (yours || triage) {
      buttons.push(h('button', { type: 'button', class: 'btn btn--sm', title: 'Say you fixed it: AgentGov checks it again now, where it can', onclick: () => act('recheck') }, icon('refresh'), 'I fixed it'));
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
  // An exception its people asked for: what they asked, to agree to or change.
  const asked = f.details?.exception_request;
  const later = asked?.until?.slice(0, 10) || new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10);
  const done = await ask({
    title: 'Accept the risk?',
    text: `${f.title}. It goes to nobody until the date you choose, then opens again if it still holds. A year at most: then someone decides again.`,
    iconName: 'shield-check', confirm: 'Accept risk',
    fields: [
      { id: 'reason', label: 'Why it is acceptable', type: 'textarea', required: true, value: asked?.reason || null, hint: 'Recorded in the evidence ledger, and shown with the finding.' },
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
// yours, asking for an exception, declining one, and saying you fixed it. Resolves to
// whether something was done, or null for the other actions.
async function answerIssue(f, action) {
  const path = `v1/findings/${encodeURIComponent(f.id)}`;
  if (action === 'accept') return Boolean(await acceptRisk(f));
  if (action === 'not-mine') {
    const done = await ask({
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
    const done = await ask({
      title: 'Ask for an exception?',
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
    const done = await ask({
      title: 'Decline the exception?',
      text: `${f.title}. It stays with whoever asked, to fix.`,
      iconName: 'x', confirm: 'Decline',
      fields: [{ id: 'reason', label: 'Why not', type: 'textarea', required: true, hint: 'Recorded in the evidence ledger, and shown with the finding.' }],
      submit: (v) => api(`${path}/exception/decline`, { method: 'POST', body: { reason: v.reason } }),
    });
    if (done) toast('Declined.');
    return Boolean(done);
  }
  if (action === 'dismiss') {
    const done = await ask({
      title: 'Dismiss it?',
      text: `${f.title}. Dismiss what is wrong: to live with a real risk, accept it. It goes to nobody; given a date, it opens again then if it still holds. A threat opens again when it happens again.`,
      iconName: 'minus', confirm: 'Dismiss',
      fields: [
        { id: 'reason', label: 'Why it is wrong', type: 'textarea', required: true, hint: 'Recorded in the evidence ledger, and shown with the finding.' },
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
function exceptionAsked(f, act) {
  const asked = f.details?.exception_request;
  if (!asked || f.status !== 'open') return null;
  return callout('warning', 'shield-check', h('div', { class: 'stack', style: 'gap:8px' },
    h('span', {}, h('strong', {}, `${asked.by} asks for its risk to be accepted until ${String(asked.until).slice(0, 10)}: `), asked.reason),
    mayTriage() ? h('div', { class: 'btn-row' },
      h('button', { type: 'button', class: 'btn btn--sm btn--primary', onclick: () => act('accept') }, icon('shield-check'), 'Accept the risk'),
      h('button', { type: 'button', class: 'btn btn--sm', onclick: () => act('decline-exception') }, icon('x'), 'Decline')) : null));
}

function findingCard(f, agentsById, act, { yours = false, choose = null } = {}) {
  const tone = toneOf('severity', f.severity);
  const agent = f.agent_id ? agentsById.get(f.agent_id) : null;
  const headingId = `finding-title-${f.id}`;
  const subject = f.agent_id && !isPerson() ? agentLink(f.agent_id, agent?.name || f.subject) : h('code', {}, agent?.name || f.subject);
  return h('article', { class: 'card finding', 'data-tone': tone, 'aria-labelledby': headingId, tabindex: '-1', 'data-focus-key': `finding-${f.id}` },
    h('div', { class: 'finding-stripe', 'aria-hidden': 'true' }),
    h('div', { class: 'finding-main' },
      h('div', { class: 'finding-top' },
        choose ? h('label', { class: 'check finding-choose' }, h('input', {
          type: 'checkbox', checked: choose.selected.has(f.id), 'data-focus-key': `choose-${f.id}`, 'aria-label': `Choose: ${f.title}`,
          onchange: (e) => choose.onSelect([f.id], e.target.checked),
        })) : null,
        chip('severity', f.severity), plainChip(humanize(f.category)),
        f.status !== 'open' ? chip('finding', f.status) : null,
        f.verified === false ? plainChip('Unverified', { tone: 'warning', iconName: 'triangle', title: `${cap(f.unverified_reason || 'the sync that checks it failed')}: it may no longer hold.` }) : null,
        f.status === 'open' && f.details?.exception_request ? plainChip('Exception asked', { tone: 'warning', iconName: 'shield-check', title: `${f.details.exception_request.by}: ${f.details.exception_request.reason}` }) : null,
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
    const answered = await answerIssue(f, action);
    if (answered === false) return;
    if (answered === null) {
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
      `${f.unverified_reason || 'the latest sync that checks it failed'}, so it may no longer hold. It stays open until its check runs again.`)) : null,
    exceptionAsked(f, act),
    card({
      title: 'What it is',
      body: h('div', { class: 'stack' },
        f.description ? h('p', {}, f.description) : null,
        f.remediation ? h('p', { class: 'finding-fix' }, h('strong', {}, 'How to fix: '), f.remediation) : null,
        facts([
          ['Subject', subject],
          ['Seen', `${f.occurrences === 1 ? 'once' : `${fmt(f.occurrences)} times`}, first `, timeEl(f.first_seen), ', last ', timeEl(f.last_seen)],
          f.status === 'accepted' ? ['Risk accepted until', [timeEl(f.accepted_until, { absolute: true }), f.accepted_reason ? `: ${f.accepted_reason}` : '']] : null,
          f.status === 'dismissed' && f.details?.dismissal ? ['Dismissed because', [f.details.dismissal.reason,
            f.details.dismissal.until ? [' (until ', timeEl(f.details.dismissal.until, { absolute: true }), ')'] : '']] : null,
          f.acknowledged_at ? ['Acknowledged', [`by ${f.acknowledged_by} `, timeEl(f.acknowledged_at)]] : null,
          f.resolved_at && f.status !== 'open' ? [humanize(f.status), [`by ${f.resolved_by || 'unknown'} `, timeEl(f.resolved_at)]] : null,
        ].map((row) => row && [row[0], Array.isArray(row[1]) ? h('span', {}, row[1]) : h('span', {}, ...row.slice(1))])),
        h('div', { class: 'btn-row' }, findingActions(f, act, { yours: f.yours, detail: true }))),
    }),
    f.type.startsWith('access.') ? await findingAccessCard(f) : null,
    findingAttestCard(f),
    chainCard(f),
    ticketsCard(f),
    notificationsCard(f),
    historyCard(f));
}

// An issue that an agent's review is due: its sponsors attest it from here, whatever their
// role (the people the issue reached see this page, not the agent's).
function findingAttestCard(f) {
  if (!f.type.startsWith('agent.attestation') || !f.agent_id || f.status !== 'open') return null;
  if (!f.yours && !can('admin')) return null;
  const attest = guarded(async () => {
    const values = await ask({
      title: 'Attest this agent?',
      text: 'Confirm that it is still needed and that its access is still right. Its sponsors do this.',
      iconName: 'shield-check', confirm: 'Attest',
      fields: [{ id: 'note', label: 'Note (optional)', type: 'textarea', hint: 'Recorded in the evidence ledger.' }],
    });
    if (!values) return;
    const updated = await api(`v1/agents/${encodeURIComponent(f.agent_id)}/attest`, { method: 'POST', body: values.note ? { note: values.note } : {} });
    const due = updated.attestation?.expires_at;
    toast(due ? `Attested: reviewed again on ${due.slice(0, 10)}. The issue closes at the next check.` : 'Attested. The issue closes at the next check.');
  });
  return card({
    title: 'Is it still needed?',
    body: h('div', { class: 'stack' },
      h('p', {}, 'One of its sponsors confirms that it is still needed and that its access is still right. If it isn\'t needed, say so to an administrator, who deletes it.'),
      h('div', { class: 'btn-row' }, h('button', { type: 'button', class: 'btn btn--primary btn--sm', onclick: attest }, icon('shield-check'), 'Attest'))),
  });
}

// An issue about an access package: what it is, and renewing, keeping or removing it.
async function findingAccessCard(f) {
  const row = await api(`v1/access-assignments/${encodeURIComponent(f.subject)}`).catch(() => null);
  if (!row) return null;
  const packages = await api('v1/access-packages').catch(() => []);
  const pk = packages.find((x) => x.name === row.package);
  const agent = { id: row.agent_id, name: row.agent_name };
  const held = ['active', 'expired'].includes(row.status);
  const after = guarded(async (done) => { if (done) { refreshBadges(); await refresh(); } });
  const buttons = held ? [
    pk && f.type !== 'access.review_due' ? h('button', { type: 'button', class: 'btn btn--sm btn--primary', onclick: async () => after(await requestPackage(agent, packages, pk)) }, icon('refresh'), 'Renew') : null,
    f.type === 'access.review_due' ? h('button', { type: 'button', class: 'btn btn--sm btn--primary', onclick: async () => after(await reviewAssignment(row, true)) }, icon('check'), 'Keep it') : null,
    f.type === 'access.review_due' ? h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', onclick: async () => after(await reviewAssignment(row, false)) }, icon('ban'), 'Remove it') : null,
    can('approve') || can('contain') ? h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', onclick: async () => after(await assignmentAction(row, 'revoke')) }, icon('ban'), 'Revoke') : null,
  ].filter(Boolean) : [];
  return card({
    title: 'Access package',
    body: h('div', { class: 'stack' },
      facts([
        ['Package', h('span', {}, row.package, ' ', chip('access', row.status))],
        ['Agent', isPerson() ? row.agent_name : agentLink(row.agent_id, row.agent_name)],
        row.expires_at ? ['Expires', timeEl(row.expires_at, { absolute: true })] : null,
        ['Asked for by', `${row.requested_by}: ${row.reason}`],
        pk ? ['Grants', [...pk.permissions.map((g) => `${g.server}: ${g.tools.join(', ')}`), ...pk.model_access.map((m) => `${m.provider}: ${m.models.join(', ')}`), ...pk.agent_access.map((x) => `agent ${x}`)].join('; ')] : null,
      ]),
      buttons.length ? h('div', { class: 'btn-row' }, buttons) : null),
  });
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

// Its tickets in the service desks, and how each stands there.
function ticketsCard(f) {
  const rows = f.tickets || [];
  if (!rows.length) return null;
  return card({
    title: 'Tickets',
    sub: 'In your service desks: AgentGov keeps each in step with the issue, and reads back what happens to it there. Taking a ticket on there takes the issue on.',
    flush: true,
    body: h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
      h('caption', { class: 'sr-only' }, 'Tickets'),
      h('thead', {}, h('tr', {}, ['Ticket', 'There', 'AgentGov'].map((t) => h('th', { scope: 'col' }, t)))),
      h('tbody', {}, rows.map((t) => h('tr', {},
        h('td', { 'data-label': 'Ticket', class: 'break' },
          t.url && t.key ? h('a', { href: t.url, target: '_blank', rel: 'noopener', class: 'cell-title' }, t.key, ' ', icon('external')) : h('span', { class: 'cell-title' }, t.key || 'Not opened yet'),
          h('div', { class: 'cell-sub' }, `${t.desk}${t.team ? `, team ${t.team}` : ''}`),
          t.replaces ? h('div', { class: 'cell-sub' }, `Takes over from ${t.replaces}`) : null),
        h('td', { 'data-label': 'There' }, t.state ? h('span', {}, t.state) : h('span', { class: 'muted' }, '—'),
          t.assignee ? h('div', { class: 'cell-sub' }, t.assignee) : null,
          t.synced_at ? h('div', { class: 'cell-sub' }, 'Read ', timeEl(t.synced_at)) : null),
        h('td', { 'data-label': 'AgentGov' }, chip('ticket', t.status),
          t.last_error ? h('div', { class: 'cell-sub break' }, t.last_error) : null,
          t.next_attempt_at && t.attempts ? h('div', { class: 'cell-sub' }, 'Tries again ', timeEl(t.next_attempt_at)) : null)))))),
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
        e.details?.ticket ? ` · ${e.details.desk ? `${e.details.desk} ` : ''}${e.details.ticket}` : '',
        e.details?.why ? ` · ${e.details.why}` : '',
        e.details?.outcome ? ` · ${e.details.outcome}` : '',
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
      title: 'Teams',
      sub: "Teams own agents (as an agent's owner or sponsor), and take the issues about them that their owners and sponsors didn't acknowledge in time.",
      actions: [
        admin ? h('button', { type: 'button', class: 'btn btn--primary', 'data-focus-key': 'add-team', onclick: guarded(() => teamForm(null, chats)) }, icon('plus'), 'Add team') : null,
        refreshButton(),
      ],
    }),
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
      if (editing) return api(`v1/teams/${encodeURIComponent(t.name)}`, { method: 'PATCH', body, ifMatch: t.version });
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

/* ----------------------------------------------------------- finding types */

// Which types of findings are raised here, and how severe each is (docs/issues.md).
async function renderFindingTypes() {
  if (isPerson()) { location.replace('#/findings'); return h('div'); }
  const types = await api('v1/finding-types');
  const admin = can('admin');
  const off = types.filter((t) => t.mode === 'off');
  const body = types.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
    h('caption', { class: 'sr-only' }, 'Types of findings'),
    h('thead', {}, h('tr', {}, ['Type', 'Raised', 'Severity', 'Open', ''].map((t) => h('th', { scope: 'col' }, t || h('span', { class: 'sr-only' }, 'Actions'))))),
    h('tbody', {}, types.map((t) => h('tr', { 'data-type': t.type },
      h('td', { 'data-label': 'Type', class: 'break' }, h('span', { class: 'cell-title mono' }, t.type),
        t.changed_by ? h('div', { class: 'cell-sub' }, `Set by ${t.changed_by.replace(/^[a-z]+:/, '')} `, timeEl(t.changed_at)) : null),
      h('td', { 'data-label': 'Raised' }, t.mode === 'off'
        ? plainChip('Off', { tone: 'warning', iconName: 'minus', title: 'Checked, but what it finds is kept dismissed' })
        : plainChip('On', { tone: 'good', iconName: 'check-circle' })),
      h('td', { 'data-label': 'Severity' }, t.severity ? chip('severity', t.severity) : h('span', { class: 'muted' }, "Its checks' own")),
      h('td', { 'data-label': 'Open' }, `${fmt(t.open)} of ${fmt(t.total)}`),
      h('td', { 'data-label': '' }, admin
        ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `ftype-${t.type}`, onclick: guarded(() => findingTypeForm(t)) }, icon('edit'), 'Change')
        : null))))))
    : emptyState('No findings yet', 'A type is listed once AgentGov raises a finding of it, or once it is set up here.');
  return h('div', { class: 'page', 'data-title': 'Finding types' },
    pageHead({
      title: 'Findings',
      sub: "Each type of finding AgentGov's checks raise. Turn off the types your organisation doesn't act on: they are still checked, but what they find is kept dismissed and reaches no one. Or say how severe a type is here.",
      actions: [
        admin ? h('button', { type: 'button', class: 'btn btn--primary', 'data-focus-key': 'add-finding-type', onclick: guarded(() => findingTypeForm(null)) }, icon('plus'), 'Set up a type') : null,
        refreshButton(),
      ],
    }),
    findingTabs('types'),
    off.length ? callout('neutral', 'info', h('span', {}, h('strong', {}, `${plural(off.length, 'type')} off: `),
      off.length === 1
        ? 'what it finds is kept dismissed. Turned on again, what its checks find again comes back the next time they run.'
        : 'what they find is kept dismissed. Turned on again, what their checks find again comes back the next time they run.')) : null,
    card({ title: 'Types of findings', flush: Boolean(types.length), body }));
}

async function findingTypeForm(t) {
  const saved = await ask({
    title: t ? `Finding type ${t.type}` : 'Set up a type of finding',
    text: t ? 'Changes are recorded in the evidence ledger.' : 'Set up a type before its checks raise anything, such as agent.no_owner (docs/issues.md lists them). Changes are recorded in the evidence ledger.',
    iconName: 'edit', confirm: 'Save',
    fields: [
      t ? null : { id: 'type', label: 'Type', required: true, mono: true, placeholder: 'agent.no_owner' },
      {
        id: 'mode', label: 'Raised', type: 'select', value: t?.mode || 'on',
        options: [
          { value: 'on', label: 'On: raised and sent to the people responsible' },
          { value: 'off', label: 'Off: checked, but what it finds is kept dismissed' },
        ],
        hint: 'Turned off, its open findings are dismissed.',
      },
      {
        id: 'severity', label: 'Severity', type: 'select', value: t?.severity || '',
        options: [{ value: '', label: "Its checks' own" }, ...SEVERITY_ORDER.map((k) => ({ value: k, label: statusMeta('severity', k)[2] }))],
        hint: 'For what it finds from now on, and what it found that is still open.',
      },
    ].filter(Boolean),
    submit: (v) => api(`v1/finding-types/${encodeURIComponent(t ? t.type : v.type)}`, {
      method: 'PUT', body: { mode: v.mode, severity: v.severity || null },
    }),
  });
  if (!saved) return;
  toast(`${saved.type}: ${saved.mode === 'off' ? 'off' : 'on'}, ${saved.severity ? `severity ${saved.severity}` : "its checks' severity"}.`);
  await refresh();
}

/* ---------------------------------------------------------------- policies */

async function renderPolicies() {
  const [blueprints, policies, agents, servers, providers, packages, rules, modes] = await Promise.all([
    api('v1/blueprints'), api('v1/policies'), api('v1/agents'), api('v1/toolservers'), api('v1/models/providers'),
    api('v1/access-packages').catch(() => []), api('v1/rules').catch(() => []), featureModes().catch(() => ({})),
  ]);
  const usage = countBy(agents, (a) => a.blueprint || '');
  const exportBtn = h('button', { type: 'button', class: 'btn', 'data-focus-key': 'export-yaml' }, icon('download'), 'Export manifests');
  exportBtn.addEventListener('click', async () => {
    exportBtn.disabled = true;
    try {
      const blob = await saveDownload('v1/export', `agentgov-manifests-${fileStamp()}.yaml`);
      toast(`Exported the registry as YAML manifests (${fmtBytes(blob.size)}).`);
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
        h('section', { class: 'stack', 'aria-labelledby': 'pkg-title' },
          h('div', { class: 'section-title' },
            h('div', {}, h('h2', { id: 'pkg-title' }, 'Access packages'),
              h('p', {}, 'Grants agents hold for a while once approved: asked for, reminded before they expire, renewed or reviewed')),
            sectionAction('New package', 'new-package', () => packageForm(null, servers, blueprints))),
          packages.length
            ? h('div', { class: 'bp-grid' }, packages.map((pk) => packageCard(pk, servers, blueprints)))
            : h('section', { class: 'card' }, emptyState('No access packages', admin
              ? 'Create one for access agents need for a while: a project, an incident, a pilot.'
              : 'An admin creates access packages here, with the CLI or with an AccessPackage manifest.'))),
        h('section', { class: 'stack', 'aria-labelledby': 'rules-title' },
          h('div', { class: 'section-title' },
            h('div', {}, h('h2', { id: 'rules-title' }, 'Management rules'),
              h('p', {}, 'What to do about agents that meet some conditions for long enough, after telling their people')),
            admin ? h('div', { class: 'btn-row' },
              rules.length ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'run-rules', onclick: guarded(runRules) }, icon('refresh'), 'Run now') : null,
              sectionAction('New rule', 'new-rule', () => ruleForm(null, blueprints))) : null),
          rulesNote(modes),
          rules.length
            ? h('div', { class: 'bp-grid' }, rules.map((r) => ruleCard(r, blueprints)))
            : h('section', { class: 'card' }, emptyState('No management rules', admin
              ? 'Add one to block agents nobody uses, give ownerless agents an owner, or clean up stale registrations, after telling their people.'
              : 'An admin adds management rules here, with the CLI or with a ManagementRule manifest.'))),
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
      if (editing) return api(`v1/blueprints/${encodeURIComponent(b.name)}`, { method: 'PATCH', body, ifMatch: b.version });
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
      if (editing) return api(`v1/policies/${encodeURIComponent(p.name)}`, { method: 'PUT', body, ifMatch: p.version });
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

function packageCard(pk, servers, blueprints) {
  const held = pk.assignments.active + pk.assignments.expired;
  return card({
    title: pk.name, level: 'h3', id: `pkg-${pk.id}`,
    sub: pk.description,
    actions: [plainChip(`Up to ${plural(pk.duration_days, 'day')}`, { iconName: 'clock' })],
    foot: can('admin') ? h('div', { class: 'btn-row' },
      h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `pkg-edit-${pk.name}`, onclick: guarded(() => packageForm(pk, servers, blueprints)) }, icon('edit'), 'Edit'),
      h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', 'data-focus-key': `pkg-delete-${pk.name}`, onclick: guarded(() => deletePackage(pk)) }, icon('trash'), 'Delete')) : null,
    body: [
      facts([
        ['Held by', held ? plural(held, 'agent') : h('span', { class: 'muted' }, 'No agents'), pk.assignments.requested ? ` · ${fmt(pk.assignments.requested)} waiting` : ''],
        ['Requests', pk.approval ? 'An approver decides' : 'Granted at once'],
        ['Reviews', pk.review_days ? `Every ${plural(pk.review_days, 'day')}` : 'None'],
        ['For agents on', pk.blueprints.length ? pk.blueprints.join(', ') : 'Any blueprint'],
        pk.model_access.length ? ['Models', h('div', { class: 'chip-row' }, pk.model_access.map((m) => plainChip(`${m.provider}: ${m.models.join(', ')}`, { mono: true })))] : null,
        pk.agent_access.length ? ['May call agents', h('div', { class: 'chip-row' }, pk.agent_access.map((x) => plainChip(x, { mono: true })))] : null,
      ].map((row) => row && [row[0], h('span', {}, ...row.slice(1))])),
      pk.permissions.length ? [h('div', { class: 'field-label' }, 'Tools'), permissionList(pk.permissions)] : null,
    ],
  });
}

async function packageForm(pk, servers, blueprints) {
  const editing = Boolean(pk);
  const saved = await ask({
    title: editing ? `Edit access package ${pk.name}` : 'New access package',
    text: editing
      ? 'Every agent that holds it gets the change as soon as OPA loads the updated policy bundle.'
      : 'Agents hold what it grants for a while once a request is approved. Before it expires, the people responsible for the agent are told, so they can renew it.',
    iconName: editing ? 'edit' : 'policies', confirm: editing ? 'Save changes' : 'Create package', wide: true,
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'crm-write', hint: NAME_HINT },
      { id: 'description', label: 'Description', type: 'textarea', value: pk?.description || '' },
      {
        id: 'permissions', label: 'Tool grants', type: 'code', rows: 3, value: formatGrants(pk?.permissions), placeholder: 'crm: update_customer',
        hint: `One server per line; tool names can use * wildcards.${servers.length ? ` Registered servers: ${servers.map((ts) => ts.name).join(', ')}.` : ''}`,
      },
      { id: 'model_access', label: 'Model access', type: 'code', rows: 2, value: formatModelAccess(pk?.model_access), placeholder: 'openai: gpt-4.1', hint: 'One provider per line.' },
      { id: 'agent_access', label: 'Agents it lets call', value: (pk?.agent_access || []).join(', '), placeholder: 'billing-agent', mono: true, hint: 'Over A2A, separated by commas; names can use * wildcards.' },
      { type: 'row', fields: [
        { id: 'duration_days', label: 'Lasts at most (days)', type: 'number', min: 1, value: pk?.duration_days ?? 90, required: true },
        { id: 'review_days', label: 'Review every (days)', type: 'number', min: 1, value: pk?.review_days ?? '', hint: 'Empty: no reviews.' },
      ] },
      { id: 'approval', label: 'An approver decides each request', type: 'checkbox', value: pk ? pk.approval : true, hint: 'Otherwise it is granted as soon as someone allowed asks for it.' },
      {
        id: 'blueprints', label: 'For agents on these blueprints', value: (pk?.blueprints || []).join(', '), mono: true,
        hint: `Separated by commas. Empty: any agent.${blueprints.length ? ` Blueprints: ${blueprints.map((b) => b.name).join(', ')}.` : ''}`,
      },
    ].filter(Boolean),
    submit: (v) => {
      const whole = (text, label) => {
        if (!text) return null;
        const n = Number(text);
        if (!(Number.isInteger(n) && n > 0 && n <= 365)) throw new Error(`${label} is a whole number of days from 1 to 365.`);
        return n;
      };
      const body = {
        description: v.description, permissions: parseGrants(v.permissions), model_access: parseModelAccess(v.model_access),
        agent_access: parseList(v.agent_access), blueprints: parseList(v.blueprints), approval: v.approval,
        duration_days: whole(v.duration_days, 'How long it lasts'), review_days: whole(v.review_days, 'The review period'),
      };
      if (editing) return api(`v1/access-packages/${encodeURIComponent(pk.name)}`, { method: 'PATCH', body, ifMatch: pk.version });
      return api('v1/access-packages', { method: 'POST', body: { name: v.name, ...body } });
    },
  });
  if (!saved) return;
  toast(editing ? `Saved access package ${saved.name}.` : `Created access package ${saved.name}.`);
  await refresh();
}

async function deletePackage(pk) {
  const done = await ask({
    title: `Delete access package ${pk.name}?`,
    text: 'Packages that agents hold or ask for cannot be deleted: revoke or deny those first.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete package', busy: 'Deleting…',
    submit: () => api(`v1/access-packages/${encodeURIComponent(pk.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted access package ${pk.name}.`);
  await refresh();
}

/* ------------------------------------------------------ management rules */

const RULE_ACTIONS = {
  issue: 'Raise an issue',
  assign_owner: 'Give it an owner',
  block: 'Block it',
  delete: 'Delete it',
  revoke_access: 'Revoke its access packages',
};
const RULE_MISSING = { workload_identity: 'workload identity' };

// What an agent must meet, in words.
function ruleWhen(c) {
  const parts = [];
  if (c.inactive_days) parts.push(`no activity for ${plural(c.inactive_days, 'day')}`);
  if (c.missing) parts.push(`no ${c.missing.map((m) => RULE_MISSING[m] || m).join(' or no ')}`);
  if (c.attestation_overdue_days != null) parts.push(c.attestation_overdue_days ? `attestation overdue for ${plural(c.attestation_overdue_days, 'day')}` : 'attestation overdue');
  if (c.findings) parts.push(`an open ${c.finding_severity ? `${c.finding_severity}+ ` : ''}finding: ${c.findings.join(', ')}`);
  if (c.risk_level) parts.push(`${c.risk_level} risk or more`);
  if (c.status) parts.push(`it is ${c.status.join(' or ')}`);
  return parts.join(' · ') || '—';
}

const RULE_PLATFORMS = {
  gateway: 'the gateway', 'microsoft-365': 'Microsoft 365', 'copilot-studio': 'Copilot Studio',
  aws: 'AWS', 'google-cloud': 'Google Cloud', salesforce: 'Salesforce', databricks: 'Databricks',
  'microsoft-foundry': 'Microsoft Foundry',
};

function ruleScope(scope) {
  const parts = [];
  if (scope.platforms?.length) parts.push(`on ${scope.platforms.map((x) => RULE_PLATFORMS[x] || x).join(' or ')}`);
  for (const [key, label] of [['blueprints', 'blueprint'], ['teams', 'team'], ['environments', 'environment']]) {
    if (scope[key]?.length) parts.push(`${label} ${scope[key].join(' or ')}`);
  }
  if (scope.labels && Object.keys(scope.labels).length) parts.push(`labelled ${formatLabels(scope.labels)}`);
  return parts.length ? parts.join(' · ') : 'All agents';
}

function ruleThen(r) {
  const what = r.action === 'assign_owner' ? `Make ${r.params.owner} its owner` : RULE_ACTIONS[r.action] || r.action;
  if (r.action === 'issue') return r.after_days ? `${what}, once it has matched for ${plural(r.after_days, 'day')}` : `${what}, at once`;
  return `${what}, ${plural(r.after_days, 'day')} after telling its people`;
}

function rulesNote(modes) {
  const mode = modes['management-rules'];
  if (mode === 'off') return callout('warning', 'minus', h('span', {}, h('strong', {}, 'Off: '), 'management rules are off in Features, so no rule runs.'));
  if (modes['posture-checks'] === 'off') return callout('warning', 'triangle', h('span', {}, h('strong', {}, 'Not running: '), 'rules run after each posture scan, and posture checks are off in Features.'));
  if (mode === 'monitor') return callout('neutral', 'eye', h('span', {}, h('strong', {}, 'Monitored: '), 'rules tell nobody and change nothing; they record what they would have done. Enforce the feature in Features, and a rule, for it to act.'));
  return null;
}

function ruleCard(r, blueprints) {
  const capped = r.mode !== r.effective_mode;
  return card({
    title: r.name, level: 'h3', id: `rule-${r.id}`,
    sub: r.description,
    actions: [chip('mode', r.effective_mode, { title: capped ? `${humanize(r.mode)} in the rule, ${r.effective_mode} by the feature` : null })],
    foot: h('div', { class: 'btn-row' },
      h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `rule-preview-${r.name}`, onclick: guarded(() => rulePreview(r)) }, icon('eye'), 'Preview'),
      can('admin') ? [
        h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `rule-edit-${r.name}`, onclick: guarded(() => ruleForm(r, blueprints)) }, icon('edit'), 'Edit'),
        h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', 'data-focus-key': `rule-delete-${r.name}`, onclick: guarded(() => deleteRule(r)) }, icon('trash'), 'Delete'),
      ] : null),
    body: facts([
      ['When', ruleWhen(r.conditions)],
      ['Agents', ruleScope(r.scope)],
      ['Then', ruleThen(r)],
      ['At once', `${plural(r.max_actions, 'agent')} at most`],
      ['Matching', [r.matches.matching ? plural(r.matches.matching, 'agent') : h('span', { class: 'muted' }, 'No agents'),
        r.matches.acted ? ` · acted on ${fmt(r.matches.acted)}` : '', r.matches.would_have_acted ? ` · would have acted on ${fmt(r.matches.would_have_acted)}` : '']],
      capped ? ['Mode', `${humanize(r.mode)} in the rule; ${r.effective_mode} by the feature`] : null,
    ]),
  });
}

// What a rule matches now and would do: for a saved rule, or the form's draft.
function rulePreviewView(view) {
  const notes = [];
  if (!view.running) notes.push(callout('warning', 'triangle', h('span', {}, h('strong', {}, 'Not running: '), `${view.why_not}.`)));
  else if (view.mode === 'monitor') notes.push(callout('neutral', 'eye', h('span', {}, h('strong', {}, 'Monitored: '), 'it tells nobody and changes nothing; it records what it would have done.')));
  if (view.held_back) notes.push(callout('critical', 'octagon', h('span', {}, h('strong', {}, 'Too many at once: '), `${fmt(view.due)} agents are due, more than its limit of ${fmt(view.max_actions)}, so it acts on none of them and raises an issue about itself.`)));
  const line = (e) => h('li', { class: 'access-row' },
    h('div', { class: 'access-main' },
      h('div', { class: 'cell-title' }, agentLink(e.agent_id, e.agent), ' ', chip('rule', e.state)),
      h('div', { class: 'cell-sub break' }, humanize(e.detail), e.reasons.length ? ` · ${e.reasons.join('; ')}` : '')));
  return h('div', { class: 'stack rule-preview' },
    h('p', { class: 'muted' }, `${plural(view.matching, 'agent')} ${view.matching === 1 ? 'matches' : 'match'} now${view.due ? `, ${fmt(view.due)} due` : ''}.`),
    notes,
    view.agents.length ? h('ul', { class: 'access-list', role: 'list' }, view.agents.map(line)) : null,
    view.unknown_count ? h('details', { class: 'disclosure' }, h('summary', {}, icon('chevron'), `Can't tell for ${plural(view.unknown_count, 'agent')}`),
      h('ul', { class: 'access-list', role: 'list' }, view.unknown.map((u) => h('li', { class: 'access-row' },
        h('div', { class: 'access-main' }, h('div', { class: 'cell-title' }, agentLink(u.agent_id, u.agent)), h('div', { class: 'cell-sub break' }, u.why)))))) : null);
}

async function rulePreview(r) {
  const view = await api(`v1/rules/${encodeURIComponent(r.name)}/preview`);
  await ask({ title: `Preview: ${r.name}`, text: 'The agents the rule matches now, since when, and what it will do to each.', iconName: 'eye', confirm: 'Close', cancel: null, wide: true, extra: rulePreviewView(view) });
}

function ruleBody(v) {
  const whole = (text, label, min, max) => {
    if (text === '' || text == null) return null;
    const n = Number(text);
    if (!(Number.isInteger(n) && n >= min && n <= max)) throw new Error(`${label} is a whole number from ${min} to ${max}.`);
    return n;
  };
  const pick = (entries) => Object.fromEntries(entries.filter(([, value]) => value != null && value !== '' && !(Array.isArray(value) && !value.length)));
  const labels = parseLabels(v.scope_labels);
  return {
    description: v.description,
    conditions: pick([
      ['inactive_days', whole(v.inactive_days, 'No activity for', 1, 3650)],
      ['attestation_overdue_days', whole(v.attestation_overdue_days, 'Attestation overdue for', 0, 3650)],
      ['missing', parseList(v.missing)],
      ['findings', parseList(v.findings)],
      ['finding_severity', v.finding_severity],
      ['risk_level', v.risk_level],
      ['status', parseList(v.status)],
    ]),
    scope: pick([
      ['blueprints', parseList(v.blueprints)], ['teams', parseList(v.teams)],
      ['environments', parseList(v.environments)], ['platforms', parseList(v.platforms)],
      ['labels', Object.keys(labels).length ? labels : null],
    ]),
    action: v.action,
    params: v.action === 'assign_owner' ? { owner: v.owner } : {},
    after_days: whole(v.after_days, 'After', 0, 365) ?? 14,
    max_actions: whole(v.max_actions, 'At most at once', 1, 1000) ?? 10,
    severity: v.severity,
    mode: v.mode,
    labels: parseLabels(v.labels),
  };
}

/** Create a rule (no `r`) or edit one, with a preview of what it matches before saving. */
async function ruleForm(r, blueprints) {
  const editing = Boolean(r);
  const teams = await api('v1/teams').catch(() => []);
  const c = r?.conditions || {};
  const scope = r?.scope || {};
  const options = (values, any) => [...(any ? [{ value: '', label: any }] : []), ...values.map((x) => ({ value: x, label: humanize(x) }))];
  let controls = {};
  const box = h('div', { class: 'rule-preview-box', 'aria-live': 'polite' });
  const previewBtn = h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'rule-form-preview' }, icon('eye'), 'Preview the agents it matches');
  previewBtn.addEventListener('click', async () => {
    const values = Object.fromEntries(Object.entries(controls).map(([k, el]) => [k, el.type === 'checkbox' ? el.checked : el.value.trim()]));
    previewBtn.disabled = true;
    try {
      const view = await api('v1/rules/preview', { method: 'POST', body: { ...ruleBody(values), name: values.name || r?.name || 'draft' } });
      box.replaceChildren(rulePreviewView(view));
    } catch (err) {
      box.replaceChildren(callout('critical', 'octagon', err.message));
    } finally {
      previewBtn.disabled = false;
    }
  });
  const saved = await ask({
    title: editing ? `Edit rule ${r.name}` : 'New management rule',
    text: 'When an agent meets all its conditions, the rule tells the agent’s people at once, and acts after its days of notice if the agent still matches. Monitored, it only records what it would have done.',
    iconName: editing ? 'edit' : 'policies', confirm: editing ? 'Save changes' : 'Create rule', wide: true,
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'inactive-agents', hint: NAME_HINT },
      { id: 'description', label: 'Description', type: 'textarea', rows: 2, value: r?.description || '' },
      { type: 'section', label: 'When an agent has all of these' },
      { type: 'row', fields: [
        { id: 'inactive_days', label: 'No activity for (days)', type: 'number', min: 1, value: c.inactive_days ?? '' },
        { id: 'attestation_overdue_days', label: 'Attestation overdue for (days)', type: 'number', min: 0, value: c.attestation_overdue_days ?? '' },
      ] },
      { id: 'missing', label: 'No', value: (c.missing || []).join(', '), mono: true, hint: 'Any of owner, sponsors, team, blueprint, workload_identity, separated by commas.' },
      { type: 'row', fields: [
        { id: 'findings', label: 'An open finding of type', value: (c.findings || []).join(', '), mono: true, placeholder: 'agent.stale', hint: '* wildcards, separated by commas.' },
        { id: 'finding_severity', label: 'Of severity', type: 'select', value: c.finding_severity || '', options: options(['low', 'medium', 'high', 'critical'], 'Any') },
      ] },
      { type: 'row', fields: [
        { id: 'risk_level', label: 'Risk at least', type: 'select', value: c.risk_level || '', options: options(['low', 'medium', 'high', 'critical'], 'Any') },
        { id: 'status', label: 'Status', value: (c.status || []).join(', '), mono: true, hint: 'pending, active, blocked or discovered.' },
      ] },
      { type: 'section', label: 'Which agents it looks at' },
      { type: 'row', fields: [
        { id: 'blueprints', label: 'Blueprints', value: (scope.blueprints || []).join(', '), mono: true, hint: `Empty: all of them.${blueprints.length ? ` Blueprints: ${blueprints.map((b) => b.name).join(', ')}.` : ''}` },
        { id: 'teams', label: 'Teams', value: (scope.teams || []).join(', '), mono: true, hint: teams.length ? `Teams: ${teams.map((t) => t.name).join(', ')}.` : null },
      ] },
      { type: 'row', fields: [
        { id: 'platforms', label: 'Platforms', value: (scope.platforms || []).join(', '), mono: true, hint: 'gateway, microsoft-365, copilot-studio, aws, google-cloud, salesforce, databricks or microsoft-foundry.' },
        { id: 'environments', label: 'Environments', value: (scope.environments || []).join(', '), mono: true },
      ] },
      { id: 'scope_labels', label: 'With labels', value: formatLabels(scope.labels), mono: true, hint: 'key=value, separated by commas. Agents labelled agentgov/exempt-rules with the rule’s name, or *, are left out.' },
      { type: 'section', label: 'What it does' },
      { type: 'row', fields: [
        { id: 'action', label: 'Action', type: 'select', required: true, value: r?.action || 'issue', options: Object.entries(RULE_ACTIONS).map(([value, label]) => ({ value, label })) },
        { id: 'owner', label: 'Owner it gives', value: r?.params?.owner || '', mono: true, datalist: teams.map((t) => t.name), hint: 'For "Give it an owner": a team, or an email address.' },
      ] },
      { type: 'row', fields: [
        { id: 'after_days', label: 'After (days)', type: 'number', min: 0, required: true, value: r?.after_days ?? 14, hint: 'How long an agent matches before the action. Rules that change something give a day’s notice at least.' },
        { id: 'max_actions', label: 'At most at once', type: 'number', min: 1, required: true, value: r?.max_actions ?? 10, hint: 'More agents due at once: it acts on none.' },
      ] },
      { type: 'row', fields: [
        { id: 'severity', label: 'Its issues’ severity', type: 'select', required: true, value: r?.severity || 'medium', options: options(['low', 'medium', 'high', 'critical']) },
        { id: 'mode', label: 'Mode', type: 'select', required: true, value: r?.mode || 'monitor', options: [{ value: 'monitor', label: 'Monitor: record what it would do' }, { value: 'enforce', label: 'Enforce: tell, then act' }, { value: 'off', label: 'Off' }] },
      ] },
      { id: 'labels', label: 'Labels', value: formatLabels(r?.labels), mono: true },
    ].filter(Boolean),
    after: h('div', { class: 'stack' }, h('div', { class: 'btn-row' }, previewBtn), box),
    onReady: (found) => { controls = found; },
    submit: (v) => {
      const body = ruleBody(v);
      if (editing) return api(`v1/rules/${encodeURIComponent(r.name)}`, { method: 'PATCH', body, ifMatch: r.version });
      return api('v1/rules', { method: 'POST', body: { name: v.name, ...body } });
    },
  });
  if (!saved) return;
  toast(editing ? `Saved rule ${saved.name}.` : `Created rule ${saved.name} (${saved.effective_mode}).`);
  await refresh();
}

async function deleteRule(r) {
  const done = await ask({
    title: `Delete rule ${r.name}?`,
    text: 'Its open issues are resolved. What it did stays done: blocked agents stay blocked until someone unblocks them.',
    tone: 'danger', iconName: 'trash', confirm: 'Delete rule', busy: 'Deleting…',
    submit: () => api(`v1/rules/${encodeURIComponent(r.name)}`, { method: 'DELETE' }),
  });
  if (!done) return;
  toast(`Deleted rule ${r.name}.`);
  await refresh();
}

async function runRules() {
  const out = await api('v1/rules/evaluate', { method: 'POST' });
  if (out.off) {
    toast('Management rules are off in Features.', { tone: 'warning' });
  } else {
    const sum = (key) => Object.values(out).reduce((n, counts) => n + (counts[key] || 0), 0);
    toast(`Rules ran: ${plural(sum('matching'), 'agent')} matching, ${fmt(sum('acted'))} acted on, ${fmt(sum('would_act'))} would have been, ${fmt(sum('held_back'))} held back.`);
  }
  await refresh();
}

function agentRulesCard(rows) {
  if (!Array.isArray(rows) || !rows.length) return null;
  return card({
    title: 'Management rules',
    sub: 'The rules it matches, and what each will do or did.',
    body: h('ul', { class: 'access-list', role: 'list' }, rows.map((r) => h('li', { class: 'access-row' },
      h('div', { class: 'access-main' },
        h('div', { class: 'cell-title' }, r.rule, ' ', chip('rule', r.state)),
        h('div', { class: 'cell-sub break' }, humanize(r.detail), ' · matching since ', timeEl(r.since)))))),
  });
}

/* -------------------------------------------- access packages on agents */

// Ask for a package for an agent; asked again while it holds one, it is a renewal.
async function requestPackage(agent, packages, current) {
  const choices = current ? [current] : packages;
  if (!choices.length) { toast('There are no access packages yet: an admin creates them on the Policies page.', { tone: 'warning' }); return null; }
  const first = choices[0];
  const done = await ask({
    title: current ? `Renew ${current.name} for ${agent.name}?` : `Request access for ${agent.name}`,
    text: current
      ? 'It carries on from now for the days you ask, and never ends sooner than it would have. An approver decides, unless the package needs no approval.'
      : 'An approver decides, unless the package needs no approval. The agent holds what it grants until it expires.',
    iconName: 'key', confirm: current ? 'Ask to renew' : 'Request access',
    fields: [
      current ? null : { id: 'package', label: 'Access package', type: 'select', value: first.name, options: choices.map((pk) => ({ value: pk.name, label: `${pk.name} (up to ${plural(pk.duration_days, 'day')})` })) },
      { id: 'days', label: 'For how many days', type: 'number', min: 1, value: first.duration_days, required: true },
      { id: 'reason', label: 'Why the agent needs it', type: 'textarea', required: true, hint: 'Recorded in the evidence ledger, and shown to the approver.' },
    ].filter(Boolean),
    submit: (v) => api('v1/access-assignments', {
      method: 'POST', body: { agent: agent.id || agent.agent_id, package: current ? current.name : v.package, days: Number(v.days), reason: v.reason },
    }),
  });
  if (!done) return null;
  toast(done.status === 'active' ? `${done.package} is granted to ${done.agent_name} until ${done.expires_at.slice(0, 10)}.` : `Asked for ${done.package} for ${done.agent_name}: an approver decides.`);
  return done;
}

async function assignmentAction(row, action) {
  const words = { approve: ['Approve', 'primary', 'check'], deny: ['Deny', 'danger', 'ban'], revoke: ['Revoke', 'danger', 'ban'] }[action];
  const done = await ask({
    title: `${words[0]} ${row.package} for ${row.agent_name}?`,
    text: action === 'revoke'
      ? 'The agent loses what it grants as soon as OPA loads the updated policy bundle.'
      : `Asked by ${row.requested_by} for ${plural(row.days, 'day')}: ${row.reason}`,
    tone: words[1], iconName: words[2], confirm: words[0],
    fields: [{ id: 'note', label: action === 'revoke' ? 'Reason' : 'Note', type: 'textarea', hint: 'Recorded in the evidence ledger.' }],
    submit: (v) => api(`v1/access-assignments/${encodeURIComponent(row.id)}/${action}`, {
      method: 'POST', body: action === 'revoke' ? { reason: v.note || null } : { note: v.note || null },
    }),
  });
  if (!done) return null;
  toast(`${{ approve: 'Approved', deny: 'Denied', revoke: 'Revoked' }[action]}: ${row.package} for ${row.agent_name}.`);
  return done;
}

async function reviewAssignment(row, keep) {
  const done = await ask({
    title: keep ? `Keep ${row.package} for ${row.agent_name}?` : `Remove ${row.package} from ${row.agent_name}?`,
    text: keep ? 'The agent still needs it: it holds it until it expires, and is asked again at its next review.' : 'The agent loses what it grants as soon as OPA loads the updated policy bundle.',
    tone: keep ? 'primary' : 'danger', iconName: keep ? 'check' : 'ban', confirm: keep ? 'Keep it' : 'Remove it',
    fields: [{ id: 'note', label: 'Note', type: 'textarea', hint: 'Recorded in the evidence ledger.' }],
    submit: (v) => api(`v1/access-assignments/${encodeURIComponent(row.id)}/review`, { method: 'POST', body: { keep, note: v.note || null } }),
  });
  if (done) toast(keep ? `Kept ${row.package} for ${row.agent_name}.` : `Removed ${row.package} from ${row.agent_name}.`);
  return done;
}

function assignmentButtons(row, packages, agent) {
  const buttons = [];
  const decider = can('approve');
  if (row.status === 'requested' && decider && row.requested_by === me?.actor) {
    buttons.push(h('span', { class: 'muted small' }, 'You asked for it: another approver decides.'));
  }
  if (row.status === 'requested' && decider && row.requested_by !== me?.actor) {
    buttons.push(
      h('button', { type: 'button', class: 'btn btn--sm btn--primary', onclick: guarded(async () => { if (await assignmentAction(row, 'approve')) await refresh(); }) }, icon('check'), 'Approve'),
      h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', onclick: guarded(async () => { if (await assignmentAction(row, 'deny')) await refresh(); }) }, icon('ban'), 'Deny'));
  }
  if (['active', 'expired'].includes(row.status)) {
    const pk = packages.find((x) => x.name === row.package);
    if (pk && decider) {
      buttons.push(h('button', { type: 'button', class: 'btn btn--sm', onclick: guarded(async () => { if (await requestPackage(agent, packages, pk)) await refresh(); }) }, icon('refresh'), 'Renew'));
    }
    if (decider || can('contain')) {
      buttons.push(h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', onclick: guarded(async () => { if (await assignmentAction(row, 'revoke')) await refresh(); }) }, icon('ban'), 'Revoke'));
    }
  }
  return buttons;
}

function entraAccessCard(agent, view) {
  const manage = view.mode === 'manage' && can('admin');
  const rows = view.held || [];
  const remove = (row) => guarded(async () => {
    const done = await ask({
      title: `Remove ${row.package} from ${agent.name} in Entra?`,
      text: "AgentGov asks Microsoft Entra to remove the assignment, as its app. Entra removes what it grants the agent's identity, or refuses; the next sync shows which.",
      tone: 'danger', iconName: 'ban', confirm: 'Ask Entra to remove it',
      submit: () => api(`v1/agents/${encodeURIComponent(agent.id)}/entra-access-packages/${encodeURIComponent(row.id)}`, { method: 'DELETE' }),
    });
    if (done) { toast(`Asked Entra to remove ${row.package} from ${agent.name}.`); await refresh(); }
  });
  const assign = guarded(async () => {
    const done = await ask({
      title: `Assign an Entra access package to ${agent.name}`,
      text: "AgentGov asks Microsoft Entra to assign it to the agent's Entra identity, as its app, through the package's policy for agents. The next sync shows it delivered.",
      iconName: 'key', confirm: 'Ask Entra to assign it',
      fields: [{ id: 'package', label: 'Access package', type: 'select', value: view.packages[0]?.id, options: view.packages.map((p) => ({ value: p.id, label: p.name })) }],
      submit: (v) => api(`v1/agents/${encodeURIComponent(agent.id)}/entra-access-packages/assign`, { method: 'POST', body: { package: v.package } }),
    });
    if (done) { toast(`Asked Entra to assign it to ${agent.name}.`); await refresh(); }
  });
  let body;
  if (view.mode === 'off') body = emptyState('Turned off', h('span', {}, 'Turn on Microsoft Entra access packages on the ', h('a', { href: '#/features' }, 'Features'), ' page.'));
  else if (!view.synced_at) body = emptyState('Not read yet', h('span', {}, 'The connection runs on a schedule, once AgentGov\'s app can read them (', h('a', { href: '#/platforms' }, 'Platforms'), ').'));
  else if (!rows.length) body = emptyState('None', 'Its Entra identity holds no access package.');
  else {
    body = h('ul', { class: 'access-list', role: 'list' }, rows.map((row) => h('li', { class: 'access-row' },
      h('div', { class: 'access-main' },
        h('div', { class: 'cell-title' }, row.package, ' ', chip('entra_access', row.state)),
        h('div', { class: 'cell-sub' }, row.expires_at ? ['Expires ', timeEl(row.expires_at)] : 'No end date')),
      manage ? h('div', { class: 'btn-row' }, h('button', { type: 'button', class: 'btn btn--sm btn--danger-quiet', onclick: remove(row) }, icon('ban'), 'Remove in Entra')) : null)));
  }
  return card({
    title: 'Entra access packages',
    sub: view.mode === 'manage' ? 'What Microsoft Entra ID Governance assigns its Entra identity. Administrators assign and remove them here.' : 'What Microsoft Entra ID Governance assigns its Entra identity, read by AgentGov.',
    actions: manage && view.packages.length ? [h('button', { type: 'button', class: 'btn btn--sm', onclick: assign }, icon('plus'), 'Assign')] : null,
    body,
  });
}

function agentAccessCard(agent, rows, packages, mode) {
  if (rows instanceof Error) return null;
  const current = rows.filter((r) => ['requested', 'active', 'expired'].includes(r.status));
  const earlier = rows.filter((r) => !current.includes(r));
  const line = (r) => h('li', { class: 'access-row' },
    h('div', { class: 'access-main' },
      h('div', { class: 'cell-title' }, r.package, ' ', chip('access', r.status)),
      h('div', { class: 'cell-sub break' },
        r.status === 'requested' ? [`Asked by ${r.requested_by} for ${plural(r.days, 'day')}: ${r.reason}`]
          : r.expires_at ? [r.status === 'expired' ? 'Expired ' : ['active'].includes(r.status) ? 'Expires ' : 'Ended ', timeEl(r.status === 'active' || r.status === 'expired' ? r.expires_at : r.ended_at || r.decided_at)]
            : [`${humanize(r.status)} by ${r.decided_by || 'unknown'}`])),
    h('div', { class: 'btn-row' }, assignmentButtons(r, packages, agent)));
  const expiredNote = current.some((r) => r.status === 'expired') && mode !== 'enforce'
    ? callout('warning', 'triangle', h('span', {}, h('strong', {}, 'Expired, still used: '),
      mode === 'off' ? 'access packages are off, so they grant nothing.' : 'expired packages are monitored, so the agent keeps the access. Renew or revoke them.'))
    : null;
  return card({
    title: 'Access packages',
    sub: 'Extra tools, models and agents it holds for a while once approved.',
    actions: can('approve') && packages.length ? [h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'request-access', onclick: guarded(async () => { if (await requestPackage(agent, packages, null)) await refresh(); }) }, icon('plus'), 'Request access')] : null,
    body: [
      expiredNote,
      current.length ? h('ul', { class: 'access-list', role: 'list' }, current.map(line))
        : emptyState('No access packages', packages.length ? 'Request one when the agent needs more for a while.' : null),
      earlier.length ? h('details', { class: 'disclosure' }, h('summary', {}, icon('chevron'), `Earlier (${fmt(earlier.length)})`),
        h('ul', { class: 'access-list', role: 'list' }, earlier.map(line))) : null,
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
    changesTable(e.details?.changes),
    Object.keys(e.details || {}).length ? jsonBlock(e.details) : null);
}

// What an edit changed, from what to what (long text by its length and SHA-256).
function changedValue(value) {
  if (value === null || value === undefined || value === '') return h('span', { class: 'muted' }, '—');
  if (typeof value === 'object' && value.sha256 && value.length) {
    return h('span', { class: 'muted', title: `SHA-256 ${value.sha256}` }, `${fmt(value.length)} characters (${value.sha256.slice(0, 12)}…)`);
  }
  return h('code', { class: 'break' }, typeof value === 'string' ? value : JSON.stringify(value));
}

function changesTable(changes) {
  const rows = Object.entries(changes || {});
  if (!rows.length) return null;
  return h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
    h('caption', { class: 'sr-only' }, 'What changed'),
    h('thead', {}, h('tr', {}, ['Changed', 'From', 'To'].map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', {}, rows.map(([field, { from, to }]) => h('tr', {},
      h('td', { 'data-label': 'Changed' }, humanize(field)),
      h('td', { 'data-label': 'From' }, changedValue(from)),
      h('td', { 'data-label': 'To' }, changedValue(to)))))));
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
    banner.replaceChildren(callout('neutral', 'clock', 'Recomputing every hash in the database…'));
    try {
      const v = await api('v1/ledger/verify');
      const origin = v.from ? `the checkpoint at entry #${fmt(v.from)} (the entries before it are archived)` : 'the genesis entry';
      banner.replaceChildren(v.valid
        ? callout('good', 'shield-check', h('span', {}, h('strong', {}, 'Chain intact. '),
          `Recomputed ${plural(v.checked - (v.from || 0), 'hash', 'hashes')} from ${origin}; nothing was edited, removed or reordered. Head `,
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
  const [kept, points, witness] = await Promise.all([
    api('v1/ledger/retention').catch(() => null), api('v1/ledger/checkpoints?limit=10').catch(() => null),
    api('v1/ledger/witness').catch(() => null),
  ]);

  return h('div', { class: 'page' },
    pageHead({
      title: 'Ledger',
      sub: "Tamper-evident record of lifecycle changes, admin actions and policy decisions. Each entry's SHA-256 hash covers the previous entry's hash, so any edit breaks the chain.",
      actions: [verifyBtn, exportBtn],
    }),
    ledgerTabs('entries'),
    rewoundCallout(witness),
    banner,
    h('div', { class: 'filters' },
      h('div', { class: 'field' }, h('label', { for: 'ledger-agent' }, 'Agent'), agentInput, agentList),
      h('div', { class: 'field' }, h('label', { for: 'ledger-user' }, 'On behalf of'), userInput),
      h('div', { class: 'field' }, h('label', { for: 'ledger-type' }, 'Event type'), typeSel),
      h('div', { class: 'field' }, h('label', { for: 'ledger-decision' }, 'Decision'), decisionSel),
      h('div', { class: 'field', style: 'flex:0 0 auto; align-self:flex-end' }, clearBtn),
      countEl),
    h('section', { class: 'card', 'aria-label': 'Ledger entries' }, tableHost),
    kept && points ? checkpointsCard(kept, points) : null);
}

// The database lost ledger entries AgentGov wrote (a restore): what, and accepting it.
function rewoundCallout(witness) {
  if (!witness?.rewound) return null;
  const accept = can('admin') ? h('button', {
    type: 'button', class: 'btn btn--sm btn--primary', 'data-focus-key': 'accept-rewind',
    onclick: guarded(async () => {
      const done = await ask({
        title: 'Accept the restore?',
        text: 'AgentGov writes into the ledger which entries are missing and when they were written, then goes on from the entries the database has. Do it once you know why they are missing: a backup you restored on purpose, say.',
        tone: 'danger', iconName: 'shield-check', confirm: 'Accept and record it',
        submit: () => api('v1/ledger/witness/accept', { method: 'POST' }),
      });
      if (!done) return;
      toast('Recorded in the ledger: entry ledger.rewound.');
      await refresh();
    }),
  }, icon('shield-check'), 'Accept the restore') : null;
  return callout('critical', 'octagon', h('div', { class: 'stack' },
    h('span', {}, h('strong', {}, witness.state === 'behind' ? 'Entries are missing. ' : 'Another history. '), witness.message,
      ' The chain still verifies: only the head kept outside the database tells.'),
    h('span', { class: 'small' }, `The head is kept in ${witness.file} (docs/backup.md).`),
    accept ? h('div', { class: 'btn-row' }, accept) : null));
}

function ledgerTabs(current) {
  return h('nav', { class: 'tabs', 'aria-label': 'Ledger views' },
    h('a', { class: 'tab', href: '#/ledger', 'aria-current': current === 'entries' ? 'page' : null }, 'Entries'),
    h('a', { class: 'tab', href: '#/ledger/compliance', 'aria-current': current === 'compliance' ? 'page' : null }, 'Compliance'),
    h('a', { class: 'tab', href: '#/ledger/register', 'aria-current': current === 'register' ? 'page' : null }, 'Register'));
}

/* -------------------------------------------------- classification register */

// Each agent's classification under the EU AI Act (docs/evidence.md#a-classification-register).
const CLASSIFICATION_CATEGORIES = [
  ['high-risk', 'High-risk (Art. 6: Annex I or Annex III)'],
  ['transparency', 'Transparency obligations (Art. 50)'],
  ['minimal', 'Minimal risk'],
  ['prohibited', 'A prohibited practice (Art. 5)'],
  ['not-ai-system', 'Not an AI system (Art. 3(1))'],
];
const CLASSIFICATION_ROLES = [['deployer', 'Deployer'], ['provider', 'Provider'], ['provider-and-deployer', 'Provider and deployer']];
const roleWord = (role) => (CLASSIFICATION_ROLES.find(([k]) => k === role) || [])[1] || role || '';

// Classify one agent, or several alike at once; resolves to whether it was done.
async function classifyAgents(list) {
  if (!list.length) return false;
  const one = list.length === 1 ? list[0] : null;
  const c = one?.classification || {};
  const result = await ask({
    title: one ? `Classify ${one.name}` : `Classify ${plural(list.length, 'agent')}`,
    text: 'Under the EU AI Act. Whether it is high-risk, and whether you are its provider or its deployer, decides which obligations apply to it. AgentGov keeps what you decide, who decided and when.',
    iconName: 'shield-check', confirm: 'Classify', busy: 'Saving…', wide: !one,
    extra: one ? null : nameList(list.map((a) => a.name)),
    fields: [
      { type: 'row', fields: [
        { id: 'category', label: 'Category', type: 'select', required: true, value: c.category || '',
          options: [{ value: '', label: 'Choose one' }, ...CLASSIFICATION_CATEGORIES.map(([value, label]) => ({ value, label }))] },
        { id: 'role', label: 'Your role for it', type: 'select', required: true, value: c.role || 'deployer',
          options: CLASSIFICATION_ROLES.map(([value, label]) => ({ value, label })) },
      ] },
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

function classificationCard(a) {
  const c = a.classification;
  const change = can('approve') && a.status !== 'deleted'
    ? h('button', {
      type: 'button', class: 'btn btn--sm', 'data-focus-key': 'classify',
      onclick: guarded(async () => { if (await classifyAgents([a])) await refresh(); }),
    }, icon('shield-check'), c ? 'Change' : 'Classify')
    : null;
  return card({
    title: 'Classification', sub: 'Under the EU AI Act', actions: change ? [change] : null,
    body: c
      ? [h('div', { class: 'chip-row' }, chip('classification', c.category)), facts([
        ['Your role', roleWord(c.role)],
        c.basis ? ['Why', c.basis] : null,
        c.purpose ? ['What it is for', c.purpose] : null,
        ['Classified by', h('span', {}, `${(c.by || 'unknown').replace(/^[a-z]+:/, '')} `, timeEl(c.at))],
      ].filter(Boolean))]
      : h('p', { class: 'muted' }, 'Not classified yet: whether it is high-risk, and your role for it, decide which obligations apply to it.'),
  });
}

const REGISTER_CSV = [
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

async function renderRegister({ params }) {
  const rows = await api('v1/evidence/register');
  const state = { category: params.get('category') || '' };
  const host = h('div', {});
  const countEl = h('p', { class: 'result-count', 'aria-live': 'polite' });
  const counts = countBy(rows, (r) => r.category || 'none');
  const select = h('select', { id: 'register-category', 'data-focus-key': 'register-category' },
    [['', `Every agent (${fmt(rows.length)})`], ['none', `Not classified (${fmt(counts.none || 0)})`],
      ...CLASSIFICATION_CATEGORIES.map(([k]) => [k, `${statusMeta('classification', k)[2]} (${fmt(counts[k] || 0)})`])]
      .map(([value, label]) => h('option', { value, selected: value === state.category }, label)));
  let shown = [];
  const csvButton = h('button', {
    type: 'button', class: 'btn btn--sm btn--ghost', 'data-focus-key': 'register-csv',
    onclick: () => saveCsv('agentgov-register', REGISTER_CSV, shown),
  }, icon('download'), 'Download CSV');
  function apply() {
    shown = rows.filter((r) => !state.category || (state.category === 'none' ? !r.category : r.category === state.category));
    countEl.textContent = plural(shown.length, 'agent');
    csvButton.disabled = !shown.length;
    host.replaceChildren(shown.length ? registerTable(shown) : emptyState('No agents here', 'Try another category.'));
  }
  select.addEventListener('change', () => { state.category = select.value; apply(); setHashQuiet('/ledger/register', { category: state.category }); });
  apply();
  return h('div', { class: 'page', 'data-title': 'Register' },
    pageHead({
      title: 'Classification register',
      sub: 'Each agent\u2019s classification under the EU AI Act: whether it is an AI system and at which level of risk, your role for it, why, and what it is for, with who classified it and when. It goes in the evidence pack.',
    }),
    ledgerTabs('register'),
    h('div', { class: 'chip-row' }, Object.entries(counts).map(([k, n]) => chip('classification', k, { extra: n }))),
    h('div', { class: 'filters' },
      h('div', { class: 'field', style: 'flex:0 1 300px' }, h('label', { for: 'register-category', class: 'sr-only' }, 'Category'), select),
      countEl, csvButton),
    h('section', { class: 'card', 'aria-label': 'Classification register' }, host));
}

function registerTable(rows) {
  const classify = can('approve');
  return h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
    h('thead', {}, h('tr', {}, ['Agent', 'Category', 'Your role', 'What it is for', 'Classified', classify ? '' : null]
      .filter((t) => t !== null).map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', {}, rows.map((r) => h('tr', {},
      h('td', { 'data-label': 'Agent' }, agentLink(r.id, r.agent), h('div', { class: 'cell-sub' }, humanize(r.status), r.owner ? ` \u00b7 ${r.owner}` : '')),
      h('td', { 'data-label': 'Category' }, chip('classification', r.category || 'none')),
      h('td', { 'data-label': 'Your role' }, roleWord(r.role) || h('span', { class: 'muted' }, '\u2014')),
      h('td', { 'data-label': 'What it is for', class: 'break' }, r.purpose ? h('div', { class: 'clamp-2' }, r.purpose) : h('span', { class: 'muted' }, '\u2014'),
        r.basis ? h('div', { class: 'cell-sub clamp-2' }, r.basis) : null),
      h('td', { 'data-label': 'Classified', class: 'nowrap' }, r.classified_at
        ? [timeEl(r.classified_at), h('div', { class: 'cell-sub' }, (r.classified_by || '').replace(/^[a-z]+:/, ''))]
        : h('span', { class: 'muted' }, 'Not yet')),
      classify ? h('td', { 'data-label': '' }, r.status === 'deleted' ? null : h('button', {
        type: 'button', class: 'btn btn--sm', 'data-focus-key': `classify-${r.id}`,
        onclick: guarded(async () => {
          const agent = { id: r.id, name: r.agent, classification: r.category ? { category: r.category, role: r.role, basis: r.basis, purpose: r.purpose } : null };
          if (await classifyAgents([agent])) await refresh();
        }),
      }, r.category ? 'Change' : 'Classify')) : null)))));
}

/* -------------------------------------------------------------- compliance */

const COMPLIANCE_PERIODS = [[30, 'Last 30 days'], [90, 'Last 90 days'], [365, 'Last year']];

async function renderCompliance({ params }) {
  const frameworks = await api('v1/evidence/frameworks');
  const state = {
    framework: frameworks.some((f) => f.key === params.get('framework')) ? params.get('framework') : frameworks[0].key,
    days: Number(params.get('days')) || 90,
  };
  const report = await api(`v1/evidence/report?framework=${encodeURIComponent(state.framework)}&days=${state.days}`);
  const go = () => { location.hash = `#/ledger/compliance?framework=${encodeURIComponent(state.framework)}&days=${state.days}`; };
  const frameworkSel = h('select', { id: 'compliance-framework', 'data-focus-key': 'compliance-framework' },
    frameworks.map((f) => h('option', { value: f.key, selected: f.key === state.framework }, f.title)));
  frameworkSel.addEventListener('change', () => { state.framework = frameworkSel.value; go(); });
  const periodSel = h('select', { id: 'compliance-days', 'data-focus-key': 'compliance-days' },
    COMPLIANCE_PERIODS.map(([d, label]) => h('option', { value: d, selected: d === state.days }, label)));
  periodSel.addEventListener('change', () => { state.days = Number(periodSel.value); go(); });
  const packBtn = h('button', {
    type: 'button', class: 'btn btn--primary', 'data-focus-key': 'evidence-pack',
    onclick: guarded(async () => {
      const blob = await saveDownload(`v1/evidence/pack?days=${state.days}`, `agentgov-evidence-${fileStamp()}.zip`);
      toast(`Downloaded the evidence pack (${fmtBytes(blob.size)}).`);
    }),
  }, icon('download'), 'Evidence pack');
  const l = report.ledger;
  const counts = Object.entries(report.summary).filter(([, n]) => n);
  return h('div', { class: 'page', 'data-title': 'Compliance' },
    pageHead({
      title: 'Compliance',
      sub: 'What AgentGov does towards each control, how far it is set up here, and the evidence it holds. It doesn\u2019t say that your organisation complies: that is for its assessors, and the evidence pack is for them.',
      actions: [packBtn],
    }),
    ledgerTabs('compliance'),
    h('div', { class: 'filters' },
      h('div', { class: 'field' }, h('label', { for: 'compliance-framework' }, 'Framework'), frameworkSel),
      h('div', { class: 'field', style: 'flex:0 1 200px' }, h('label', { for: 'compliance-days' }, 'Period'), periodSel)),
    callout('neutral', 'info', h('span', {}, report.framework.note, ' ', h('a', { href: report.framework.url, target: '_blank', rel: 'noopener' }, 'The framework'), '.')),
    h('div', { class: 'chip-row' }, counts.map(([status, n]) => chip('compliance', status, { extra: n }))),
    h('p', { class: 'muted' }, l.valid
      ? `The ledger verifies: ${plural(l.checked - (l.from || 0), 'entry', 'entries')} in the database; ${plural(l.checkpoints, 'checkpoint')}, ${fmt(l.timestamped)} time-stamped${l.last_timestamp ? ` (last on ${l.last_timestamp.slice(0, 10)})` : ''}.`
      : 'The ledger\u2019s chain is broken: see the Entries tab.'),
    coverageCard(report.coverage),
    h('div', { class: 'bp-grid' }, report.controls.map(complianceCard)));
}

// What AgentGov saw of the agents in the period, each counted once by the most it saw.
const COVERAGE = [
  ['calls_checked', 'Calls checked by AgentGov', 'good', 'shield-check'],
  ['activity_only', 'Seen at work, calls not checked', 'warning', 'eye'],
  ['inventory_only', 'In their platform\u2019s inventory only', 'neutral', 'platforms'],
  ['not_seen', 'Not seen', 'critical', 'alert-circle'],
];

function coverageCard(c) {
  if (!c) return null;
  if (!c.agents) {
    return card({ title: 'What AgentGov saw', body: emptyState('No agents yet', 'Register agents, or connect the platforms they run on.') });
  }
  const rows = COVERAGE.map(([key, label, tone, iconName]) => ({ label, tone, iconName, count: c[key] || 0, color: TONE_COLOR[tone] }));
  const pct = (n) => `${Math.round((n / c.agents) * 100)}%`;
  const more = c.not_seen - (c.not_seen_names || []).length;
  return card({
    title: 'What AgentGov saw',
    sub: 'In the period. A control only works for the agents AgentGov sees: the rest of this report is about them.',
    body: [
      h('div', {}, h('div', { class: 'hero-figure' }, fmt(c.agents)), h('p', { class: 'hero-caption' }, 'agents in the inventory')),
      h('div', { class: 'chart' }, h('div', { class: 'splitbar', role: 'img', 'aria-label': rows.map((r) => `${r.label}: ${r.count}`).join(', ') },
        rows.filter((r) => r.count).map((r) => h('span', { style: `flex: ${r.count} 1 0px; background: ${r.color}`, title: `${r.label}: ${fmt(r.count)}` })))),
      h('ul', { class: 'split-legend', role: 'list' }, rows.map((r) => h('li', {},
        icon(r.iconName, { cls: `t-${r.tone}` }), h('span', {}, r.label),
        h('span', { class: 'count' }, fmt(r.count)), h('span', { class: 'pct' }, pct(r.count))))),
      c.not_seen ? h('p', { class: 'small' }, h('strong', {}, 'Not seen: '), (c.not_seen_names || []).join(', '), more > 0 ? ` and ${fmt(more)} more` : '', '.') : null,
      c.platforms_not_read?.length ? callout('warning', 'triangle',
        `Not read in the period, or the last read failed: ${c.platforms_not_read.join(', ')}. What AgentGov holds about their agents may be out of date.`) : null,
    ],
  });
}

function complianceCard(c) {
  const value = (e) => (e.link ? h('a', { href: e.link }, String(e.value)) : String(e.value));
  return card({
    title: `${c.id} ${c.title}`, level: 'h3',
    sub: c.asks,
    actions: [chip('compliance', c.status)],
    body: [
      h('p', {}, c.agentgov),
      c.evidence.length ? facts(c.evidence.map((e) => [e.label, value(e)])) : null,
      c.gaps.length ? callout(c.status === 'attention' ? 'critical' : 'warning', 'triangle',
        h('div', {}, c.gaps.map((g) => h('div', {}, g)))) : null,
    ],
  });
}

// Checkpoints of the chain, their time-stamps and archives, and how long things are kept.
function checkpointsCard(kept, points) {
  const make = can('admin') ? h('button', {
    type: 'button', class: 'btn btn--sm', 'data-focus-key': 'make-checkpoint',
    onclick: guarded(async () => {
      const point = await api('v1/ledger/checkpoints', { method: 'POST' });
      const done = [point.timestamped ? 'time-stamped' : null, point.log?.logged ? 'in the transparency log' : null].filter(Boolean);
      toast(`Checkpoint at entry #${fmt(point.seq)}${done.length ? `, ${done.join(' and ')}` : ''}.`);
      await refresh();
    }),
  }, icon('plus'), 'Make a checkpoint') : null;
  const stamp = (c) => {
    if (c.timestamped) {
      return h('span', {}, plainChip('Time-stamped', { tone: 'good', iconName: 'shield-check' }), ' ', timeEl(c.timestamped_at), ' ',
        h('button', {
          type: 'button', class: 'btn btn--sm btn--ghost', 'data-focus-key': `tsr-${c.seq}`,
          onclick: guarded(async () => { await saveDownload(`v1/ledger/checkpoints/${c.seq}/timestamp`, `checkpoint-${c.seq}.tsr`); }),
        }, icon('download'), 'Time-stamp'));
    }
    if (c.timestamp_error) return plainChip('Not time-stamped', { tone: 'warning', iconName: 'triangle', title: c.timestamp_error });
    return h('span', { class: 'muted' }, kept.tsa_url ? 'Waiting for its time-stamp' : 'Not time-stamped');
  };
  // Its entry in the transparency log: where, whether its proof was checked, and the
  // Sigstore bundle that checks it offline.
  const logged = (c) => {
    const log = c.log || {};
    if (log.logged) {
      const [tone, label] = log.checked === false ? ['warning', 'Logged, proof failed']
        : log.checked ? ['good', `In the log, #${fmt(log.index)}`] : [null, `In the log, #${fmt(log.index)} (unchecked)`];
      return h('span', {}, plainChip(label, { tone, iconName: log.checked === false ? 'triangle' : 'shield-check', title: log.error || log.url }), ' ',
        h('button', {
          type: 'button', class: 'btn btn--sm btn--ghost', 'data-focus-key': `bundle-${c.seq}`,
          onclick: guarded(async () => { await saveDownload(`v1/ledger/checkpoints/${c.seq}/log-entry`, `checkpoint-${c.seq}.sigstore.json`); }),
        }, icon('download'), 'Log entry'));
    }
    if (log.error) return plainChip('Not in the log', { tone: 'warning', iconName: 'triangle', title: log.error });
    return kept.rekor_url ? h('span', { class: 'muted' }, 'Waiting for the log') : null;
  };
  const line = (c) => h('li', { class: 'access-row' },
    h('div', { class: 'access-main' },
      h('div', { class: 'cell-title' }, `Entry #${fmt(c.seq)} `, h('code', { class: 'hash', title: c.hash }, shortHash(c.hash))),
      h('div', { class: 'cell-sub break' }, 'Kept ', timeEl(c.created_at),
        c.archive ? [' · entries ', fmt(c.archived_from), '–', fmt(c.seq), ' archived to ', h('code', {}, c.archive)] : '')),
    h('div', { class: 'stack', style: 'gap:4px' }, stamp(c), logged(c)));
  return card({
    title: 'Checkpoints and retention',
    sub: 'Points of the chain kept for good, time-stamped by an authority and added to a transparency log when they are set; what leaves the database is archived first.',
    actions: make ? [make] : null,
    body: [
      facts([
        ['Ledger', kept.ledger_retention_days ? `${plural(kept.ledger_retention_days, 'day')} in the database, then archived` : 'Every entry kept in the database'],
        ['Chain in the database', kept.chain_from ? `From the checkpoint at entry #${fmt(kept.chain_from)}` : 'From the genesis entry'],
        ['Checkpoints', kept.checkpoint_hours ? `Every ${plural(kept.checkpoint_hours, 'hour')}` : 'On demand'],
        ['Time-stamping authority', kept.tsa_url ? h('code', {}, kept.tsa_url) : h('span', { class: 'muted' }, 'None')],
        ['Transparency log', kept.rekor_url ? h('code', {}, kept.rekor_url) : h('span', { class: 'muted' }, 'None')],
        ['Operational records', kept.data_retention_days ? `${plural(kept.data_retention_days, 'day')}` : 'Kept'],
      ]),
      points.length ? h('ul', { class: 'access-list', role: 'list' }, points.map(line)) : emptyState('No checkpoints yet', 'The first is kept within the hour.'),
    ],
  });
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
      if (editing) return api(`v1/identity-issuers/${encodeURIComponent(i.name)}`, { method: 'PATCH', body, ifMatch: i.version });
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

// Agents built on other platforms (Microsoft 365 Copilot, Copilot Studio, Microsoft Foundry,
// AWS, Google Cloud, Salesforce, Databricks). They never call the gateway, so AgentGov
// governs what their platform reports about them.
const PLATFORM_SOURCES = {
  'platform:microsoft-365': 'Microsoft 365',
  'platform:copilot-studio': 'Copilot Studio',
  'platform:entra-agent-id': 'Microsoft Entra Agent ID',
  'platform:aws': 'AWS',
  'platform:google-cloud': 'Google Cloud',
  'platform:salesforce': 'Salesforce',
  'platform:databricks': 'Databricks',
  'platform:microsoft-foundry': 'Microsoft Foundry',
};
// The platforms a connector of AgentGov's own reads: each reports its agents the same way.
const INVENTORY_SOURCES = new Set(['aws', 'google-cloud', 'salesforce', 'databricks', 'microsoft-foundry']);
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
  if (c.gone) parts.push(`${fmt(c.gone)} gone from the platform`);
  if (c.findings != null) parts.push(plural(c.findings, 'open finding'));
  return parts.join(', ');
}

async function renderPlatforms() {
  const [view, usage, modes] = await Promise.all([
    api('v1/platforms'), api('v1/platforms/connectors'), featureModes().catch(() => ({})),
  ]);
  const sources = Object.fromEntries(view.sources.map((src) => [src.source, src]));
  return h('div', { class: 'page' },
    pageHead({
      title: 'Platforms',
      sub: "Agents built on Microsoft 365 Copilot and Copilot Studio. They don't call tools through AgentGov's gateway, so AgentGov governs what their platform reports: who owns them, who they are shared with and which connectors they use.",
      actions: [refreshButton()],
    }),
    platformsCallout(view),
    connectionsCard(view),
    h('div', { class: 'grid-halves' }, m365Card(sources['microsoft-365']), copilotStudioCard(sources['copilot-studio'], view.admin_actions, view.people)),
    connectorsCard(usage, view, modes),
    otherPlatformsCard(view));
}

function inventoryStatus(src) {
  if (!src.configured) return 'off';
  if (!src.turned_on) return 'turned_off';
  const last = src.last_sync;
  if (!last) return 'waiting';
  if (last.ok) return 'ok';
  // Some parts (a region, an account) couldn't be read, but the rest was.
  return last.counts?.failed && (last.counts.created || last.counts.updated) ? 'partial' : 'failing';
}

function otherPlatformsCard(view) {
  const rows = view.sources.filter((src) => INVENTORY_SOURCES.has(src.source));
  if (!rows.length) return null;
  const names = rows.map((src) => src.name);
  const listed = names.length > 1 ? `${names.slice(0, -1).join(', ')} and ${names.at(-1)}` : names[0];
  return card({
    title: 'Other platforms',
    sub: `Agents built on ${listed}. AgentGov reads each platform it is set up for, on a schedule, and flags its agents' risky settings; it doesn't change them.`,
    flush: true,
    body: h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
      h('caption', { class: 'sr-only' }, 'Other platforms'),
      h('thead', {}, h('tr', {}, ['Platform', 'Status', 'Last sync', ''].map((t) => h('th', { scope: 'col' }, t || h('span', { class: 'sr-only' }, 'Actions'))))),
      h('tbody', {}, rows.map((src) => {
        const status = inventoryStatus(src);
        const last = src.last_sync;
        const help = status === 'off' && src.needs ? `Needs ${src.needs}.`
          : status === 'turned_off' ? 'Turn it on again on the Features page.' : null;
        return h('tr', { 'data-platform': src.source },
          h('td', { 'data-label': 'Platform' }, h('span', { class: 'cell-title' }, src.name),
            h('div', { class: 'cell-sub' }, src.agents
              ? h('a', { href: `#/agents?source=${encodeURIComponent(`platform:${src.source}`)}` }, plural(src.agents, 'agent'))
              : 'No agents yet')),
          h('td', { 'data-label': 'Status' }, chip('connection', status), help ? h('div', { class: 'cell-sub break' }, help) : null),
          h('td', { 'data-label': 'Last sync' }, last
            ? h('div', {}, timeEl(last.at), h('div', { class: last.ok ? 'cell-sub' : 'cell-sub tone-text-critical' }, last.ok ? syncCounts(last.counts || {}) : last.message))
            : h('span', { class: 'muted' }, 'Never')),
          h('td', { 'data-label': '' }, can('admin') && src.configured && src.turned_on
            ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': `sync-${src.source}`, onclick: (e) => syncConnection({ key: src.source, name: src.name }, e.currentTarget) }, icon('refresh'), 'Sync now')
            : null));
      })))),
  });
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
  'entra-users': (c) => [`${plural(c.found, 'person', 'people')} found`, c.not_found ? `${fmt(c.not_found)} not users` : null,
    c.left ? `${fmt(c.left)} left` : null].filter(Boolean).join(', '),
  'purview-audit': (c) => [`${plural(c.interactions, 'interaction')}`, `${plural(c.maker_events, 'maker change')}`,
    c.searching ? `${plural(c.searching, 'search', 'searches')} running` : null].filter(Boolean).join(', '),
  defender: (c) => `${plural(c.alerts, 'alert')} about agents, ${fmt(c.matched)} matched, ${fmt(c.resolved)} resolved`,
  'entra-access-packages': (c) => `${plural(c.packages, 'package')} agents can hold, ${plural(c.assignments, 'assignment')} to agents, ${fmt(c.expiring)} expiring`,
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
  if (c.manage === 'unknown') {
    return "Managing: the app's token holds no EntitlementManagement.ReadWrite.All, so Entra takes AgentGov's requests only for catalogs where its app is an Access package assignment manager.";
  }
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

// Who made Copilot Studio's agents, as far as AgentGov knows them.
function makersFact(summary) {
  if (!summary?.named) return null;
  const parts = [`${fmt(summary.known)} of ${fmt(summary.named)} known by name`];
  if (summary.unknown) parts.push(`${fmt(summary.unknown)} not looked up yet`);
  if (summary.left) parts.push(`${fmt(summary.left)} left`);
  if (summary.disabled) parts.push(`${fmt(summary.disabled)} with their account disabled`);
  return ['Makers and owners', parts.join(', ')];
}

function copilotStudioCard(src, adminActions, summary) {
  const asYou = adminActions && can('admin') && me?.microsoft;
  const actions = can('admin') ? [
    asYou ? h('button', { type: 'button', class: 'btn btn--sm btn--primary', 'data-focus-key': 'studio-sync', onclick: (e) => syncCopilotStudio(e.currentTarget) }, icon('refresh'), 'Sync now') : null,
    h('button', { type: 'button', class: asYou ? 'btn btn--sm' : 'btn btn--sm btn--primary', 'data-focus-key': 'studio-import', onclick: guarded(importCopilotStudio) }, icon('upload'), 'Import inventory'),
    summary?.named ? h('button', { type: 'button', class: 'btn btn--sm', 'data-focus-key': 'people-import', onclick: guarded(importPeople) }, icon('upload'), 'Upload users') : null,
  ].filter(Boolean) : null;
  return card({
    title: 'Copilot Studio',
    sub: asYou
      ? 'Copilot Studio and Agent Builder agents with the connectors they use, from the Power Platform inventory. Microsoft only lets a signed-in admin read it, so AgentGov syncs it as you.'
      : 'Copilot Studio and Agent Builder agents with the connectors they use, from the Power Platform inventory. Microsoft only lets a signed-in admin read the inventory, so export it and import the file here'
        + (adminActions && can('admin') ? ', or sign in to AgentGov with Microsoft Entra ID to sync it from here.' : '.'),
    actions,
    body: src.last_sync
      ? [sourceFacts(src, 'update'), makersFact(summary) ? facts([makersFact(summary)]) : null,
        summary?.unknown ? h('p', { class: 'hint' }, 'Copilot Studio names makers by their Entra IDs. AgentGov looks them up with its app (User.Read.All) or as an admin signed in with Microsoft; without either, upload the list of users from the Microsoft Entra admin center (Users, Download users).') : null]
      : emptyState('Nothing imported yet', 'Export the inventory as a Power Platform or AI administrator (a reader role is enough), then import the file:',
        h('pre', { class: 'kv-pre' }, INVENTORY_EXPORT)),
  });
}

async function importPeople() {
  const result = await ask({
    title: 'Upload a list of users',
    text: "So that AgentGov knows the people Copilot Studio names by their Entra IDs. In the Microsoft Entra admin center, go to Users, then Download users (anyone can): the file has each user's object ID, name and email address. AgentGov keeps those; it doesn't take a user missing from the list to have left.",
    iconName: 'upload', confirm: 'Upload', busy: 'Uploading…', wide: true,
    fields: [{ id: 'csv', label: 'Users (CSV)', type: 'code', rows: 8, required: true, file: '.csv', placeholder: 'objectId,userPrincipalName,displayName,mail,accountEnabled\n…' }],
    submit: (v) => api('v1/platforms/entra-users/import', { method: 'POST', text: v.csv, contentType: 'text/csv' }),
  });
  if (!result) return;
  const m = result.makers || {};
  toast(`Kept ${plural(result.people, 'person', 'people')}. AgentGov now knows ${fmt(m.known)} of the ${fmt(m.named)} people Copilot Studio names.`);
  await refresh();
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
    }, {
      id: 'complete', type: 'checkbox', value: false,
      label: 'This is the whole inventory, every environment',
      hint: 'Agents missing from it are marked gone from Copilot Studio, and their findings close. Leave it unticked for an export of some environments, or one page of a larger one (import every page at once with `agentgov platforms import --complete`).',
    }],
    submit: (v) => {
      try {
        JSON.parse(v.json);
      } catch (err) {
        throw new Error(`That isn't valid JSON: ${err.message}`);
      }
      const path = `v1/platforms/copilot-studio/import${v.complete ? '?complete=true' : ''}`;
      return api(path, { method: 'POST', text: v.json, contentType: 'application/json' });
    },
  });
  if (!result) return;
  toast(`Imported Copilot Studio agents: ${syncCounts(result)}.`);
  refreshBadges();
  await refresh();
}

// What happens to an agent that uses a connector the allowlist doesn't name
// (docs/platforms.md#when-an-agent-uses-a-connector-that-isnt-approved).
function connectorResponse(modes) {
  const detection = modes['copilot-studio-threat-detection'];
  const control = modes['connector-allowlist'];
  let runtime;
  if (!detection || detection === 'off') runtime = 'not checked as they run, because Copilot Studio threat detection is off';
  else if (control === 'off') runtime = 'not checked as they run, because the connector allowlist control is off';
  else if (detection === 'monitor' || control === 'monitor') runtime = 'let through, and recorded as what AgentGov would refuse';
  else runtime = 'refused by Copilot Studio threat detection';
  return h('p', { class: 'hint' }, 'An agent that uses a connector that is not approved is flagged, and its people are told. Its calls through that connector are ',
    runtime, '. ', h('a', { href: '#/features' }, 'Features'), ' sets this, and a ', h('a', { href: '#/policies' }, 'management rule'),
    ' can block such agents too.');
}

function connectorsCard(usage, view, modes = {}) {
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
    foot: active ? connectorResponse(modes) : null,
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

// What a connector of AgentGov's own read about an agent on its platform.
function inventoryCard(v) {
  const notes = v.in_inventory === false
    ? [callout('warning', 'triangle', `${v.source_name} no longer reports this agent. Delete it here when you no longer need its record.`)]
    : [];
  const value = (f) => {
    if (f.tone) return plainChip(f.value, { tone: f.tone, iconName: f.tone === 'serious' ? 'triangle' : 'alert-circle' });
    return f.code ? h('code', {}, f.value) : f.value;
  };
  const rows = [
    ['Name there', v.display_name],
    ['What it is', v.kind],
    ...(v.facts || []).map((f) => [f.label, value(f)]),
    ['ID', copyable(v.external_id, `${v.source_name} ID`)],
    /^https:\/\//.test(v.url || '') ? ['Open', h('a', { href: v.url, target: '_blank', rel: 'noopener noreferrer' }, `In ${v.source_name}`)] : null,
    ['Synced', timeEl(v.synced_at)],
  ];
  const tools = v.tools || [];
  return card({
    title: v.source_name,
    sub: `As ${v.source_name} reported it at the last sync`,
    body: [...notes, facts(rows), tools.length ? h('div', { class: 'stack', style: 'gap:8px; margin-top:14px' },
      h('h3', { class: 'dialog-section' }, 'Tools'),
      h('ul', { class: 'perm-list', role: 'list' }, tools.map((t) => h('li', {},
        h('span', { class: 'perm-server' }, h('code', {}, t.name), ' ', plainChip(t.kind, { tone: t.tone || null })),
        t.detail ? h('div', { class: 'cell-sub break' }, t.detail) : null)))) : null],
  });
}

function platformCard(a, v, where) {
  if (v.source === 'entra-agent-id') return entraCard(v);
  if (INVENTORY_SOURCES.has(v.source)) return inventoryCard(v);
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
  if (studio && v.in_inventory === false) notes.push(callout('warning', 'triangle', 'Copilot Studio no longer has this agent: the last sync, or an import of the whole inventory, didn\'t list it. Delete it here when you no longer need its record.'));
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

// Whether a feature can do what its mode says (agentgov.health): words and tone.
const FEATURE_STATUS = {
  failing: ['Stopping more than it should', 'critical', 'alert-circle'],
  inactive: ['Doing nothing', 'warning', 'triangle'],
  limited: ['Doing part of it', 'warning', 'triangle'],
};

async function renderFeatures() {
  const [view, components, presets] = await Promise.all([api('v1/features'), api('v1/components'), api('v1/feature-presets')]);
  const monitored = view.features.filter((f) => f.mode === 'monitor' && f.group === 'controls');
  const failing = view.features.filter((f) => f.status === 'failing');
  const short = view.features.filter((f) => f.status === 'inactive' || f.status === 'limited');
  return h('div', { class: 'page' },
    pageHead({
      title: 'Features',
      sub: 'Choose which parts of AgentGov you use, and how strictly. In monitor mode a control decides and records what it would have done, but lets the call through: try it on real traffic before you enforce it.',
      actions: [refreshButton()],
    }),
    failing.length ? callout('critical', 'alert-circle', h('span', {},
      h('strong', {}, `${plural(failing.length, 'feature')} stopping more than ${failing.length === 1 ? 'it' : 'they'} should: `),
      failing.map((f) => f.title).join(', '), '. See why below.')) : null,
    short.length ? callout('warning', 'triangle', h('span', {},
      h('strong', {}, `${plural(short.length, 'feature')} not doing all ${short.length === 1 ? 'its mode says' : 'their modes say'}: `),
      short.map((f) => f.title).join(', '), '. Turn off the ones you don\'t use; for the others, see below what each needs.')) : null,
    monitored.length ? callout('warning', 'eye', h('span', {},
      h('strong', {}, `${plural(monitored.length, 'control')} in monitor mode. `),
      'Calls they would have stopped go through, and the ledger records them as warnings. ',
      h('a', { href: '#/ledger?decision=monitored' }, 'See what they would have stopped'), '.')) : null,
    componentsCard(components),
    presetsCard(presets),
    Object.entries(view.groups).map(([group, title]) => {
      const list = view.features.filter((f) => f.group === group);
      return list.length ? featuresCard(title, list) : null;
    }));
}

// What the control plane reaches itself, and what each governance processor says it reaches.
const CHECK_NAMES = { opa: 'OPA', keycloak: "Keycloak's keys", presidio: 'Presidio', guardian: 'Granite Guardian', authzen: 'Your decision point' };

function checkChip(name, c) {
  const label = CHECK_NAMES[name] || name;
  if (!c || !c.configured) {
    // A processor with no AGENTGOV_OPA_URL still asks one, at its default address.
    if (c && c.detail) return plainChip(`${label}: ${c.ok ? 'reachable' : 'unreachable'}`, { tone: c.ok ? 'good' : 'critical', iconName: c.ok ? 'check' : 'alert-circle', title: c.detail });
    return plainChip(`${label}: not set up`, { title: `Not set up where it runs` });
  }
  return c.ok
    ? plainChip(`${label}: reachable`, { tone: 'good', iconName: 'check' })
    : plainChip(`${label}: unreachable`, { tone: 'critical', iconName: 'alert-circle', title: c.detail || null });
}

// What a governance processor does when what it depends on fails (AGENTGOV_*_FAILURE_MODE).
const FAILURE_WORDS = {
  gateway_failure_mode: ['Calls it can\'t check', { modes: 'refused while a control is enforced', closed: 'refused', open: 'let through, recorded' }],
  presidio_failure_mode: ['Presidio down', { closed: 'refused while data protection is enforced', open: 'personal data not looked for' }],
  guardian_failure_mode: ['Granite Guardian down', { open: 'the rules decide alone', closed: 'refused where it is waited for' }],
  authzen_failure_mode: ['Your decision point down', { closed: 'refused while it is enforced', open: 'AgentGov decides alone' }],
};

function failureLine(settings) {
  const parts = Object.entries(FAILURE_WORDS)
    .filter(([k]) => settings?.[k])
    .map(([k, [label, words]]) => `${label}: ${words[settings[k]] || settings[k]}`);
  return parts.length ? h('div', { class: 'cell-sub' }, `${parts.join('. ')}.`) : null;
}

function componentsCard(view) {
  const cp = view.control_plane || {};
  const processors = view.processors || [];
  const rows = [
    ['Control plane', h('div', { class: 'chip-row' }, ['opa', 'keycloak'].map((n) => checkChip(n, cp[n])))],
    ...processors.map((p) => [
      h('span', {}, 'Governance processor ', h('code', {}, p.instance)),
      h('div', {},
        h('div', { class: 'chip-row' }, ['opa', 'presidio', 'guardian', 'authzen'].map((n) => checkChip(n, p.checks[n]))),
        h('div', { class: 'cell-sub' }, p.fresh ? 'Reported ' : 'Out of touch: last reported ', timeEl(p.reported_at)),
        failureLine(p.settings),
        ...Object.entries(p.checks).filter(([, c]) => c.configured && !c.ok && c.detail).map(([n, c]) => h('div', { class: 'cell-sub' }, `${CHECK_NAMES[n] || n}: ${c.detail}`))),
    ]),
  ];
  return card({
    title: 'What AgentGov can reach',
    sub: 'Checked now by the control plane, and reported every minute by each governance processor where it runs. A feature that needs what isn\'t reachable says so below.',
    body: h('div', {},
      processors.length ? null : callout('warning', 'triangle', 'No governance processor has reported. The controls at the gateway check only calls through AgentGov\'s gateway, and nothing is known to check them.'),
      facts(rows)),
  });
}

// Starting points that set many modes at once.
function presetsCard(view) {
  const applied = view.applied ? ` The deployment applied ${view.applied} (AGENTGOV_FEATURE_PRESET).` : '';
  return card({
    title: 'Starting points',
    sub: `Set many modes at once, then change them one by one. Each change goes into the ledger with the preset's name; features the deployment pins keep their modes.${applied}`,
    body: h('ul', { class: 'apply-results', role: 'list' }, view.presets.map((p) => h('li', { 'data-preset': p.preset },
      h('div', {},
        h('span', { class: 'cell-title' }, p.title),
        h('div', { class: 'cell-sub' }, p.description),
        h('div', { class: 'cell-sub' }, p.changes.length ? `Would change ${plural(p.changes.length, 'feature')} now.` : 'Changes nothing now.')),
      can('admin') && p.changes.length
        ? h('button', { type: 'button', class: 'btn', onclick: guarded(() => applyPreset(p)) }, `Apply ${p.title.toLowerCase()}…`)
        : null))),
  });
}

async function applyPreset(p) {
  const words = (m) => (MODE_WORDS[m] || humanize(m)).toLowerCase();
  const weakens = p.changes.some((c) => c.to === 'off' || (c.from === 'enforce' && c.to === 'monitor'));
  const result = await ask({
    title: `${p.title}?`,
    text: p.description,
    tone: weakens ? 'danger' : 'primary', iconName: weakens ? 'triangle' : 'info',
    confirm: `Change ${plural(p.changes.length, 'feature')}`, busy: 'Changing…',
    extra: h('div', { class: 'stack-tight' },
      h('ul', { class: 'apply-results', role: 'list' }, p.changes.map((c) => h('li', {},
        h('span', {}, c.title), h('span', { class: 'cell-sub' }, `${words(c.from)} to ${words(c.to)}`)))),
      p.kept.length ? h('p', { class: 'cell-sub' }, 'Left as they are: ', p.kept.map((c) => `${c.title} (${c.reason})`).join('; '), '.') : null),
    submit: () => api(`v1/feature-presets/${encodeURIComponent(p.preset)}`, { method: 'POST' }),
  });
  if (result?.changes) toast(`${p.title}: ${plural(result.changes.length, 'feature')} changed.`);
  await refresh();
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
        h('td', { 'data-label': 'Mode' }, modeControl(f), exceptionsBlock(f)),
        h('td', { 'data-label': 'Now' }, featureNow(f), featureProvenance(f))))))),
  });
}

// What the mode does, or, when it can't do all of it, what stops it.
function featureNow(f) {
  const status = FEATURE_STATUS[f.status];
  if (!status || !(f.problems || []).length) return h('div', {}, f.effect);
  const [words, tone, iconName] = status;
  return h('div', { class: 'stack-tight' },
    plainChip(words, { tone, iconName }),
    (f.problems || []).map((p) => h('div', { class: 'break' }, p)),
    h('div', { class: 'cell-sub' }, `Its mode: ${f.effect}`));
}

function featureProvenance(f) {
  if (f.set_by === 'deployment') {
    return h('div', { class: 'cell-sub' }, icon('lock'), ' Set by the deployment (AGENTGOV_FEATURES)');
  }
  if (f.set_by === 'admin') return h('div', { class: 'cell-sub' }, `Set by ${f.changed_by} `, timeEl(f.changed_at));
  return h('div', { class: 'cell-sub' }, 'The default');
}

// A control's exceptions: its mode for the agents in a scope, the first that matches.
function plainScopes(f) {
  return (f.scopes || []).map(({ describe, agents, missing, ...e }) => e);
}

// How many agents an exception applies to now, and what it names that there isn't.
function exceptionReach(e) {
  if (e.agents === undefined) return null;
  const missing = e.missing?.length ? `There is no ${e.missing.join(', ')}. ` : '';
  const reach = e.agents ? `Applies to ${plural(e.agents, 'agent')} now.` : 'Applies to no agent now.';
  return h('span', { class: `exception-reach cell-sub${missing || !e.agents ? ' tone-text-warning' : ''}` }, `${missing}${reach}`);
}

function exceptionsBlock(f) {
  if (!f.scopable) return null;
  const pinned = f.set_by === 'deployment';
  const editable = can('admin') && !pinned;
  const list = f.scopes || [];
  if (!list.length && !editable) return null;
  return h('div', { class: 'exceptions' },
    list.length ? h('ul', { class: 'exception-list', role: 'list' }, list.map((e, i) => h('li', {},
      plainChip(MODE_WORDS[e.mode] || e.mode, { tone: e.mode === 'enforce' ? 'good' : e.mode === 'monitor' ? 'warning' : null }),
      h('span', { class: 'exception-scope' }, ruleScope(e.scope), e.note ? h('span', { class: 'cell-sub' }, ` (${e.note})`) : null, exceptionReach(e)),
      editable ? h('button', {
        type: 'button', class: 'icon-btn', title: 'Remove this exception',
        'aria-label': `Remove the exception: ${MODE_WORDS[e.mode] || e.mode} for ${ruleScope(e.scope)}`,
        onclick: guarded(() => removeException(f, i)),
      }, icon('x')) : null))) : null,
    pinned && list.length ? h('div', { class: 'cell-sub' }, 'Not applied: the deployment pins this feature for every agent.') : null,
    editable ? h('button', { type: 'button', class: 'btn btn--sm btn--ghost', onclick: guarded(() => addException(f)) }, icon('plus'), 'Add an exception') : null);
}

async function addException(f) {
  const result = await ask({
    title: `${f.title}: an exception`,
    text: 'Its mode for the agents in a scope. Every box you fill in must match; the first exception that matches an agent applies to it, and the others have the feature\'s mode.',
    confirm: 'Add the exception', busy: 'Saving…',
    fields: [
      { id: 'mode', label: 'Mode for these agents', type: 'select', required: true, value: f.mode === 'enforce' ? 'monitor' : 'enforce', options: f.modes.map((m) => ({ value: m, label: MODE_WORDS[m] || humanize(m) })) },
      { type: 'row', fields: [
        { id: 'blueprints', label: 'Blueprints', mono: true },
        { id: 'teams', label: 'Teams', mono: true },
      ] },
      { type: 'row', fields: [
        { id: 'platforms', label: 'Platforms', mono: true, hint: 'gateway, microsoft-365, copilot-studio, aws, google-cloud, salesforce, databricks or microsoft-foundry.' },
        { id: 'environments', label: 'Environments', mono: true },
      ] },
      { id: 'labels', label: 'With labels', mono: true, hint: 'key=value, separated by commas.' },
      { id: 'note', label: 'Why', hint: 'For whoever reads it next.' },
    ],
    submit: async (v) => {
      const scope = {};
      for (const key of ['blueprints', 'teams', 'platforms', 'environments']) {
        const list = parseList(v[key]);
        if (list.length) scope[key] = list;
      }
      const labels = parseLabels(v.labels);
      if (Object.keys(labels).length) scope.labels = labels;
      if (!Object.keys(scope).length) throw new Error('Say which agents: a blueprint, a team, a platform, an environment or a label.');
      const entry = { mode: v.mode, scope };
      if (v.note) entry.note = v.note;
      try {
        return await api(`v1/features/${encodeURIComponent(f.key)}`, { method: 'PUT', body: { scopes: [...plainScopes(f), entry] } });
      } catch (err) {
        // What is wrong with this exception, not where it is in the list ("scopes[3].scope").
        if (err instanceof ApiError) err.message = err.message.replace(/\bscopes\[\d+\]\.scope: (\w)/i, (_, c) => c.toUpperCase());
        throw err;
      }
    },
  });
  if (result?.scopes) toast(`${f.title}: ${plural(result.scopes.length, 'exception')}.`);
  await refresh();
}

async function removeException(f, i) {
  const e = f.scopes[i];
  const ok = await ask({
    title: 'Remove this exception?',
    text: `${f.title}: ${(MODE_WORDS[e.mode] || e.mode).toLowerCase()} for ${ruleScope(e.scope)}. These agents then have the feature's mode, ${(MODE_WORDS[f.mode] || f.mode).toLowerCase()}, unless a later exception takes them in.`,
    tone: 'danger', iconName: 'triangle', confirm: 'Remove it',
  });
  if (!ok) return;
  try {
    const out = await api(`v1/features/${encodeURIComponent(f.key)}`, { method: 'PUT', body: { scopes: plainScopes(f).filter((_, j) => j !== i) } });
    toast(`${f.title}: ${plural(out.scopes.length, 'exception')} left.`);
  } catch (err) {
    toast(err.message, { tone: 'critical' });
  }
  await refresh();
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
  servicenow: ['ServiceNow', 'desk', 'https://your-instance.service-now.com', 'Your instance. Tickets go to its Table API: the incident table, unless you choose another.'],
  jira: ['Jira Service Management', 'desk', 'https://your-site.atlassian.net', "Your site (Jira Data Center: its base URL). With a service account's scoped token: https://api.atlassian.com/ex/jira/<cloud ID>."],
  freshservice: ['Freshservice', 'desk', 'https://your-domain.freshservice.com', 'Your helpdesk.'],
};
// A desk's main setting: where its tickets go.
const DESK_GROUP = {
  servicenow: ['Assignment group', 'AI Governance', 'By name or sys_id. Empty: the table\'s own rules assign them.'],
  jira: ['Project', 'OPS', "The key of the project tickets go to."],
  freshservice: ['Group ID', '42', "The ID of the agent group tickets go to (in its URL in Freshservice's admin). Empty: Freshservice's own rules assign them."],
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
  servicenow: 'user:password on one line (an integration user with the itil role, say), or HTTP headers, one per line: x-sn-apikey: <key>, or Authorization: Basic <…>.',
  jira: 'email:api-token on one line (Jira Cloud), or HTTP headers, one per line: Authorization: Bearer <personal access token> (Jira Data Center).',
  freshservice: 'The API key, on one line (in Freshservice, Profile settings → API key).',
};
const destKind = (kind) => (DEST_KINDS[kind] || [kind])[0];
const destFamily = (kind) => (DEST_KINDS[kind] || [kind, 'siem'])[1];

async function renderSecops() {
  const [view, feature] = await Promise.all([api('v1/secops'), api(`v1/features/security-operations`)]);
  return h('div', { class: 'page' },
    pageHead({
      title: 'Security operations',
      sub: "What AgentGov hands to other tools: the evidence ledger, as OCSF events, to the security team's SIEMs; alerts to Teams and Slack channels; issues, as tickets, to service desks; and how much the security team's secops role may do here.",
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
  if (destFamily(d.kind) === 'desk') {
    const t = delivery.tickets || {};
    return [plainChip(`${fmt(t.open || 0)} ${t.open === 1 ? 'ticket' : 'tickets'} kept in step`, { tone: 'good', iconName: 'check-circle' }),
      t.pending ? h('div', { class: 'cell-sub' }, `${fmt(t.pending)} opening`) : null,
      t.failed ? h('div', { class: 'cell-sub' }, plainChip(`${fmt(t.failed)} it couldn't open`, { tone: 'critical', iconName: 'octagon' })) : null,
      t.erring ? h('div', { class: 'cell-sub' }, `${fmt(t.erring)} refused for now: their issues say why`) : null,
      delivery.delivered_at ? h('div', { class: 'cell-sub' }, 'Last change sent ', timeEl(delivery.delivered_at)) : h('div', { class: 'cell-sub' }, 'Nothing sent yet')];
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
      h('td', { 'data-label': 'Gets' }, h('div', { class: 'chip-row' }, destFamily(d.kind) === 'desk' ? plainChip('Issues, as tickets', { iconName: 'ticket' }) : d.events.map((e) => plainChip(humanize(e)))),
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
    : emptyState('No destinations', 'Add a SIEM, through OpenTelemetry, an HTTP input or Splunk, to send it the ledger as OCSF events; a Teams or Slack channel, to send it alerts; or a service desk, where issues become tickets.');
  return card({
    title: 'Destinations',
    sub: "SIEMs get what is new in the ledger, at least once and in order, and keep their place while paused or failing; chats get alerts; service desks get issues as tickets, kept in step with them. Each one's credential is a file the control plane reads, named after it: never in AgentGov's database.",
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

// A desk's groups by team, a "team = group" a line.
function teamGroupsText(groups) {
  return Object.entries(groups || {}).map(([team, group]) => `${team} = ${group}`).join('\n');
}

function parseTeamGroups(text) {
  const out = {};
  for (const line of (text || '').split('\n').map((l) => l.trim()).filter(Boolean)) {
    const at = line.indexOf('=');
    if (at < 1 || !line.slice(at + 1).trim()) throw new Error(`Per team: "${line}" isn't "team = group".`);
    out[line.slice(0, at).trim()] = line.slice(at + 1).trim();
  }
  return out;
}

function jsonObject(text, what) {
  if (!(text || '').trim()) return null;
  let value;
  try { value = JSON.parse(text); } catch { value = null; }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${what}: a JSON object, such as {"category": "security"}.`);
  return value;
}

async function destinationForm(d) {
  const editing = Boolean(d);
  const kind0 = d?.kind || 'otlp';
  const tk = d?.tickets || {};
  const eventFields = (family) => DEST_EVENTS[family].map(([key, label, hint]) => ({
    id: `ev-${family}-${key}`, label, hint, type: 'checkbox',
    value: editing ? d.events.includes(key) : true,
  }));
  const pretty = (value) => (value ? JSON.stringify(value, null, 2) : '');
  const saved = await ask({
    title: editing ? `Edit ${d.name}` : 'Add a destination',
    text: editing
      ? `${destKind(d.kind)}. Changes apply to what it is sent next, and are recorded in the evidence ledger.`
      : "A SIEM gets the ledger as OCSF events; a chat gets alerts; a service desk gets issues as tickets, kept in step with them. Put its credential in its secret file, which the control plane reads when it sends.",
    iconName: editing ? 'edit' : 'secops', confirm: editing ? 'Save changes' : 'Add destination', wide: true,
    fields: [
      editing ? null : { id: 'name', label: 'Name', required: true, mono: true, placeholder: 'soc-splunk', hint: NAME_HINT },
      editing ? null : {
        id: 'kind', label: 'Kind', type: 'select', value: kind0,
        options: Object.entries(DEST_KINDS).map(([value, [label, family]]) => ({ value, label: `${label}: ${{ chat: 'alerts', desk: 'tickets' }[family] || 'OCSF events'}` })),
      },
      { id: 'url', label: 'URL', mono: true, value: d?.url || '', placeholder: DEST_KINDS[kind0][2] || '', hint: DEST_KINDS[kind0][3] || '' },
      { id: 'format', label: 'Body', type: 'select', value: d?.format || 'json', options: [
        { value: 'json', label: 'A JSON array of events' }, { value: 'ndjson', label: 'JSON lines: one event per line' },
      ] },
      { type: 'section', id: 'sec-gets', label: 'What it gets' },
      ...eventFields('siem'),
      ...eventFields('chat'),
      { type: 'section', id: 'sec-tickets', label: 'Its tickets' },
      { id: 'tk-group', label: 'Assignment group', mono: true, value: tk.group ?? '' },
      {
        id: 'tk-groups', label: 'Per team', type: 'textarea', mono: true, value: teamGroupsText(tk.groups), placeholder: 'cx-platform = CX Platform',
        hint: "Where the issues of AgentGov's teams go instead, a team a line. An issue's team is the first team in its chain: its owner, a sponsor, or its team.",
      },
      { id: 'tk-only', label: 'Only the issues of the teams listed', type: 'checkbox', value: Boolean(tk.only_listed_teams) },
      { id: 'tk-table', label: 'Table', mono: true, value: tk.table || '', placeholder: 'incident', hint: 'incident, unless you choose another: sn_si_incident for Security Incident Response, say.' },
      { id: 'tk-issue_type', label: 'Issue type', value: tk.issue_type || '', placeholder: 'Task', hint: "Its name in the project: Task, unless you choose another." },
      { id: 'tk-site', label: 'Site', mono: true, value: tk.site || '', placeholder: 'https://your-site.atlassian.net', hint: "Where people open tickets: needed when the URL is Atlassian's API gateway." },
      { id: 'tk-requester', label: 'Raised for', mono: true, value: tk.requester || '', placeholder: 'agentgov@example.com', hint: "The requester's email address: AgentGov's mailbox, say." },
      {
        id: 'tk-fields', label: 'More fields', type: 'textarea', mono: true, value: pretty(tk.fields), placeholder: '{"category": "security"}',
        hint: "As JSON, by the desk's own names: what its forms require, such as a caller, a category or a custom field.",
      },
      { id: 'tk-resolve', label: 'Resolve the ticket when the issue ends', type: 'checkbox', value: tk.resolve !== false, hint: 'Otherwise AgentGov adds a note that it ended, and someone resolves it there.' },
      {
        id: 'tk-resolve_fields', label: 'Resolve it with', type: 'textarea', mono: true, value: pretty(tk.resolve_fields), placeholder: '{"close_code": "Solution provided"}',
        hint: "As JSON: what resolving takes there, if not the defaults (docs/tickets.md).",
      },
      {
        id: 'min_severity', label: 'Minimum severity', type: 'select', value: d?.min_severity || (destFamily(kind0) === 'siem' ? 'info' : 'high'),
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
        document.getElementById('dlg-sec-gets').hidden = family === 'desk';
        document.getElementById('dlg-sec-tickets').hidden = family !== 'desk';
        for (const id of ['tk-group', 'tk-groups', 'tk-only', 'tk-fields', 'tk-resolve', 'tk-resolve_fields']) field(id).hidden = family !== 'desk';
        field('tk-table').hidden = kind !== 'servicenow';
        field('tk-issue_type').hidden = kind !== 'jira';
        field('tk-site').hidden = kind !== 'jira';
        field('tk-requester').hidden = kind !== 'freshservice';
        if (family === 'desk') {
          const [label, placeholder, hint] = DESK_GROUP[kind];
          field('tk-group').querySelector('label').firstChild.nodeValue = label;
          controls['tk-group'].placeholder = placeholder;
          const groupHint = field('tk-group').querySelector('.hint');
          if (groupHint) groupHint.textContent = hint;
          else field('tk-group').append(h('p', { class: 'hint' }, hint));
        }
        field('url').hidden = family === 'chat';
        field('format').hidden = kind !== 'webhook';
        const severityHint = field('min_severity').querySelector('.hint');
        if (severityHint) severityHint.textContent = family === 'desk' ? 'Issues from this severity up become tickets.' : 'For a chat, of findings: approval requests and kill switches always go.';
        if (field('backfill')) {
          field('backfill').hidden = family === 'chat';
          field('backfill').querySelector('label').lastChild.nodeValue = family === 'desk'
            ? 'Open tickets for the issues already open too, not only those from now on'
            : 'Send it the ledger from its start, not from now';
        }
        controls.url.placeholder = DEST_KINDS[kind][2] || '';
        const hint = field('url').querySelector('.hint');
        if (hint) hint.textContent = DEST_KINDS[kind][3] || '';
        const name = editing ? d.name : (controls.name.value || '<name>');
        secretHint.textContent = `Secret file: ${d?.secret?.file || `<destination secrets>/${name}`}. ${DEST_SECRET[kind]}`;
        if (!editing && document.activeElement !== controls.min_severity) controls.min_severity.value = family === 'siem' ? 'info' : 'high';
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
      const body = { min_severity: v.min_severity, description: v.description, labels: parseLabels(v.labels) };
      if (family === 'desk') {
        const groups = parseTeamGroups(v['tk-groups']);
        // Cleared settings go (null), so that an edit can take one out.
        body.tickets = {
          group: orNull(v['tk-group']),
          groups: Object.keys(groups).length ? groups : null,
          only_listed_teams: v['tk-only'] || null,
          fields: jsonObject(v['tk-fields'], 'More fields'),
          resolve: v['tk-resolve'] ? null : false,
          resolve_fields: jsonObject(v['tk-resolve_fields'], 'Resolve it with'),
          ...(kind === 'servicenow' ? { table: orNull(v['tk-table']) } : {}),
          ...(kind === 'jira' ? { issue_type: orNull(v['tk-issue_type']), site: orNull(v['tk-site']) } : {}),
          ...(kind === 'freshservice' ? { requester: orNull(v['tk-requester']) } : {}),
        };
        body.url = orNull(v.url);
      } else {
        const events = DEST_EVENTS[family].map(([key]) => key).filter((key) => v[`ev-${family}-${key}`]);
        // A chat may take no alerts: a team's channel, for the issues its team posts there.
        if (!events.length && family !== 'chat') throw new Error('Choose at least one kind of event to send it.');
        body.events = events;
        if (family === 'siem') body.url = orNull(v.url);
        if (kind === 'webhook') body.format = v.format;
      }
      if (editing) return api(`v1/destinations/${encodeURIComponent(d.name)}`, { method: 'PATCH', body, ifMatch: d.version });
      return api('v1/destinations', { method: 'POST', body: { name: v.name, kind, ...body, ...(family !== 'chat' && v.backfill ? { backfill: true } : {}) } });
    },
  });
  if (!saved) return;
  const missing = !saved.secret.present && saved.secret.need === 'required';
  toast(editing ? `Saved ${saved.name}.` : `Added ${saved.name}.${missing ? ` Put its credential in ${saved.secret.file}.` : ''}`);
  await refresh();
}

async function testDestination(d) {
  const out = await api(`v1/destinations/${encodeURIComponent(d.name)}/test`, { method: 'POST' });
  if (out.ok && out.message) toast(`${d.name}: ${out.message}.`);
  else if (out.ok) toast(`Sent ${d.name} a test ${destFamily(d.kind) === 'chat' ? 'message' : 'event'}.`);
  else toast(`${d.name}: ${out.error}`, { tone: 'critical' });
  await refresh();
}

async function pauseDestination(d) {
  const pause = d.status !== 'paused';
  const done = await ask({
    title: pause ? `Pause ${d.name}?` : `Resume ${d.name}?`,
    text: destFamily(d.kind) === 'desk'
      ? (pause ? 'AgentGov opens no tickets there, and neither updates nor reads back the ones it has, until it is resumed.' : 'AgentGov opens the tickets due meanwhile, tells it what changed, and reads its tickets back.')
      : (pause ? 'It gets nothing until it is resumed, then everything it missed (alerts older than an hour excepted).' : 'It gets what it missed while it was paused, then what happens next.'),
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
      if (editing) return api(`v1/models/providers/${encodeURIComponent(p.name)}`, { method: 'PATCH', body, ifMatch: p.version });
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
  const [registry, sightings, features, agentList] = await Promise.all([
    api('v1/mcp/registry'), api('v1/mcp/sightings'), featureModes().catch(() => ({})), api('v1/agents').catch(() => []),
  ]);
  return h('div', { class: 'page' },
    pageHead({
      title: 'Developer tools',
      sub: "Which MCP servers developers' MCP clients may use, served as an MCP registry for GitHub Copilot and VS Code, how developers sign in to the ones on the gateway, and which ones developers have set up on their machines.",
      actions: [refreshButton()],
    }),
    registryCard(registry),
    signInCard(agentList.filter((a) => a.client_type === 'public'), features),
    sightingsCard(sightings, features));
}

/** Developers' MCP clients on the gateway, with their own tokens: the public clients they sign in to. */
function signInCard(clients, features) {
  const on = features['developer-sign-in'] === 'on';
  return card({
    title: 'Signing in at the gateway',
    sub: "Developers' MCP clients reach the tool servers on the gateway with the developer's own token: the gateway tells them where to sign in, and they sign in to an agent registered as a public client, which acts for them.",
    flush: Boolean(clients.length),
    body: [
      on ? null : callout('info', 'power', h('span', {}, h('strong', {}, 'Off: '),
        "the gateway doesn't tell MCP clients where to sign in. Turn on ", h('code', {}, 'developer-sign-in'), ' on the ', h('a', { href: '#/features' }, 'Features'), ' page.')),
      clients.length
        ? h('div', { class: 'table-wrap' }, h('table', { class: 'data rtable' },
          h('caption', { class: 'sr-only' }, 'Agents developers sign in to'),
          h('thead', {}, h('tr', {}, ['Agent', 'Client ID', 'Sign-ins return to', 'Status'].map((c) => h('th', { scope: 'col' }, c)))),
          h('tbody', {}, clients.map((a) => h('tr', {},
            h('td', { 'data-label': 'Agent' }, h('a', { href: agentHref(a.id) }, a.name), a.blueprint ? h('div', { class: 'cell-sub' }, a.blueprint) : null),
            h('td', { 'data-label': 'Client ID' }, copyable(a.identity.client_id, 'client ID')),
            h('td', { 'data-label': 'Sign-ins return to' }, h('code', { class: 'break' }, (a.redirect_uris.length ? a.redirect_uris : ['http://127.0.0.1/*', 'http://localhost/*']).join(', '))),
            h('td', { 'data-label': 'Status' }, humanize(a.status)))))))
        : emptyState('No agent for developers to sign in to', "Register an agent whose tokens are for people who sign in to it (a public client), with a blueprint whose agents act for people."),
    ],
  });
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
