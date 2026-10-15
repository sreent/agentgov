// The control plane's API. The UI is served at <control plane>/ui/, so the API is one
// level up, wherever the control plane is.

import { cap, fileStamp } from './format';
import { getToken, inSession } from './session';

export const API_ROOT = new URL('../', window.location.href);

export class ApiError extends Error {
  status: number;
  detail: string;
  constructor(status: number, message: string, detail = '') {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

// Called when a request is refused for want of a valid sign-in (the shell signs out).
let onExpired: () => void = () => {};
export function whenSignInExpires(handler: () => void): void {
  onExpired = handler;
}

function describeDetail(detail: unknown): string {
  if (!detail) return '';
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail.map((d) => {
      const where = Array.isArray(d?.loc) ? d.loc.filter((x: unknown) => x !== 'body' && x !== 'query').join('.') : '';
      return [where, d?.msg].filter(Boolean).join(': ');
    }).join('; ');
  }
  try {
    return JSON.stringify(detail);
  } catch {
    return String(detail);
  }
}

function friendlyError(status: number, detail: string): string {
  const d = detail ? `${cap(detail).replace(/\.$/, '')}.` : '';
  if (status === 401) return inSession() ? 'Your session has ended. Sign in again.' : 'Your API token was not accepted. Sign in again with a valid token.';
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

export interface ApiOptions {
  method?: string;
  /** A JSON body. */
  body?: unknown;
  /** A text body, of contentType. */
  text?: string;
  contentType?: string;
  auth?: boolean;
  /** A 401 is the answer, not a sign that the sign-in ended. */
  signingIn?: boolean;
  /** The version an edit was made from: the control plane refuses it if that's old (412). */
  ifMatch?: string | number | null;
}

async function request(path: string, opts: ApiOptions): Promise<Response> {
  const { method = 'GET', body, text, contentType = 'text/plain', auth = true, signingIn = false, ifMatch } = opts;
  // Required on writes authenticated by the session cookie (other sites cannot set it).
  const headers: Record<string, string> = { Accept: 'application/json', 'X-AgentGov-CSRF': '1' };
  const token = getToken();
  if (auth && token) headers.Authorization = `Bearer ${token}`;
  if (ifMatch != null) headers['If-Match'] = `"${ifMatch}"`;
  const init: RequestInit = { method, headers, cache: 'no-store' };
  if (text !== undefined) {
    headers['Content-Type'] = contentType;
    init.body = text;
  } else if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let res: Response;
  try {
    res = await fetch(new URL(path, API_ROOT), init);
  } catch {
    throw new ApiError(0, "Can't reach the control plane. Check that it is running and that this browser can connect to it.");
  }
  if (!res.ok) {
    let detail = '';
    try {
      detail = describeDetail((await res.json())?.detail);
    } catch {
      /* body was not JSON */
    }
    if (res.status === 401 && auth && !signingIn) onExpired();
    throw new ApiError(res.status, friendlyError(res.status, detail), detail);
  }
  return res;
}

/** Call the API: the answer's JSON (null for 204). */
export async function api<T = any>(path: string, opts: ApiOptions = {}): Promise<T> {
  const res = await request(path, opts);
  return (res.status === 204 ? null : await res.json()) as T;
}

/** Call the API: the response itself, for its headers or a file. */
export function apiRaw(path: string, opts: ApiOptions = {}): Promise<Response> {
  return request(path, opts);
}

// What the control plane says about itself without a sign-in (GET /v1/info), once.
let infoPromise: Promise<any> | null = null;
export function getInfo(): Promise<any> {
  if (!infoPromise) infoPromise = api('v1/info', { auth: false }).catch(() => null);
  return infoPromise;
}

/** Save a blob as a file, as a download. */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.hidden = true;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/** Download what the API answers at path, as filename. */
export async function saveDownload(path: string, filename: string): Promise<Blob> {
  const res = await apiRaw(path);
  const blob = await res.blob();
  saveBlob(blob, filename);
  return blob;
}

// A spreadsheet's file of what a page shows: a header, then a line each. A cell a
// spreadsheet would take for a formula (names and titles come from the platforms) is kept
// as text.
function csvCell(value: unknown): string {
  let text = value == null ? '' : Array.isArray(value) ? value.join('; ') : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export type CsvColumns<T> = [label: string, get: (row: T) => unknown][];

export function saveCsv<T>(name: string, columns: CsvColumns<T>, rows: T[]): void {
  const lines = [columns.map(([label]) => csvCell(label)).join(','),
    ...rows.map((row) => columns.map(([, get]) => csvCell(get(row))).join(','))];
  // A byte-order mark, so spreadsheets read it as UTF-8.
  saveBlob(new Blob([`\uFEFF${lines.join('\r\n')}\r\n`], { type: 'text/csv;charset=utf-8' }), `${name}-${fileStamp()}.csv`);
}
