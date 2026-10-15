// Pages by address: the part of the URL after # (#/agents/support-bot?tab=x), so that links
// in emails, chats and tickets (…/ui/#/findings/fnd_123) open the page they are about.

import type { ComponentType } from 'react';

export interface PageContext {
  path: string;
  match: RegExpMatchArray;
  params: URLSearchParams;
}

export interface PageProps<D = any> {
  data: D;
  ctx: PageContext;
}

export interface PageDef<D = any> {
  re: RegExp;
  /** The menu entry it is under. */
  nav: string;
  title: string;
  /** What the page shows, from the API. It runs again on refresh(). */
  load: (ctx: PageContext) => Promise<D>;
  View: ComponentType<PageProps<D>>;
  /** Its own title, when it has one (an agent's name), for the window and the top bar. */
  titleOf?: (data: D) => string;
  /** For the whole organisation: not for those whose roles are for some teams only. */
  orgWide?: boolean;
}

export function parseHash(): { path: string; params: URLSearchParams } {
  const raw = window.location.hash.replace(/^#/, '');
  const q = raw.indexOf('?');
  let path = q < 0 ? raw : raw.slice(0, q);
  if (!path || path === '/') path = '/overview';
  if (!path.startsWith('/')) path = `/${path}`;
  return { path, params: new URLSearchParams(q < 0 ? '' : raw.slice(q + 1)) };
}

/** Put a page's filters in its address, without going anywhere (for links and reloads). */
export function setHashQuiet(path: string, params?: Record<string, unknown>): void {
  const qs = params
    ? new URLSearchParams(Object.entries(params).filter(([, v]) => v).map(([k, v]) => [k, String(v)])).toString()
    : '';
  window.history.replaceState(null, '', `#${path}${qs ? `?${qs}` : ''}`);
}

let refresher: (() => Promise<void>) | null = null;

/** The page host's own: how refresh() reloads the page shown. */
export function setRefresher(fn: (() => Promise<void>) | null): void {
  refresher = fn;
}

/**
 * Load the page shown again, keeping what was typed and chosen on it, the scroll and the
 * focus: after a change, so that it shows the new state. Resolves once it shows it.
 */
export function refresh(): Promise<void> {
  return refresher ? refresher() : Promise.resolve();
}
