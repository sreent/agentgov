import { test as base, expect, type APIRequestContext, type Locator, type Page } from '@playwright/test';

// The bootstrap admin token of the control plane the tests run against
// (scripts/ui-test-server.py).
export const ADMIN_TOKEN = 'ui-test-admin-token';

/**
 * Every test fails on a script error in the page. The tests find what they check by what
 * people see and hear (roles, labels, headings), not by how the page is built, so that
 * they hold whatever the UI is written in.
 */
export const test = base.extend<{ pageErrors: string[] }>({
  pageErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on('pageerror', (err) => errors.push(err.message));
      page.on('console', (msg) => {
        // A refused request is logged by the browser itself; the tests check the page's answer.
        if (msg.type() === 'error' && !msg.text().startsWith('Failed to load resource')) errors.push(msg.text());
      });
      await use(errors);
      expect(errors, 'script errors in the page').toEqual([]);
    },
    { auto: true },
  ],
});
export { expect };

/** Sign in with an API token, on the page `path` (such as '/agents') or the default one. */
export async function signIn(page: Page, token = ADMIN_TOKEN, path = ''): Promise<void> {
  await page.goto(path ? `./#${path}` : './');
  await page.getByLabel('API token').fill(token);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('navigation', { name: 'Admin center' })).toBeVisible();
}

/** Sign out, back to the sign-in form. */
export async function signOut(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByLabel('API token')).toBeVisible();
}

/** The page's own heading. */
export function pageHeading(page: Page, name: string | RegExp): Locator {
  return page.getByRole('heading', { level: 1, name, exact: typeof name === 'string' });
}

/** A menu entry's name, with the count it may show ("Issues 2 open"). */
export function entryName(name: string): RegExp {
  return new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?: \\d+ [a-z ]+)?$`);
}

/** A menu entry. */
export function menu(page: Page, name: string): Locator {
  return page.getByRole('navigation', { name: 'Admin center' }).getByRole('link', { name: entryName(name) });
}

/** The dialog open now, by its title. */
export function dialog(page: Page, title: string | RegExp): Locator {
  return page.getByRole('dialog', { name: title });
}

/** A name no other test uses: lowercase letters, digits and hyphens. */
export function unique(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}${Math.floor(Math.random() * 1296).toString(36)}`;
}

/** The control plane's API, to set up what a test needs, as the bootstrap admin by default. */
export async function api<T = any>(
  request: APIRequestContext,
  method: string,
  path: string,
  data?: unknown,
  token = ADMIN_TOKEN,
): Promise<T> {
  const resp = await request.fetch(`/${path}`, {
    method,
    data: data === undefined ? undefined : data,
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok()) throw new Error(`${method} /${path}: ${resp.status()} ${await resp.text()}`);
  return (resp.status() === 204 ? null : await resp.json()) as T;
}

/** A new API key with `role` (for one team, with `team`): its token. */
export async function apiKey(request: APIRequestContext, role: string, team?: string): Promise<string> {
  const key = await api<{ token: string }>(request, 'POST', 'v1/apikeys', {
    name: unique(`ui-${role}`), role, team: team ?? null, expires_in_days: 1,
  });
  return key.token;
}

/** A ledger event (such as agent.block) as a whole word, in a cell that may say more. */
export function event(name: string): RegExp {
  return new RegExp(`(^|\\s)${name.replace(/\./g, '\\.')}(\\s|$)`);
}
