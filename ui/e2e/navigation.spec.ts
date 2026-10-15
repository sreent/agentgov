import { entryName, expect, menu, pageHeading, signIn, test } from './fixtures';

// Every entry of the menu, by group, and the heading of the page it opens.
const MENU: [group: string | null, entry: string, heading: string][] = [
  [null, 'Overview', 'Overview'],
  ['Work', 'Approvals', 'Approvals'],
  ['Work', 'Issues', 'Issues'],
  ['Agents', 'Agents', 'Agents'],
  ['Agents', 'Agent map', 'Agent map'],
  ['Agents', 'Platforms', 'Platforms'],
  ['Gateway', 'Tool servers', 'Tool servers'],
  ['Gateway', 'Models', 'Models'],
  ['Gateway', 'Policies', 'Policies'],
  ['Gateway', 'Developer tools', 'Developer tools'],
  ['Evidence', 'Ledger', 'Ledger'],
  ['Evidence', 'Compliance', 'Compliance'],
  ['Evidence', 'Register', 'Classification register'],
  ['Settings', 'Teams', 'Teams'],
  ['Settings', 'Security operations', 'Security operations'],
  ['Settings', 'Access', 'Access'],
  ['Settings', 'Features', 'Features'],
];

test('every page of the menu opens, in its group', async ({ page }) => {
  await signIn(page);
  const nav = page.getByRole('navigation', { name: 'Admin center' });
  for (const [group, entry, heading] of MENU) {
    if (group) await expect(nav.getByRole('list', { name: group }).getByRole('link', { name: entryName(entry) })).toBeVisible();
    await menu(page, entry).click();
    await expect(pageHeading(page, heading), `${entry} opens`).toBeVisible();
    await expect(menu(page, entry)).toHaveAttribute('aria-current', 'page');
    await expect(page.getByText(/couldn't be loaded/), `${entry} loads`).toBeHidden();
    await expect(page).toHaveTitle(new RegExp(`· AgentGov$`));
  }
});

test('pages that hang off others open from their links', async ({ page }) => {
  await signIn(page, undefined, '/agents');
  await page.getByRole('link', { name: 'support-bot', exact: true }).click();
  await expect(pageHeading(page, 'support-bot')).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Breadcrumb' }).getByRole('link', { name: 'Agents' })).toBeVisible();

  await page.goto('./#/approvals/history');
  await expect(pageHeading(page, 'Approvals')).toBeVisible();
  await page.goto('./#/findings/types');
  await expect(pageHeading(page, 'Issues')).toBeVisible();
});

test('an address that is no page goes to the overview', async ({ page }) => {
  await signIn(page, undefined, '/no-such-page');
  await expect(pageHeading(page, 'Overview')).toBeVisible();
});

test('the overview links to what it counts', async ({ page }) => {
  await signIn(page);
  await expect(pageHeading(page, 'Overview')).toBeVisible();
  const figures = page.getByRole('region', { name: 'Key figures' });
  await figures.getByRole('link', { name: /^Total agents/ }).click();
  await expect(pageHeading(page, 'Agents')).toBeVisible();
});
