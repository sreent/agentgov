import { apiKey, dialog, expect, menu, pageHeading, signIn, signOut, test, unique } from './fixtures';

test('creates an API key, shows it once, and revokes it', async ({ page }) => {
  const name = unique('ui-key');
  await signIn(page, undefined, '/access');
  const keys = page.getByRole('region', { name: 'API keys' });
  await keys.getByRole('button', { name: 'Create API key' }).click();
  const form = dialog(page, 'Create an API key');
  await form.getByLabel('Name').fill(name);
  await form.getByLabel('Role').selectOption('Auditor: reads everything, including the ledger, and changes nothing');
  await form.getByLabel('Expires after').selectOption('30 days');
  await form.getByRole('button', { name: 'Create key' }).click();

  // The key is shown once, with how to use it.
  const created = dialog(page, `API key for ${name}`);
  await expect(created).toContainText("Copy the key now: it can't be shown again.");
  await expect(created.getByRole('button', { name: 'Copy API key' })).toBeVisible();
  const token = (await created.getByRole('code').first().textContent())?.trim() ?? '';
  expect(token.length).toBeGreaterThan(20);
  await expect(created).toContainText(`export AGENTGOV_TOKEN=${token}`);
  await created.getByRole('button', { name: 'Done' }).click();
  await expect(created).toBeHidden();

  const row = keys.getByRole('row').filter({ hasText: name });
  await expect(row).toContainText('Auditor');
  await expect(row).toContainText('Active');

  // It signs in, as an auditor.
  await signOut(page);
  await signIn(page, token);
  await expect(page.getByText(new RegExp(`signed in as auditor:${name}`))).toBeVisible();

  // Revoked, it no longer does.
  await signOut(page);
  await signIn(page, undefined, '/access');
  await row.getByRole('button', { name: 'Revoke' }).click();
  await dialog(page, `Revoke ${name}?`).getByRole('button', { name: 'Revoke key' }).click();
  await expect(page.getByText(`Revoked ${name}.`)).toBeVisible();
  await expect(row).toContainText('Revoked');
  await expect(row.getByRole('button', { name: 'Revoke' })).toBeHidden();

  await signOut(page);
  await page.getByLabel('API token').fill(token);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('That token was not accepted.');
});

test('an auditor reads everything and changes nothing', async ({ page, request }) => {
  await signIn(page, await apiKey(request, 'auditor'));
  // Auditors start on the compliance report.
  await expect(pageHeading(page, 'Compliance')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Evidence pack' })).toBeVisible();

  await menu(page, 'Agents').click();
  await expect(pageHeading(page, 'Agents')).toBeVisible();
  const list = page.getByRole('region', { name: 'Agent list' });
  await expect(list.getByRole('link', { name: 'support-bot', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Register agent' })).toBeHidden();
  await expect(list.getByRole('checkbox')).toHaveCount(0);

  await list.getByRole('link', { name: 'support-bot', exact: true }).click();
  await expect(pageHeading(page, 'support-bot')).toBeVisible();
  await expect(page.getByRole('region', { name: 'Recent activity' })).toBeVisible();
  await expect(page.getByRole('group', { name: 'Agent actions' })).toBeHidden();

  await menu(page, 'Tool servers').click();
  await expect(page.getByRole('region', { name: 'crm', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Register tool server' })).toBeHidden();
  await expect(page.getByRole('button', { name: 'Block server' })).toHaveCount(0);

  await menu(page, 'Access').click();
  await expect(page.getByRole('region', { name: 'API keys' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create API key' })).toBeHidden();
  await expect(page.getByRole('button', { name: 'Revoke' })).toHaveCount(0);
});

test("a role for one team sees that team's agents and pages only", async ({ page, request }) => {
  await signIn(page, await apiKey(request, 'admin', 'cx-platform'));
  // They start on their agents.
  await expect(pageHeading(page, 'Agents')).toBeVisible();
  await expect(page.getByText(/signed in as admin@cx-platform:/)).toBeVisible();
  for (const entry of ['Approvals', 'Issues', 'Agents', 'Ledger']) await expect(menu(page, entry)).toBeVisible();
  for (const entry of ['Overview', 'Tool servers', 'Policies', 'Compliance', 'Access', 'Features']) await expect(menu(page, entry)).toBeHidden();

  const list = page.getByRole('region', { name: 'Agent list' });
  await expect(list.getByRole('link', { name: 'support-bot', exact: true })).toBeVisible();
  await expect(list.getByRole('link', { name: 'billing-agent', exact: true })).toBeHidden();
  await expect(list.getByRole('link', { name: 'coding-assistant', exact: true })).toBeHidden();
  // An administrator of the team registers its agents.
  await expect(page.getByRole('button', { name: 'Register agent' })).toBeVisible();

  // Pages for the whole organisation aren't theirs: they go back to their agents.
  await page.goto('./#/access');
  await expect(pageHeading(page, 'Agents')).toBeVisible();
  await expect(page).toHaveURL(/#\/agents$/);

  // The ledger shows their agents' entries, without the organisation's chain tools.
  await menu(page, 'Ledger').click();
  await expect(pageHeading(page, 'Ledger')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Verify chain' })).toBeHidden();
});
