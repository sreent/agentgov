import { readFile } from 'node:fs/promises';
import { api, event, expect, pageHeading, signIn, test, unique } from './fixtures';

test('verifies the ledger chain', async ({ page }) => {
  await signIn(page, undefined, '/ledger');
  await expect(pageHeading(page, 'Ledger')).toBeVisible();
  await page.getByRole('button', { name: 'Verify chain' }).click();
  await expect(page.getByText('Chain intact.')).toBeVisible();
  await expect(page.getByRole('main')).toContainText('nothing was edited, removed or reordered');
});

test("filters the ledger, and opens an entry's details", async ({ page, request }) => {
  const name = unique('ui-ledger');
  await api(request, 'POST', 'v1/agents', { name, owner: 'qa-team', sponsors: ['alice@example.com'], blueprint: 'customer-support' });
  await api(request, 'POST', `v1/agents/${name}/block`, { reason: 'Seen in the ledger' });
  await signIn(page, undefined, '/ledger');
  const entries = page.getByRole('region', { name: 'Ledger entries' });
  const agent = page.getByRole('main').getByLabel('Agent', { exact: true });

  await agent.fill(name);
  await agent.press('Enter');
  await expect(page).toHaveURL(new RegExp(`agent=${name}`));
  // Its registration and its block, and anything a background job wrote about it since.
  await expect(page.getByText(/^[2-9] entries$/)).toBeVisible();
  await expect(entries.getByRole('cell', { name: event('agent.registered') })).toBeVisible();

  await page.getByLabel('Event type').selectOption('Agent lifecycle');
  await expect(page).toHaveURL(/type=agent\.\*/);
  const block = entries.getByRole('row').filter({ has: page.getByRole('cell', { name: event('agent.block') }) });
  await expect(block).toContainText('Seen in the ledger');

  const details = block.getByRole('button', { name: /^#\d+ details$/ });
  await expect(details).toHaveAttribute('aria-expanded', 'false');
  // Only the entry opened shows its details.
  const shown = entries.getByText('Previous hash').filter({ visible: true });
  await expect(shown).toHaveCount(0);
  await details.click();
  await expect(details).toHaveAttribute('aria-expanded', 'true');
  await expect(shown).toHaveCount(1);
  await details.click();
  await expect(shown).toHaveCount(0);

  await page.getByRole('button', { name: 'Clear filters' }).click();
  await expect(agent).toHaveValue('');
  await expect(page).not.toHaveURL(/agent=/);
});

test('exports the ledger as JSON Lines', async ({ page }) => {
  await signIn(page, undefined, '/ledger');
  const downloading = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export JSONL' }).click();
  const file = await downloading;
  expect(file.suggestedFilename()).toMatch(/\.jsonl$/);
  await expect(page.getByText(/^Exported the full ledger as JSON Lines/)).toBeVisible();
  const lines = (await readFile(await file.path(), 'utf8')).trim().split('\n');
  expect(lines.length).toBeGreaterThan(10);
  const first = JSON.parse(lines[0]);
  expect(first).toHaveProperty('hash');
  expect(first).toHaveProperty('prev_hash');
});

test('reports on a framework, for a period, and downloads the evidence pack', async ({ page }) => {
  await signIn(page, undefined, '/ledger/compliance');
  await expect(pageHeading(page, 'Compliance')).toBeVisible();
  await expect(page.getByRole('region', { name: 'What AgentGov saw' })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Art. 12 Record-keeping' })).toBeVisible();
  await expect(page.getByRole('main')).toContainText(/The ledger verifies: \d+ entries/);

  await page.getByLabel('Framework').selectOption('ISO/IEC 42001:2023, Annex A');
  await expect(page).toHaveURL(/framework=/);
  await expect(page.getByRole('region', { name: 'Art. 12 Record-keeping' })).toBeHidden();
  await page.getByLabel('Period').selectOption('Last 30 days');
  await expect(page).toHaveURL(/days=30/);
  await expect(page.getByLabel('Framework')).toHaveValue(/iso/i);

  const downloading = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Evidence pack' }).click();
  const file = await downloading;
  expect(file.suggestedFilename()).toMatch(/\.zip$/);
  await expect(page.getByText(/^Downloaded the evidence pack/)).toBeVisible();
  // A zip archive.
  expect((await readFile(await file.path())).subarray(0, 2).toString()).toBe('PK');
});

test('lists each agent in the classification register', async ({ page }) => {
  await signIn(page, undefined, '/ledger/register');
  await expect(pageHeading(page, 'Classification register')).toBeVisible();
  const register = page.getByRole('region', { name: 'Classification register' });
  for (const agent of ['support-bot', 'billing-agent', 'coding-assistant']) {
    await expect(register.getByRole('link', { name: agent, exact: true })).toBeVisible();
  }
});
