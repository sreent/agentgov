import { readFile } from 'node:fs/promises';
import { dialog, event, expect, pageHeading, signIn, test, unique } from './fixtures';

test('registers an agent, approves it, blocks and unblocks it', async ({ page }) => {
  const name = unique('ui-agent');
  await signIn(page, undefined, '/agents');
  await page.getByRole('button', { name: 'Register agent' }).click();
  const form = dialog(page, 'Register an agent');
  await form.getByLabel('Name', { exact: true }).fill(name);
  await form.getByLabel('Description').fill('Registered by the browser tests.');
  await form.getByLabel('Owner').fill('qa-team');
  await form.getByLabel('Sponsors').fill('alice@example.com');
  await form.getByLabel('Blueprint').selectOption('customer-support');
  await form.getByRole('button', { name: 'Register agent' }).click();

  // Registered agents wait for review: the page opens on the new one.
  await expect(pageHeading(page, name)).toBeVisible();
  await expect(page.getByRole('main')).toContainText('Pending approval');
  const actions = page.getByRole('group', { name: 'Agent actions' });

  await actions.getByRole('button', { name: 'Approve' }).click();
  await dialog(page, `Approve ${name}?`).getByRole('button', { name: 'Approve agent' }).click();
  await expect(page.getByText(`Approved ${name}. It is now active.`)).toBeVisible();
  await expect(actions.getByRole('button', { name: 'Block (kill switch)' })).toBeVisible();
  await expect(actions.getByRole('button', { name: 'Approve' })).toBeHidden();

  await actions.getByRole('button', { name: 'Block (kill switch)' }).click();
  const block = dialog(page, `Block ${name}?`);
  await block.getByLabel('Reason').fill('Browser test of the kill switch');
  await block.getByRole('button', { name: 'Block agent' }).click();
  await expect(page.getByText(`Blocked ${name}. Its tool calls are refused.`)).toBeVisible();
  await expect(actions.getByRole('button', { name: 'Unblock' })).toBeVisible();

  // Unblocking gives back what the block found: active, not waiting for approval again.
  await actions.getByRole('button', { name: 'Unblock' }).click();
  await dialog(page, `Unblock ${name}?`).getByRole('button', { name: 'Unblock agent' }).click();
  await expect(page.getByText(`Unblocked ${name}.`)).toBeVisible();
  await expect(actions.getByRole('button', { name: 'Block (kill switch)' })).toBeVisible();
  await expect(actions.getByRole('button', { name: 'Approve' })).toBeHidden();

  // Each step is in the evidence ledger.
  const activity = page.getByRole('region', { name: 'Recent activity' });
  for (const type of ['agent.registered', 'agent.approve', 'agent.block', 'agent.unblock']) {
    await expect(activity.getByRole('cell', { name: event(type) })).toBeVisible();
  }
  await expect(activity.getByRole('cell', { name: event('agent.block') })).toContainText('Browser test of the kill switch');
});

test('refuses to register an agent without a name, and keeps what was typed', async ({ page }) => {
  await signIn(page, undefined, '/agents');
  await page.getByRole('button', { name: 'Register agent' }).click();
  const form = dialog(page, 'Register an agent');
  await form.getByLabel('Description').fill('No name yet');
  await form.getByRole('button', { name: 'Register agent' }).click();
  await expect(form.getByRole('alert')).toHaveText('Name is required.');
  await expect(form.getByLabel('Description')).toHaveValue('No name yet');
  await form.getByRole('button', { name: 'Cancel' }).click();
  await expect(form).toBeHidden();
});

test('finds agents by name, status and owner', async ({ page }) => {
  await signIn(page, undefined, '/agents');
  const list = page.getByRole('region', { name: 'Agent list' });
  const search = page.getByRole('searchbox', { name: 'Search agents' });
  await search.fill('billing');
  await expect(list.getByRole('link', { name: 'billing-agent', exact: true })).toBeVisible();
  await expect(list.getByRole('link', { name: 'support-bot', exact: true })).toBeHidden();
  await search.fill('');
  await expect(list.getByRole('link', { name: 'support-bot', exact: true })).toBeVisible();

  const owner = page.getByRole('combobox', { name: 'Owner' });
  await owner.selectOption({ label: 'developer-experience (1)' });
  await expect(list.getByRole('link', { name: 'coding-assistant', exact: true })).toBeVisible();
  await expect(list.getByRole('link', { name: 'support-bot', exact: true })).toBeHidden();
  await owner.selectOption({ label: 'Any owner' });

  const status = page.getByRole('group', { name: 'Filter by status' });
  await status.getByRole('button', { name: /^Deleted \d+$/ }).click();
  await expect(status.getByRole('button', { name: /^Deleted \d+$/ })).toHaveAttribute('aria-pressed', 'true');
  await expect(list.getByRole('link', { name: 'support-bot', exact: true })).toBeHidden();
  await status.getByRole('button', { name: /^All \d+$/ }).click();
  await expect(list.getByRole('link', { name: 'support-bot', exact: true })).toBeVisible();
});

test('sorts the list by a column', async ({ page }) => {
  await signIn(page, undefined, '/agents');
  const list = page.getByRole('region', { name: 'Agent list' });
  const header = list.getByRole('columnheader', { name: 'Agent', exact: true });
  await header.getByRole('button', { name: 'Agent' }).click();
  await expect(header).toHaveAttribute('aria-sort', /ascending|descending/);
  const first = await header.getAttribute('aria-sort');
  await header.getByRole('button', { name: 'Agent' }).click();
  await expect(header).not.toHaveAttribute('aria-sort', first ?? '');
});

test('chooses several agents for one action, and lets them go', async ({ page }) => {
  await signIn(page, undefined, '/agents');
  const list = page.getByRole('region', { name: 'Agent list' });
  await list.getByRole('checkbox', { name: 'Choose billing-agent' }).check();
  await list.getByRole('checkbox', { name: 'Choose support-bot' }).check();
  const chosen = page.getByRole('region', { name: 'Chosen agents' });
  await expect(chosen).toContainText('2 agents chosen');
  for (const action of ['Edit…', 'Classify…', 'Block', 'Delete']) {
    await expect(chosen.getByRole('button', { name: action, exact: true })).toBeVisible();
  }
  await chosen.getByRole('button', { name: 'Block', exact: true }).click();
  const block = dialog(page, 'Block 2 agents?');
  await expect(block).toContainText('billing-agent');
  await expect(block).toContainText('support-bot');
  await block.getByRole('button', { name: 'Cancel' }).click();
  await chosen.getByRole('button', { name: 'Clear' }).click();
  await expect(chosen).toBeHidden();
  await expect(list.getByRole('checkbox', { name: 'Choose billing-agent' })).not.toBeChecked();
});

test('downloads the list as CSV', async ({ page }) => {
  await signIn(page, undefined, '/agents');
  const downloading = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download CSV' }).click();
  const file = await downloading;
  expect(file.suggestedFilename()).toMatch(/\.csv$/);
  const csv = await readFile(await file.path(), 'utf8');
  for (const agent of ['support-bot', 'billing-agent', 'coding-assistant']) expect(csv).toContain(agent);
});
