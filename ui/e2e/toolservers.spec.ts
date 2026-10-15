import { api, apiKey, dialog, expect, signIn, test, unique } from './fixtures';

test('registers a tool server, blocks and unblocks it', async ({ page }) => {
  const name = unique('ui-tools');
  await signIn(page, undefined, '/toolservers');
  await page.getByRole('button', { name: 'Register tool server' }).click();
  const form = dialog(page, 'Register a tool server');
  await form.getByLabel('Name', { exact: true }).fill(name);
  await form.getByLabel('Upstream URL').fill('http://ui-tools.example:9000/mcp');
  await form.getByLabel('Description').fill('Registered by the browser tests.');
  await form.getByLabel('Owner').fill('qa-team');
  await form.getByRole('button', { name: 'Register server' }).click();
  await expect(form).toBeHidden();

  // An administrator's server is approved as it is registered.
  const server = page.getByRole('region', { name, exact: true });
  await expect(server).toContainText('Approved');
  await expect(server).toContainText('Registered by the browser tests.');
  await expect(server.getByRole('code').filter({ hasText: `/mcp/${name}` })).toBeVisible();

  await server.getByRole('button', { name: 'Block server' }).click();
  await dialog(page, `Block ${name}?`).getByRole('button', { name: 'Block server' }).click();
  await expect(page.getByText(`Blocked ${name}. Calls to it are refused.`)).toBeVisible();

  await server.getByRole('button', { name: /^Unblock/ }).click();
  await dialog(page, `Unblock ${name}?`).getByRole('button', { name: 'Unblock server' }).click();
  await expect(page.getByText(`Unblocked ${name}.`)).toBeVisible();
  // Unblocked, it is approved again, as it was when it was blocked.
  await expect(server.getByRole('button', { name: 'Block server' })).toBeVisible();
});

test('approves a server a registrar registered for review', async ({ page, request }) => {
  const name = unique('ui-review');
  const registrar = await apiKey(request, 'registrar');
  await api(request, 'POST', 'v1/toolservers', { name, url: 'http://ui-review.example:9000/mcp', description: 'Waits for review.' }, registrar);
  await signIn(page, undefined, '/toolservers');
  const server = page.getByRole('region', { name, exact: true });
  await expect(server).toContainText('Waits for review.');
  await server.getByRole('button', { name: /^Approve/ }).click();
  await dialog(page, `Approve ${name}?`).getByRole('button', { name: 'Approve server' }).click();
  await expect(page.getByText(`Approved ${name}.`)).toBeVisible();
  await expect(server.getByRole('button', { name: 'Block server' })).toBeVisible();
});

test("shows a server's gateway address, for agents to call", async ({ page }) => {
  await signIn(page, undefined, '/toolservers');
  const crm = page.getByRole('region', { name: 'crm', exact: true });
  await expect(crm.getByRole('code').filter({ hasText: '/mcp/crm' })).toBeVisible();
  await expect(crm.getByRole('button', { name: 'Copy gateway URL' })).toBeVisible();
});
