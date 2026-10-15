import { api, dialog, expect, menu, pageHeading, signIn, test, unique } from './fixtures';

test('approves an agent waiting in the inbox', async ({ page, request }) => {
  const name = unique('ui-waiting');
  await api(request, 'POST', 'v1/agents', {
    name, description: 'Waits for a decision.', owner: 'qa-team', sponsors: ['alice@example.com'], blueprint: 'customer-support',
  });
  await signIn(page, undefined, '/approvals');
  await expect(pageHeading(page, 'Approvals')).toBeVisible();
  // The menu says how many decisions wait.
  await expect(menu(page, 'Approvals')).toHaveAccessibleName(/^Approvals \d+ /);
  const waiting = page.getByRole('region', { name: 'Agents waiting for approval' });
  const item = waiting.getByRole('listitem').filter({ has: page.getByRole('link', { name, exact: true }) });
  await item.getByRole('button', { name: 'Approve' }).click();
  const approve = dialog(page, `Approve ${name}?`);
  await approve.getByLabel('Reason').fill('Reviewed by the browser tests');
  await approve.getByRole('button', { name: 'Approve agent' }).click();
  await expect(page.getByRole('link', { name, exact: true })).toBeHidden();

  await page.goto(`./#/agents/${name}`);
  await expect(pageHeading(page, name)).toBeVisible();
  await expect(page.getByRole('group', { name: 'Agent actions' }).getByRole('button', { name: 'Block (kill switch)' })).toBeVisible();
});

test('blocks an agent waiting in the inbox instead', async ({ page, request }) => {
  const name = unique('ui-refused');
  await api(request, 'POST', 'v1/agents', { name, owner: 'qa-team', sponsors: ['alice@example.com'], blueprint: 'customer-support' });
  await signIn(page, undefined, '/approvals');
  const item = page.getByRole('region', { name: 'Agents waiting for approval' })
    .getByRole('listitem').filter({ has: page.getByRole('link', { name, exact: true }) });
  await item.getByRole('button', { name: 'Block' }).click();
  await dialog(page, `Block ${name}?`).getByRole('button', { name: 'Block agent' }).click();
  await expect(page.getByRole('link', { name, exact: true })).toBeHidden();
  await page.goto(`./#/agents/${name}`);
  await expect(page.getByRole('group', { name: 'Agent actions' }).getByRole('button', { name: 'Unblock' })).toBeVisible();
});

test('shows the decisions made, apart from those waiting', async ({ page }) => {
  await signIn(page, undefined, '/approvals');
  const views = page.getByRole('navigation', { name: 'Approval views' });
  await views.getByRole('link', { name: /^History/ }).click();
  await expect(page).toHaveURL(/#\/approvals\/history$/);
  await expect(views.getByRole('link', { name: /^History/ })).toHaveAttribute('aria-current', 'page');
  await views.getByRole('link', { name: /^Pending/ }).click();
  await expect(page).toHaveURL(/#\/approvals$/);
});
