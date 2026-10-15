import { ADMIN_TOKEN, expect, pageHeading, signIn, test } from './fixtures';

test('signs in with an API token, and out again', async ({ page }) => {
  await page.goto('./');
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await page.getByLabel('API token').fill(ADMIN_TOKEN);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(pageHeading(page, 'Overview')).toBeVisible();
  await expect(page.getByText(/signed in as admin:bootstrap/)).toBeVisible();

  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await expect(page.getByText('You signed out.')).toBeVisible();
});

test('refuses a token it does not know, and says why', async ({ page }) => {
  await page.goto('./');
  await page.getByLabel('API token').fill('not-a-token');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('That token was not accepted.');
  await expect(page.getByRole('navigation', { name: 'Admin center' })).toBeHidden();
});

test('asks for a token before trying', async ({ page }) => {
  await page.goto('./');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText('Enter an API token.');
});

test('shows the token on request', async ({ page }) => {
  await page.goto('./');
  const token = page.getByLabel('API token');
  await expect(token).toHaveAttribute('type', 'password');
  await page.getByRole('button', { name: 'Show' }).click();
  await expect(token).toHaveAttribute('type', 'text');
  await page.getByRole('button', { name: 'Hide' }).click();
  await expect(token).toHaveAttribute('type', 'password');
});

test('opens the page a link was for, once signed in', async ({ page }) => {
  await signIn(page, ADMIN_TOKEN, '/toolservers');
  await expect(pageHeading(page, 'Tool servers')).toBeVisible();
});

test('stays signed in when the page is reloaded', async ({ page }) => {
  await signIn(page);
  await expect(pageHeading(page, 'Overview')).toBeVisible();
  await page.reload();
  await expect(pageHeading(page, 'Overview')).toBeVisible();
  await expect(page.getByLabel('API token')).toBeHidden();
});
