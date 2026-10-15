import { dialog, expect, pageHeading, signIn, test } from './fixtures';

test("keeps a destination's minimum severity while its name is typed", async ({ page }) => {
  await signIn(page, undefined, '/secops');
  await expect(pageHeading(page, 'Security operations')).toBeVisible();
  await page.getByRole('button', { name: 'Add destination' }).click();
  const form = dialog(page, 'Add a destination');
  // Its kind sets where it starts: a chat gets issues from high up.
  await form.getByLabel('Kind').selectOption({ label: 'Slack: alerts' });
  const severity = form.getByLabel('Minimum severity');
  await expect(severity).toHaveValue('high');
  await severity.selectOption({ label: 'Critical' });
  await form.getByLabel('Name', { exact: true }).fill('soc-alerts');
  await expect(severity).toHaveValue('critical');
  // Another kind starts it again.
  await form.getByLabel('Kind').selectOption({ label: 'Webhook (HTTP input): OCSF events' });
  await expect(severity).toHaveValue('info');
  await form.getByRole('button', { name: 'Cancel' }).click();
  await expect(form).toBeHidden();
});
