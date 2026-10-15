import { api, dialog, expect, pageHeading, signIn, test } from './fixtures';

test("changes a control's mode, asking first when it lowers it", async ({ page, request }) => {
  try {
    await signIn(page, undefined, '/features');
    await expect(pageHeading(page, 'Features')).toBeVisible();
    const mode = page.getByRole('radiogroup', { name: 'Least-privilege access: mode' });
    await expect(mode.getByRole('radio', { name: 'Enforce' })).toBeChecked();

    // Lowering it asks first; cancelled, nothing changes.
    await mode.getByRole('radio', { name: 'Off' }).click();
    const off = dialog(page, 'Least-privilege access: off?');
    await off.getByRole('button', { name: 'Cancel' }).click();
    await expect(off).toBeHidden();
    await expect(mode.getByRole('radio', { name: 'Enforce' })).toBeChecked();

    await mode.getByRole('radio', { name: 'Monitor' }).click();
    await dialog(page, 'Least-privilege access: monitor?').getByRole('button', { name: 'Set to monitor' }).click();
    await expect(page.getByText(/^Least-privilege access: monitor\./)).toBeVisible();
    await expect(mode.getByRole('radio', { name: 'Monitor' })).toBeChecked();

    // Raising it doesn't ask.
    await mode.getByRole('radio', { name: 'Enforce' }).click();
    await expect(page.getByText(/^Least-privilege access: enforce\./)).toBeVisible();
    await expect(mode.getByRole('radio', { name: 'Enforce' })).toBeChecked();
  } finally {
    await api(request, 'PUT', 'v1/features/least-privilege', { mode: 'enforce' });
  }
});

test('previews a starting point before applying it', async ({ page }) => {
  await signIn(page, undefined, '/features');
  const presets = page.getByRole('region', { name: 'Starting points' });
  await presets.getByRole('button', { name: 'Apply monitor everything…' }).click();
  const preview = dialog(page, 'Monitor everything?');
  await expect(preview.getByRole('listitem').filter({ hasText: 'Least-privilege access' })).toContainText('enforce to monitor');
  await expect(preview.getByRole('button', { name: /^Change \d+ features$/ })).toBeVisible();
  await preview.getByRole('button', { name: 'Cancel' }).click();
  await expect(preview).toBeHidden();
  await expect(page.getByRole('radiogroup', { name: 'Least-privilege access: mode' }).getByRole('radio', { name: 'Enforce' })).toBeChecked();
});
