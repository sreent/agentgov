import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig, devices } from '@playwright/test';

// The admin UI's browser tests run against a control plane of their own, with the
// examples' manifests applied (scripts/ui-test-server.py), on this port.
const port = Number(process.env.AGENTGOV_UI_TEST_PORT || 8765);
const repo = resolve(import.meta.dirname, '..');
const venvPython = resolve(repo, '.venv/bin/python');
const python = process.env.AGENTGOV_PYTHON || (existsSync(venvPython) ? venvPython : 'python3');

export default defineConfig({
  testDir: './e2e',
  // The tests share one control plane, and some change what others see (an agent
  // blocked, a feature's mode): one at a time, in file order.
  workers: 1,
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  // A flaky test is fixed, not retried. CI's machines are slower than a laptop.
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: `http://127.0.0.1:${port}/ui/`,
    actionTimeout: 15_000,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    // Its log goes into test-results, which Playwright empties before starting it.
    command: `"${python}" "${resolve(repo, 'scripts/ui-test-server.py')}" --port ${port} --log "${resolve(import.meta.dirname, 'test-results/control-plane.log')}"`,
    url: `http://127.0.0.1:${port}/readyz`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    stdout: 'pipe',
    // Asked to stop, it stops the control plane and removes its database; by default
    // Playwright would kill it outright.
    gracefulShutdown: { signal: 'SIGTERM', timeout: 15_000 },
  },
});
