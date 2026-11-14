// End-to-end tests against the real single binary (UI embedded), run by
// `make e2e`. A fresh data directory per run keeps results independent of
// whatever the developer has analysed locally.
import { defineConfig } from '@playwright/test';

const PORT = 7979;
const DATA = process.env.E2E_DATA ?? `${process.env.TMPDIR ?? '/tmp'}/drishti-e2e`;

export default defineConfig({
  testDir: 'e2e',
  timeout: 60_000,
  expect: { timeout: 15_000 },
  // Desktop and mobile share one server and data dir: run them in order.
  workers: 1,
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'line' : 'list',
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    browserName: 'chromium',
    headless: true,
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'desktop', grep: /desktop: /, use: { viewport: { width: 1400, height: 900 } } },
    { name: 'mobile', grep: /mobile: /, use: { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true } },
  ],
  webServer: {
    command: `rm -rf "${DATA}" && ../target/release/drishti serve --port ${PORT} --data "${DATA}"`,
    url: `http://127.0.0.1:${PORT}/`,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
