// Core user journeys on a desktop (1400 px) and a phone-sized (390 px)
// viewport: first-run tour → upload → plain-language summary → safety
// checks → Expert mode → read a function → flow graph → rename.
import { expect, Page, test } from '@playwright/test';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

// A small benign corpus program with symbols (`make corpus`); /bin/ls is a
// fallback so the test also runs on a fresh checkout.
const SAMPLE = [
  process.env.E2E_SAMPLE,
  resolve('../corpus/out/switches-arm64-O0'),
  resolve('../corpus/out/switches-x86_64-O0'),
  '/bin/ls',
].find((p): p is string => Boolean(p && existsSync(p)))!;

/** Fail on uncaught page errors and console errors. */
function watchErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(`console: ${m.text()}`); });
  return errors;
}

/** Start in Simple mode with the tour already seen. */
async function fresh(page: Page) {
  await page.addInitScript(() => {
    if (!sessionStorage.getItem('e2e-init')) {
      sessionStorage.setItem('e2e-init', '1');
      localStorage.setItem('drishti-tour', '1');
      localStorage.setItem('drishti-mode', 'simple');
    }
  });
}

async function upload(page: Page) {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'What would you like to check?' })).toBeVisible();
  await page.locator('input[type=file]').setInputFiles(SAMPLE);
  await expect(page).toHaveURL(/#\/b\/[0-9a-f]{64}\/overview/);
  await expect(page.locator('.vh-name')).toHaveText(SAMPLE.split('/').pop()!);
  // The verdict has a plain-language title (e.g. "Looks normal").
  await expect(page.locator('.vh-title')).not.toBeEmpty();
}

/** The page never scrolls sideways (phone layouts). */
async function expectNoHorizontalScroll(page: Page) {
  const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(over).toBeLessThanOrEqual(1);
}

async function openFunction(page: Page, query: string) {
  const search = page.getByRole('searchbox', { name: 'Search functions' });
  await search.fill(query);
  // Analysis runs automatically on open; the list fills when it is done.
  const row = page.locator('a.fnrow', { hasText: query }).first();
  await expect(row).toBeVisible({ timeout: 30_000 });
  await row.click();
  await expect(page).toHaveURL(/\/code\?a=0x[0-9a-f]+/);
  await expect(page.locator('.code-head h2')).toContainText(query);
  await expect(page.locator('.listing .insn').first()).toBeVisible();
}

async function graphAndBack(page: Page) {
  await page.locator('.code-head').getByRole('button', { name: 'Graph' }).click();
  await expect(page).toHaveURL(/\/graph\?a=/);
  await expect(page.locator('g.gnode').first()).toBeVisible();
  expect(await page.locator('g.gnode').count()).toBeGreaterThan(0);
  await page.locator('.code-head').getByRole('button', { name: 'Listing' }).click();
  await expect(page).toHaveURL(/\/code\?a=/);
}

async function rename(page: Page, to: string) {
  page.once('dialog', (d) => d.accept(to));
  await page.locator('.code-head').getByRole('button', { name: 'Rename' }).click();
  await expect(page.getByRole('status')).toContainText(`Renamed to ${to}`);
  await expect(page.locator('.code-head h2')).toHaveText(to);
}

/** Advanced search: an instruction pattern, then jump to a hit. */
async function searchCode(page: Page) {
  await page.keyboard.press('/');
  await expect(page.locator('.code-head h2', { hasText: 'Search' })).toBeVisible();
  await page.getByRole('tab', { name: 'Instructions' }).click();
  await page.getByRole('textbox', { name: 'Search query' }).fill('ret');
  await page.locator('form.search-form button[type=submit]').click();
  await expect(page.locator('.search-sum')).toContainText('match');
  const hit = page.locator('.shit').first();
  await expect(hit).toContainText('ret');
  await hit.click();
  await expect(page).toHaveURL(/\/code\?a=0x[0-9a-f]+/);
}

test('desktop: first visit shows a short tour', async ({ page }) => {
  const errors = watchErrors(page);
  await page.goto('/');
  const tour = page.getByRole('dialog', { name: 'Introduction' });
  await expect(tour).toBeVisible();
  await tour.getByRole('button', { name: 'Next' }).click();
  await tour.getByRole('button', { name: 'Skip' }).click();
  await expect(tour).toBeHidden();
  await page.reload();
  await expect(page.getByRole('dialog', { name: 'Introduction' })).toBeHidden();
  expect(errors).toEqual([]);
});

test('desktop: summary, safety checks, expert mode, read a function, graph, rename', async ({ page }) => {
  const errors = watchErrors(page);
  await fresh(page);
  await upload(page);
  const nav = page.locator('nav.sidenav');
  await expect(nav.getByRole('link', { name: 'Safety checks' })).toBeVisible();
  // Simple mode hides the code views.
  await expect(nav.getByRole('link', { name: 'Code' })).toHaveCount(0);
  await nav.getByRole('link', { name: 'Safety checks' }).click();
  await expect(page.getByRole('heading', { name: 'Safety checks', level: 1 })).toBeVisible();
  // Weak spots: the static input→sink audit (shown in both modes).
  await nav.getByRole('link', { name: 'Weak spots' }).click();
  await expect(page.getByText('could reach a risky operation')).toBeVisible();
  await page.getByRole('group', { name: 'Detail level' }).getByRole('button', { name: 'Expert' }).click();
  await nav.getByRole('link', { name: 'Functions' }).click();
  // Plain-English query translates to the function-query language.
  const nlBox = page.getByRole('searchbox', { name: 'Ask for functions in plain English' });
  await nlBox.fill('functions that run shell commands');
  await nlBox.press('Enter');
  await expect(page.locator('.fn-nl-info')).toBeVisible();
  await openFunction(page, 'main');
  await graphAndBack(page);
  await rename(page, 'main_desktop');
  // The rename shows in the function list too (✎ marks user names).
  await expect(page.locator('aside.side a.fnrow', { hasText: 'main_desktop' })).toContainText('✎');
  await searchCode(page);
  // Back to Simple: the code view goes away and the summary returns.
  await page.getByRole('group', { name: 'Detail level' }).getByRole('button', { name: 'Simple' }).click();
  await expect(page).toHaveURL(/\/overview/);
  expect(errors).toEqual([]);
});

test('mobile: same journey through the bottom bar', async ({ page }) => {
  const errors = watchErrors(page);
  await fresh(page);
  await upload(page);
  const bottom = page.locator('nav.bottom');
  await expect(bottom).toBeVisible();
  await expectNoHorizontalScroll(page);
  await bottom.getByText('Checks').click();
  await expect(page.getByRole('heading', { name: 'Safety checks', level: 1 })).toBeVisible();
  await expectNoHorizontalScroll(page);
  await page.getByRole('group', { name: 'Detail level' }).getByRole('button', { name: 'Expert' }).click();
  await bottom.getByText('More').click();
  await page.locator('.sheet-body').getByText('Functions').click();
  await openFunction(page, 'main');
  await expectNoHorizontalScroll(page);
  await graphAndBack(page);
  await rename(page, 'main_mobile');
  await expectNoHorizontalScroll(page);
  expect(errors).toEqual([]);
});
