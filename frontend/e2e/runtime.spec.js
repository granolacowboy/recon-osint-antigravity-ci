import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

const viewports = [
  { name: 'mobile', width: 390, height: 844 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'desktop', width: 1440, height: 900 },
];

const states = ['queued', 'running', 'partial', 'failed', 'cancelled', 'succeeded'];
const apiBaseUrl = process.env.PLAYWRIGHT_API_BASE_URL || 'http://127.0.0.1:8000';
const mockCorsHeaders = { 'Access-Control-Allow-Origin': '*' };

function displayState(state) {
  return state[0].toUpperCase() + state.slice(1);
}

async function expectNoHorizontalClipping(page) {
  await expect.poll(() => page.evaluate(() => (
    document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1
  ))).toBe(true);
}

async function expectNoSeriousAccessibilityViolations(page) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  const blocking = results.violations.filter(
    (violation) => ['critical', 'serious'].includes(violation.impact),
  );
  expect(blocking).toEqual([]);
}

async function mockScanApi(page, state, { populated = false } = {}) {
  const scanId = `acceptance-${state}`;
  const terminal = ['partial', 'failed', 'cancelled', 'succeeded'].includes(state);
  await page.route('**/v1/**', async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api(?=\/v1\/)/, '');
    if (path.endsWith('/events')) {
      await route.fulfill({
        status: 200,
        contentType: 'text/event-stream',
        headers: mockCorsHeaders,
        body: `id: ${scanId}-${state}\nevent: scan_status\ndata: {"state":"${state}"}\n\n`,
      });
      return;
    }
    if (path.endsWith('/graph')) {
      const graph = populated ? {
        nodes: [
          { id: 'node-domain', entity_type: 'domain', value: 'example.com', metadata: { registrar: 'Recorded provider' } },
          { id: 'node-ip', entity_type: 'ip', value: '203.0.113.10', metadata: { country: 'US' } },
        ],
        edges: [{
          id: 'edge-resolves',
          source_node_id: 'node-domain',
          target_node_id: 'node-ip',
          relationship: 'resolves_to',
        }],
        provenance: [{
          id: 'provenance-domain',
          node_id: 'node-domain',
          source_adapter_id: 'recorded-provider',
          adapter_version: '1',
          observed_at: '2026-07-11T12:00:01Z',
          confidence: 0.95,
          source_target: { target_type: 'ip', target_value: '203.0.113.10' },
        }],
        next_cursor: null,
      } : { nodes: [], edges: [], provenance: [], next_cursor: null };
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: mockCorsHeaders,
        body: JSON.stringify(graph),
      });
      return;
    }
    if (path === `/v1/scans/${scanId}`) {
      const runState = state === 'queued'
        ? 'queued'
        : state === 'running'
          ? 'running'
          : state === 'failed'
            ? 'failed'
            : state === 'cancelled'
              ? 'unavailable'
              : 'succeeded';
      const outcomeCodes = {
        queued: 'queued',
        running: 'running',
        partial: 'partial_adapter_failure',
        failed: 'provider_failure',
        cancelled: 'cancelled',
        succeeded: 'complete',
      };
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: mockCorsHeaders,
        body: JSON.stringify({
          id: scanId,
          case_id: 'acceptance-case',
          owner_id: 'acceptance-investigator',
          targets: [{ target_type: 'ip', target_value: '203.0.113.10' }],
          mode: state === 'failed' ? 'active' : 'passive',
          adapter_ids: ['recorded-provider'],
          state,
          outcome_code: outcomeCodes[state],
          created_at: '2026-07-11T12:00:00Z',
          started_at: state === 'queued' ? null : '2026-07-11T12:00:01Z',
          finished_at: terminal ? '2026-07-11T12:00:02Z' : null,
          adapter_runs: [{
            id: `run-${state}`,
            adapter_id: 'recorded-provider',
            adapter_version: '1',
            source_target: { target_type: 'ip', target_value: '203.0.113.10' },
            state: runState,
            outcome_code: state === 'failed' ? 'provider_failure' : null,
            finding_count: state === 'succeeded' ? 1 : 0,
            attempts: state === 'queued' ? 0 : 1,
            created_at: '2026-07-11T12:00:00Z',
            finished_at: terminal ? '2026-07-11T12:00:02Z' : null,
          }],
        }),
      });
      return;
    }
    await route.fulfill({
      status: 404,
      contentType: 'application/json',
      headers: mockCorsHeaders,
      body: '{"detail":"not found"}',
    });
  });
  return scanId;
}

for (const viewport of viewports) {
  test(`full stack case scan history is responsive and accessible at ${viewport.name}`, async ({ page, request }) => {
    const caseResponse = await request.post(`${apiBaseUrl}/v1/cases`, {
      data: { name: `Acceptance ${viewport.name} ${Date.now()}` },
    });
    expect(caseResponse.status()).toBe(201);
    const caseRecord = await caseResponse.json();
    const scanResponse = await request.post(`${apiBaseUrl}/v1/cases/${caseRecord.id}/scans`, {
      data: {
        targets: [{ target_type: 'ip', target_value: '203.0.113.10' }],
        mode: 'passive',
      },
    });
    expect(scanResponse.status()).toBe(202);
    const scan = await scanResponse.json();

    await page.setViewportSize(viewport);
    await page.goto(`/cases/${caseRecord.id}`);
    await expect(page.getByRole('heading', { name: 'Scan history' })).toBeVisible();
    await expect(page.getByRole('link', { name: /203\.0\.113\.10/i })).toHaveAttribute('href', `/scans/${scan.id}`);
    await expectNoHorizontalClipping(page);
    await expectNoSeriousAccessibilityViolations(page);
  });
}

for (const viewport of viewports) {
  for (const state of states) {
    test(`renders the durable ${state} scan state at ${viewport.name}`, async ({ page }) => {
      await page.setViewportSize(viewport);
      const scanId = await mockScanApi(page, state);
      await page.goto(`/scans/${scanId}`);
      await expect(page.locator('.scan-title-row .status-badge')).toHaveText(displayState(state));
      if (state === 'failed') {
        await expect(page.getByLabel(/confirm this active retry is authorized/i)).toBeVisible();
      }
      await expectNoHorizontalClipping(page);
      await expectNoSeriousAccessibilityViolations(page);
    });
  }
}

for (const viewport of viewports) {
  test(`renders populated relationships and graph controls at ${viewport.name}`, async ({ page }) => {
    await page.setViewportSize(viewport);
    const scanId = await mockScanApi(page, 'succeeded', { populated: true });
    await page.goto(`/scans/${scanId}`);

    await expect(page.getByRole('cell', { name: 'resolves to' })).toBeVisible();
    await page.getByRole('button', { name: 'example.com' }).click();
    await expect(page.getByRole('heading', { name: 'example.com' })).toBeVisible();
    await expect(page.getByText('95% confidence')).toBeVisible();

    await page.getByRole('tab', { name: 'Graph', exact: true }).click();
    await expect(page.locator('.graph-canvas')).toBeVisible();
    const filters = page.getByRole('button', { name: 'Filters' });
    const filterPanel = page.locator('#graph-filters');
    if (viewport.width <= 767) {
      await expect(filters).toBeVisible();
      await expect(filterPanel).toHaveAttribute('aria-hidden', 'true');
      await filters.click();
      await expect(filterPanel).toBeVisible();
      await expect(filterPanel).not.toHaveAttribute('aria-hidden', 'true');
      await page.keyboard.press('Escape');
      await expect(filters).toBeFocused();
      await expect(filterPanel).toHaveAttribute('aria-hidden', 'true');
    } else {
      await expect(filters).toBeHidden();
      await expect(filterPanel).toBeVisible();
    }

    await expectNoHorizontalClipping(page);
    await expectNoSeriousAccessibilityViolations(page);
  });
}
