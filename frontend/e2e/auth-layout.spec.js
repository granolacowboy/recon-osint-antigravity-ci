import { expect, test } from '@playwright/test';

const enabled = process.env.PLAYWRIGHT_AUTH_LAYOUT === '1';
const authority = process.env.PLAYWRIGHT_OIDC_AUTHORITY || 'https://issuer.test';
const clientId = process.env.PLAYWRIGHT_OIDC_CLIENT_ID || 'recon-e2e';

test('authenticated header stays within the 390px viewport', async ({ page }) => {
  test.skip(!enabled, 'Run against a frontend built with the matching OIDC test settings.');
  const identity = 'Investigator With A Deliberately Long Organization Identity';
  await page.addInitScript(({ storageKey, user }) => {
    window.sessionStorage.setItem(storageKey, JSON.stringify(user));
  }, {
    storageKey: `oidc.user:${authority}:${clientId}`,
    user: {
      access_token: 'e2e-local-token',
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      profile: { name: identity, sub: 'e2e-investigator' },
      scope: 'openid profile email',
      token_type: 'Bearer',
    },
  });
  await page.route('**/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/api(?=\/v1\/)/, '');
    if (path === '/v1/cases') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
      return;
    }
    if (path === '/v1/capabilities') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          adapters: [],
          dependencies: {},
          policy: { passive_default: true, active_scanning_enabled: false },
        }),
      });
      return;
    }
    await route.fulfill({ status: 404, contentType: 'application/json', body: '{"detail":"not found"}' });
  });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/cases');

  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
  await expect(page.locator('.nav-signout span')).toHaveText(identity);
  await expect(page.locator('.nav-signout span')).toBeHidden();
  await expect.poll(() => page.evaluate(() => ({
    documentFits: document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1,
    headerFits: document.querySelector('.app-header').scrollWidth
      <= document.querySelector('.app-header').clientWidth + 1,
  }))).toEqual({ documentFits: true, headerFits: true });
});
