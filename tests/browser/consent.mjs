import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const input = JSON.parse(process.env.LOOP_BROWSER_INPUT);
const browser = await chromium.launch();
try {
  // Only ephemeral, loopback httptest TLS servers use self-signed test certificates.
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  const discovery = await page.goto(`${input.origin}/.well-known/oauth-authorization-server`);
  assert.equal(discovery.status(), 200);
  const metadata = await discovery.json();
  assert.equal(metadata.issuer, input.origin);
  const consent = await page.goto(`${metadata.authorization_endpoint}?${input.query}`);
  assert.equal(consent.status(), 200);
  assert.equal(consent.headers()['referrer-policy'], input.scenario === 'old-policy' ? 'no-referrer' : 'same-origin');
  await page.getByLabel('Owner password').fill(input.scenario === 'wrong-password' ? 'wrong-synthetic-password' : input.password);
  if (input.scenario === 'missing-cookie') await context.clearCookies();
  if (input.scenario === 'wrong-cookie') {
    const cookies = await context.cookies();
    await context.addCookies(cookies.map(cookie => ({ ...cookie, value: 'wrong-synthetic-cookie' })));
  }
  // These two negative tests inject hostile headers; old-policy/success never
  // intercept or override the browser-generated Origin, Referer, cookies or POST.
  if (['foreign-origin', 'null-origin'].includes(input.scenario)) {
    await page.route('**/oauth/authorize', async route => {
      const headers = await route.request().allHeaders();
      headers.origin = input.scenario === 'null-origin' ? 'null' : 'https://foreign.example';
      await route.continue({ headers });
    });
  }
  const posted = page.waitForResponse(response => response.request().method() === 'POST' && response.url() === metadata.authorization_endpoint);
  await page.getByRole('button', { name: 'Allow connection' }).click();
  const result = await posted;
  assert.equal(result.status(), input.scenario === 'success' ? 303 : 403);
  if (input.scenario === 'success') {
    await page.waitForURL(url => url.origin + url.pathname === input.callback);
    await page.getByText('Synthetic callback reached').waitFor();
  } else {
    await page.getByText('Authorization denied; restart the connection').waitFor();
    assert.equal(page.url(), metadata.authorization_endpoint);
  }
  console.log(`${input.scenario}: native form status ${result.status()}`);
} finally {
  await browser.close();
}
