import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const input = JSON.parse(process.env.LOOP_BROWSER_INPUT);
const browser = await chromium.launch(process.env.LOOP_CHROMIUM_EXECUTABLE ? { executablePath: process.env.LOOP_CHROMIUM_EXECUTABLE } : {});
try {
  // Only ephemeral, loopback httptest TLS servers use self-signed test certificates.
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.on('console', message => { if (message.type() === 'error') console.log(`browser console: ${message.text()}`); });
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
  // A genuinely foreign document submits the captured flow with the correct
  // synthetic password. Same-site loopback ports retain the Strict cookie, so
  // the server's Origin check must reject it. No request headers are forged.
  if (['foreign-origin', 'null-origin'].includes(input.scenario)) {
    const flow = await page.locator('input[name="flow"]').inputValue();
    await page.goto(`${new URL(input.callback).origin}/hostile`);
    await page.evaluate(({ action, flow, password }) => {
      const form = document.createElement('form');
      form.method = 'post';
      form.action = action;
      for (const [name, value] of Object.entries({ flow, password, decision: 'allow' })) {
        const field = document.createElement('input');
        field.type = 'hidden'; field.name = name; field.value = value;
        form.appendChild(field);
      }
      const button = document.createElement('button');
      button.textContent = 'Allow connection'; button.type = 'submit';
      form.appendChild(button); document.body.appendChild(form);
    }, { action: metadata.authorization_endpoint, flow, password: input.password });
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
