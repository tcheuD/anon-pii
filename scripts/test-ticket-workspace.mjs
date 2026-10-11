#!/usr/bin/env node
// Exercises the published page and actual checked-in WASM engine. Install
// Playwright separately and expose it via NODE_PATH; no project npm tree needed.
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { dirname, extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const docs = resolve(dirname(fileURLToPath(import.meta.url)), '../docs');
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm' };
const server = createServer((request, response) => {
  const pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
  const path = resolve(docs, `.${pathname === '/' ? '/index.html' : pathname}`);
  if (!path.startsWith(docs + sep)) {
    response.writeHead(403).end();
    return;
  }
  try {
    const body = readFileSync(path);
    response.writeHead(200, { 'Content-Type': mime[extname(path)] || 'application/octet-stream' }).end(body);
  } catch {
    response.writeHead(404).end();
  }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const executablePath = process.env.CHROMIUM_PATH || [
  '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome',
].find(existsSync);
let browser;
let checks = 0;

async function check(label, callback) {
  await callback();
  checks += 1;
  console.log(`ok ${checks} - ${label}`);
}

try {
  browser = await chromium.launch({ executablePath, headless: true });
  const context = await browser.newContext();
  await context.addInitScript(() => {
    window.__copied = [];
    window.__clipboardReject = false;
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async text => {
          if (window.__clipboardReject) throw new Error('Clipboard denied for test');
          window.__copied.push(text);
        },
      },
    });
  });
  const page = await context.newPage();
  const requests = [];
  const errors = [];
  page.on('request', request => requests.push({ method: request.method(), url: request.url(), body: request.postData() }));
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(origin, { waitUntil: 'networkidle' });
  await page.waitForFunction(() => document.getElementById('engstats').textContent.includes('Local engine ready'));
  const field = id => page.locator(`#${id}`);
  const click = id => field(id).click();
  const input = id => field(id).inputValue();
  const disabled = id => field(id).isDisabled();
  const source = 'Payment failed for avery@example.invalid from 192.0.2.20. Please investigate.';
  let tokenized;
  let oldToken;

  await check('empty input and initial session cannot copy or restore', async () => {
    assert.equal(await input('ticket-source'), '');
    for (const id of ['prepare-ticket', 'copy-ticket', 'ticket-reply', 'restore-reply', 'copy-reply']) {
      assert.equal(await disabled(id), true, id);
    }
    await field('ticket-source').fill(' \n ');
    assert.equal(await disabled('prepare-ticket'), true);
  });

  await check('explicit preparation redacts with the actual WASM engine', async () => {
    await field('ticket-source').fill(source);
    assert.equal(await input('ticket-prepared'), '', 'typing must not prepare a session');
    await click('prepare-ticket');
    tokenized = await input('ticket-prepared');
    assert.ok(!tokenized.includes('avery@example.invalid'));
    assert.ok(!tokenized.includes('192.0.2.20'));
    assert.match(tokenized, /\[EMAIL_ADDRESS_[a-f0-9]{8}\]/);
    assert.match(tokenized, /\[IP_ADDRESS_[a-f0-9]{8}\]/);
    assert.equal(await disabled('copy-ticket'), false);
    oldToken = tokenized.match(/\[EMAIL_ADDRESS_[a-f0-9]{8}\]/)[0];
  });

  await check('copy uses engine output even when the displayed field changes', async () => {
    await field('ticket-prepared').evaluate((element, original) => { element.value = original; }, source);
    await click('copy-ticket');
    assert.equal(await page.evaluate(() => window.__copied.at(-1)), tokenized);
    assert.equal(await field('copy-ticket-feedback').textContent(), 'Copied');
    await field('ticket-prepared').evaluate((element, output) => { element.value = output; }, tokenized);
  });

  await check('opening the support-ticket guide preserves the prepared session in its original tab', async () => {
    const guideUrl = 'https://github.com/tcheuD/anon-pii/blob/main/docs/support-ticket.md';
    const guideRequests = [];
    // Intercept the popup at context level so the test uses no external service.
    const serveGuide = route => {
      const request = route.request();
      guideRequests.push({ url: request.url(), method: request.method(), body: request.postData() });
      return route.fulfill({ contentType: 'text/html', body: '<title>Support-ticket guide fixture</title>' });
    };
    await context.route(guideUrl, serveGuide);
    let guide;
    try {
      await field('ticket-reply').fill(tokenized);
      const workspaceUrl = page.url();
      [guide] = await Promise.all([
        context.waitForEvent('page'),
        page.getByRole('link', { name: 'Read the support-ticket guide (opens in a new tab)', exact: true }).click(),
      ]);
      await guide.waitForLoadState('domcontentloaded');
      assert.equal(guide.url(), guideUrl);
      assert.equal(await guide.evaluate(() => window.opener), null);
      assert.deepEqual(guideRequests, [{ url: guideUrl, method: 'GET', body: null }]);
      assert.equal(page.url(), workspaceUrl);
      assert.equal(await input('ticket-source'), source);
      assert.equal(await input('ticket-prepared'), tokenized);
      assert.equal(await input('ticket-reply'), tokenized);
      assert.equal(await disabled('copy-ticket'), false);
      await guide.close();
      await click('restore-reply');
      assert.equal(await input('ticket-restored'), source, 'the original mapping must survive reading the guide');
      await click('copy-reply');
      assert.equal(await page.evaluate(() => window.__copied.at(-1)), source);
    } finally {
      if (guide && !guide.isClosed()) await guide.close();
      await context.unroute(guideUrl, serveGuide);
    }
  });

  await check('known tokens restore exactly and unknown tokens stay unchanged', async () => {
    const unknown = '[EMAIL_ADDRESS_00000000]';
    assert.ok(!tokenized.includes(unknown));
    await field('ticket-reply').fill(`${tokenized}\nUnknown: ${unknown}`);
    await click('restore-reply');
    assert.equal(await input('ticket-restored'), `${source}\nUnknown: ${unknown}`);
    const outcome = 'Restored 2 token occurrences with the current ticket mapping. Original sensitive values are visible. 1 unrecognized token-shaped placeholder left unchanged. Check that the reply uses this ticket’s unchanged tokens.';
    assert.equal(await field('ticket-status').textContent(), outcome);
    await click('copy-reply');
    assert.equal(await page.evaluate(() => window.__copied.at(-1)), `${source}\nUnknown: ${unknown}`);
    assert.equal(await field('ticket-status').textContent(), `Reply copied. ${outcome}`);
  });

  await check('restore status counts repeated known token occurrences', async () => {
    for (const [reply, expected, outcome] of [
      [
        oldToken,
        'avery@example.invalid',
        'Restored 1 token occurrence with the current ticket mapping. Original sensitive values are visible. Review the reply; changed or incomplete tokens may not be recognized.',
      ],
      [
        `${oldToken} / ${oldToken}`,
        'avery@example.invalid / avery@example.invalid',
        'Restored 2 token occurrences with the current ticket mapping. Original sensitive values are visible. Review the reply; changed or incomplete tokens may not be recognized.',
      ],
    ]) {
      await field('ticket-reply').fill(reply);
      await click('restore-reply');
      assert.equal(await input('ticket-restored'), expected);
      assert.equal(await field('ticket-status').textContent(), outcome);
      await click('copy-reply');
      assert.equal(await page.evaluate(() => window.__copied.at(-1)), expected);
      assert.equal(await field('ticket-status').textContent(), `Reply copied. ${outcome}`);
    }
  });

  await check('unknown-only replies report unchanged placeholder occurrences when restored and copied', async () => {
    const unknown = '[UNRECOGNIZED2_VALUE_deadbeef]';
    const reply = `${unknown} / ${unknown}`;
    const outcome = 'No token occurrences were restored. 2 unrecognized token-shaped placeholders left unchanged. Check that the reply uses this ticket’s unchanged tokens.';
    await field('ticket-reply').fill(reply);
    await click('restore-reply');
    assert.equal(await input('ticket-restored'), reply);
    assert.equal(await field('ticket-status').textContent(), outcome);
    await click('copy-reply');
    assert.equal(await page.evaluate(() => window.__copied.at(-1)), reply);
    assert.equal(await field('ticket-status').textContent(), `Reply copied. ${outcome}`);
  });

  await check('plain replies and malformed placeholders do not claim a restoration', async () => {
    const outcome = 'No token occurrences were restored. Review the reply; changed or incomplete tokens may not be recognized.';
    for (const reply of [
      'Please retry the upload.',
      '[email_address_deadbeef] [EMAIL_ADDRESS_DEADBEEF] [1EMAIL_deadbeef] [EMAIL-ADDRESS_deadbeef] [EMAIL_ADDRESS_deadbee] [EMAIL_ADDRESS_deadbeefx] EMAIL_ADDRESS_deadbeef [EMAIL_ADDRESS_deadbeef',
    ]) {
      await field('ticket-reply').fill(reply);
      await click('restore-reply');
      assert.equal(await input('ticket-restored'), reply);
      assert.equal(await field('ticket-status').textContent(), outcome);
      await click('copy-reply');
      assert.equal(await page.evaluate(() => window.__copied.at(-1)), reply);
      assert.equal(await field('ticket-status').textContent(), `Reply copied. ${outcome}`);
    }
  });

  await check('editing a reply invalidates the restored copy', async () => {
    await field('ticket-reply').fill('Changed reply');
    assert.equal(await input('ticket-restored'), '');
    assert.equal(await disabled('copy-reply'), true);
  });

  await check('source edits immediately invalidate all downstream state', async () => {
    await field('ticket-source').fill('Please email blair@example.invalid.');
    for (const id of ['ticket-prepared', 'ticket-reply', 'ticket-restored']) assert.equal(await input(id), '');
    for (const id of ['copy-ticket', 'ticket-reply', 'restore-reply', 'copy-reply']) assert.equal(await disabled(id), true);
    assert.match(await field('ticket-status').textContent(), /previous session and reply were cleared/);
    await click('prepare-ticket');
    await field('ticket-reply').fill(oldToken);
    await click('restore-reply');
    assert.equal(await input('ticket-restored'), oldToken, 'old ticket mapping must not survive');
    assert.equal(
      await field('ticket-status').textContent(),
      'No token occurrences were restored. 1 unrecognized token-shaped placeholder left unchanged. Check that the reply uses this ticket’s unchanged tokens.',
    );
  });

  await check('preparing again starts a new mapping and clears the previous reply', async () => {
    const previous = await input('ticket-prepared');
    await click('prepare-ticket');
    assert.notEqual(await input('ticket-prepared'), previous);
    assert.equal(await input('ticket-reply'), '');
    assert.equal(await input('ticket-restored'), '');
    assert.equal(await disabled('copy-reply'), true);
    await field('ticket-reply').fill(previous);
    await click('restore-reply');
    assert.equal(await input('ticket-restored'), previous);
  });

  await check('clipboard rejection selects the correct text for manual copying', async () => {
    await page.evaluate(() => { window.__clipboardReject = true; });
    const expected = await input('ticket-prepared');
    await click('copy-ticket');
    await page.waitForFunction(() => document.getElementById('ticket-status').textContent.includes('Clipboard access was unavailable'));
    const selection = await field('ticket-prepared').evaluate(element => ({
      text: element.value.slice(element.selectionStart, element.selectionEnd),
      focused: document.activeElement === element,
    }));
    assert.deepEqual(selection, { text: expected, focused: true });
    assert.equal(await field('copy-ticket-feedback').textContent(), 'Text selected for manual copy');
    await page.evaluate(() => { window.__clipboardReject = false; });
  });

  await check('reply clipboard fallback preserves the restoration outcome and selected output', async () => {
    const known = (await input('ticket-prepared')).match(/\[EMAIL_ADDRESS_[a-f0-9]{8}\]/)[0];
    const unknown = '[UNRECOGNIZED2_VALUE_deadbeef]';
    const expected = `blair@example.invalid / blair@example.invalid / ${unknown}`;
    const outcome = 'Restored 2 token occurrences with the current ticket mapping. Original sensitive values are visible. 1 unrecognized token-shaped placeholder left unchanged. Check that the reply uses this ticket’s unchanged tokens.';
    await field('ticket-reply').fill(`${known} / ${known} / ${unknown}`);
    await click('restore-reply');
    assert.equal(await field('ticket-status').textContent(), outcome);
    await page.evaluate(() => { window.__clipboardReject = true; });
    await click('copy-reply');
    await page.waitForFunction(() => document.getElementById('ticket-status').textContent.includes('Clipboard access was unavailable'));
    assert.equal(
      await field('ticket-status').textContent(),
      `Clipboard access was unavailable. The text is selected; use your browser’s Copy command or Ctrl+C / ⌘C. ${outcome}`,
    );
    const selection = await field('ticket-restored').evaluate(element => ({
      text: element.value.slice(element.selectionStart, element.selectionEnd),
      focused: document.activeElement === element,
    }));
    assert.deepEqual(selection, { text: expected, focused: true });
    await page.evaluate(() => { window.__clipboardReject = false; });
  });

  await check('HTML-looking source and reply are literal text, never active markup', async () => {
    const literal = '<img src=x onerror="window.__injected=true"> avery@example.invalid';
    await field('ticket-source').fill(literal);
    await click('prepare-ticket');
    await field('ticket-reply').fill(await input('ticket-prepared'));
    await click('restore-reply');
    assert.equal(await input('ticket-restored'), literal);
    assert.equal(await page.evaluate(() => window.__injected), undefined);
    assert.equal(await page.locator('#try img, #try script').count(), 0);
  });

  await check('WASM restore reports count input occurrences once and preserve the existing restore API', async () => {
    const result = await page.evaluate(async () => {
      const { Engine } = await import('/playground/pkg/anon_pii.js');
      const engine = new Engine();
      try {
        const email = 'ada@example.invalid';
        const emailToken = JSON.parse(engine.anonymize(email)).output;
        const unknown = '[UNRECOGNIZED2_VALUE_deadbeef]';
        // A password fixture can contain both a known token and an unknown
        // token-shaped literal. Restoring it must not scan that inserted text.
        const original = `password="${emailToken} ${unknown}"`;
        const secretToken = JSON.parse(engine.anonymize(original)).output;
        const malformed = '[email_deadbeef] [EMAIL_DEADBEEF] [1EMAIL_deadbeef] [EMAIL-ADDRESS_deadbeef] [EMAIL_deadbee] [EMAIL_deadbeefx] EMAIL_deadbeef [EMAIL_deadbeef';
        const cases = [
          ['known token', emailToken, email, 1, 0],
          ['repeated known token', `${emailToken} ${emailToken}`, `${email} ${email}`, 2, 0],
          ['mixed known and repeated unknown', `${emailToken} ${unknown} ${unknown}`, `${email} ${unknown} ${unknown}`, 1, 2],
          ['unknown-only input', `${unknown} ${unknown}`, `${unknown} ${unknown}`, 0, 2],
          ['single-letter entity placeholder', '[A_deadbeef]', '[A_deadbeef]', 0, 1],
          ['neutral plain text', 'Please retry the upload.', 'Please retry the upload.', 0, 0],
          ['malformed placeholders', malformed, malformed, 0, 0],
          ['token-shaped originals are not rescanned', secretToken, original, 1, 0],
          ['input unknown is counted separately from restored originals', `${secretToken} ${unknown}`, `${original} ${unknown}`, 1, 1],
        ];
        return {
          emailToken,
          secretToken,
          cases: cases.map(([label, text, expected, restored, unresolved]) => ({
            label,
            expected,
            restored,
            unresolved,
            report: JSON.parse(engine.restore_report(text)),
            legacy: engine.restore(text),
          })),
        };
      } finally {
        engine.free();
      }
    });
    assert.match(result.emailToken, /^\[EMAIL_ADDRESS_[a-f0-9]{8}\]$/);
    assert.match(result.secretToken, /^\[PASSWORD_[a-f0-9]{8}\]$/);
    for (const sample of result.cases) {
      assert.deepEqual(sample.report, {
        output: sample.expected,
        restored_count: sample.restored,
        unresolved_count: sample.unresolved,
      }, sample.label);
      assert.equal(sample.legacy, sample.expected, `${sample.label}: existing restore API must agree`);
    }
  });

  await check('no detections still shows a review warning and roundtrips unchanged', async () => {
    const plain = 'the upload failed, please retry';
    await field('ticket-source').fill(plain);
    await click('prepare-ticket');
    assert.equal(await input('ticket-prepared'), plain);
    assert.match(await field('ticket-status').textContent(), /No values were detected/);
    await field('ticket-reply').fill(plain);
    await click('restore-reply');
    assert.equal(await input('ticket-restored'), plain);
  });

  await check('clear session removes every field without pretending to clear the clipboard', async () => {
    await click('copy-reply');
    const clipboard = await page.evaluate(() => window.__copied.at(-1));
    await click('clear-session');
    for (const id of ['ticket-source', 'ticket-prepared', 'ticket-reply', 'ticket-restored']) assert.equal(await input(id), '');
    for (const id of ['prepare-ticket', 'copy-ticket', 'ticket-reply', 'restore-reply', 'copy-reply']) assert.equal(await disabled(id), true);
    assert.equal(await page.evaluate(() => window.__copied.at(-1)), clipboard);
    assert.match(await field('ticket-status').textContent(), /clipboard or in other apps are unchanged/);
  });

  await check('French ticket names, address, email, and credentials roundtrip without an AI service', async () => {
    await click('load-example');
    const example = await input('ticket-source');
    assert.equal(example, readFileSync(resolve(docs, '../demo/samples/support-ticket-fr.txt'), 'utf8'));
    await click('prepare-ticket');
    const output = await input('ticket-prepared');
    let expectedOutput = example;
    for (const [type, original] of Object.entries({
      PERSON: 'Camille verneuil',
      FR_ADDRESS: '24 rue des Nuages 75016 ville-exemple',
      EMAIL_ADDRESS: 'camille.verneuil@example.invalid',
      AUTH_TOKEN: 'ZGVidWc6ZXhhbXBsZS1wYXNzd29yZA==',
    })) {
      assert.ok(!output.includes(original), `${type} original must not remain`);
      const token = output.match(new RegExp(`\\[${type}_[a-f0-9]{8}\\]`));
      assert.ok(token, `${type} token must be present`);
      expectedOutput = expectedOutput.replaceAll(original, token[0]);
    }
    assert.equal(output, expectedOutput, 'the four complete values should be replaced, with surrounding ticket text preserved');
    await field('ticket-reply').fill(output);
    await click('restore-reply');
    assert.equal(await input('ticket-restored'), example);
  });

  await check('lowercase IBANs prepare, copy, and restore without consuming ticket prose', async () => {
    // Public checksum examples, used as fictional ticket data.
    for (const [iban, type] of [
      ['gb82west12345698765432', 'IBAN_CODE'],
      ['gB82wEsT12345698765432', 'IBAN_CODE'],
      ['fr14 2004 1010 0505 0001 3m02 606', 'FR_IBAN'],
    ]) {
      const ticket = `IBAN ${iban} please investigate.`;
      await field('ticket-source').fill(ticket);
      await click('prepare-ticket');
      const prepared = await input('ticket-prepared');
      const token = prepared.match(new RegExp(`\\[${type}_[a-f0-9]{8}\\]`));
      assert.ok(token, `${iban} must be detected`);
      assert.equal(prepared, `IBAN ${token[0]} please investigate.`);
      await click('copy-ticket');
      assert.equal(await page.evaluate(() => window.__copied.at(-1)), prepared);
      await field('ticket-reply').fill(prepared);
      await click('restore-reply');
      assert.equal(await input('ticket-restored'), ticket);
    }
    for (const ticket of [
      'IBAN gb82west12345698765433', // Invalid checksum.
      'ref gb82west12345698765432', // Generic IBAN still requires context.
    ]) {
      await field('ticket-source').fill(ticket);
      await click('prepare-ticket');
      assert.equal(await input('ticket-prepared'), ticket);
    }
  });

  await check('emails wrapped immediately after @ prepare, copy, and restore exact source text', async () => {
    // Textareas normalize CRLF to LF; native tests cover the CRLF source form.
    for (const email of [
      'ada@\nexample.invalid',
      'ada@\n  example.invalid',
      'iñes+case@\n \texample.invalid',
    ]) {
      const prefix = 'Échec 📨 — contact ';
      const suffix = '; please investigate.\nthis ticket remains open.';
      const ticket = `${prefix}${email}${suffix}`;
      await field('ticket-source').fill(ticket);
      await click('prepare-ticket');
      const prepared = await input('ticket-prepared');
      const token = prepared.match(/\[EMAIL_ADDRESS_[a-f0-9]{8}\]/);
      assert.ok(token, `wrapped email must be detected: ${JSON.stringify(email)}`);
      assert.equal(prepared, `${prefix}${token[0]}${suffix}`, 'replace the full wrapped email and preserve adjacent prose');
      await click('copy-ticket');
      assert.equal(await page.evaluate(() => window.__copied.at(-1)), prepared);
      await field('ticket-reply').fill(prepared);
      await click('restore-reply');
      assert.equal(await input('ticket-restored'), ticket, 'restore the exact Unicode, newline, and indentation');
      await click('copy-reply');
      assert.equal(await page.evaluate(() => window.__copied.at(-1)), ticket);
    }
  });

  await check('wrapped-email detection does not cross blank lines or unrelated prose', async () => {
    for (const ticket of [
      'ada@\n\nexample.invalid',
      'ada@\n \t\nexample.invalid',
      'ada@\nplease investigate example.invalid',
      'ada@ \nexample.invalid', // The newline must immediately follow @.
      'ada@\nexample\n.invalid', // Do not join an additional domain line.
    ]) {
      await field('ticket-source').fill(ticket);
      await click('prepare-ticket');
      assert.equal(await input('ticket-prepared'), ticket, `unrelated lines must stay unchanged: ${JSON.stringify(ticket)}`);
    }
  });

  await check('a following complete email takes priority over an ambiguous wrapped prefix', async () => {
    for (const prefix of ['ada@\n', 'ada@\nplease investigate ']) {
      const email = 'bob.smith@example.com';
      const ticket = `${prefix}${email}`;
      await field('ticket-source').fill(ticket);
      await click('prepare-ticket');
      const prepared = await input('ticket-prepared');
      const token = prepared.match(/\[EMAIL_ADDRESS_[a-f0-9]{8}\]/);
      assert.ok(token, 'the following complete email must still be detected');
      assert.equal(prepared, `${prefix}${token[0]}`, 'preserve the incomplete prefix and tokenize only the complete email');
      await click('copy-ticket');
      assert.equal(await page.evaluate(() => window.__copied.at(-1)), prepared);
      await field('ticket-reply').fill(prepared);
      await click('restore-reply');
      assert.equal(await input('ticket-restored'), ticket);
    }
  });

  await check('reload clears the ticket and all session state', async () => {
    await page.reload({ waitUntil: 'networkidle' });
    await page.waitForFunction(() => document.getElementById('engstats').textContent.includes('Local engine ready'));
    for (const id of ['ticket-source', 'ticket-prepared', 'ticket-reply', 'ticket-restored']) assert.equal(await input(id), '');
    assert.equal(await disabled('copy-ticket'), true);
    assert.equal(await disabled('restore-reply'), true);
  });

  await check('workspace never sends ticket contents or creates browser storage', async () => {
    assert.ok(requests.every(request => request.method === 'GET' && request.body === null));
    assert.ok(requests.every(request => new URL(request.url).origin === origin));
    assert.ok(requests.every(request => !request.url.includes('example.invalid')));
    assert.deepEqual(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })), { local: 0, session: 0 });
    assert.deepEqual(errors, []);
  });

  await check('the page fits narrow and wide viewports without horizontal overflow', async () => {
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `viewport ${width}`);
    }
  });

  await check('loading and failed engine states prevent preparation', async () => {
    const failedPage = await context.newPage();
    let releaseWasm;
    const held = new Promise(resolve => { releaseWasm = resolve; });
    await failedPage.route('**/anon_pii_bg.wasm', async route => {
      await held;
      await route.abort();
    });
    await failedPage.goto(origin, { waitUntil: 'domcontentloaded' });
    await failedPage.locator('#ticket-source').fill(source);
    assert.equal(await failedPage.locator('#prepare-ticket').isDisabled(), true);
    assert.match(await failedPage.locator('#engstats').textContent(), /Loading/);
    releaseWasm();
    await failedPage.waitForFunction(() => document.getElementById('engstats').textContent.includes('failed to load'));
    assert.equal(await failedPage.locator('#prepare-ticket').isDisabled(), true);
    assert.equal(await failedPage.locator('#copy-ticket').isDisabled(), true);
    assert.equal(await failedPage.locator('#ticket-source').inputValue(), source, 'load failure must not discard the unprepared source');
    await failedPage.close();
  });

  await context.close();
  console.log(`Passed ${checks} support-ticket workspace checks against the real WASM engine.`);
} finally {
  if (browser) await browser.close();
  await new Promise(resolve => server.close(resolve));
}
