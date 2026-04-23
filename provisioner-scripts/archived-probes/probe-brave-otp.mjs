import { chromium } from 'playwright';
const browser = await chromium.connectOverCDP('http://localhost:9222');
const ctx = browser.contexts()[0];
const page = ctx.pages()[0];

// Assume already on /verify-otp from a prior run
console.log('URL:', page.url());
if (!page.url().includes('/verify-otp')) {
  console.log('not on verify-otp, exiting');
  process.exit(0);
}

const inspect = async (label) => {
  const out = await page.evaluate(() => {
    const inp = document.getElementById('otp');
    const btn = document.querySelector('button.btn.btn--filled.btn--large');
    return { value: inp?.value, disabled: btn?.disabled, btnText: (btn?.textContent||'').trim() };
  });
  console.log(label, JSON.stringify(out));
};

await inspect('initial');

console.log('=== attempt 1: pressSequentially ===');
await page.click('#otp');
await page.locator('#otp').pressSequentially('111111', { delay: 80 });
await inspect('after pressSequentially');

await page.waitForTimeout(500);
await inspect('after 500ms');

console.log('=== attempt 2: clear, use humanType-style ===');
await page.fill('#otp', '');
await page.locator('#otp').focus();
await page.keyboard.type('222222', { delay: 80 });
await inspect('after keyboard.type');

await page.waitForTimeout(500);
await inspect('after 500ms');

console.log('=== attempt 3: clear, use fill + dispatch input ===');
await page.fill('#otp', '');
await page.fill('#otp', '333333');
await page.locator('#otp').dispatchEvent('input');
await inspect('after fill+dispatch');

process.exit(0);
