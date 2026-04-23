import { chromium } from 'playwright';
const browser = await chromium.connectOverCDP('http://localhost:9222');
const ctx = browser.contexts()[0];
await ctx.clearCookies();
const page = ctx.pages()[0];
await page.goto('https://api-dashboard.search.brave.com/register', { waitUntil: 'networkidle', timeout: 20000 });
await page.waitForTimeout(1500);

// Fill form minimally
const email = `bot-pow-${Date.now()}@bots.litentry.org`;
const pw = 'PowTest-' + Date.now();
await page.fill('#email', email);
await page.fill('#password', pw);
await page.fill('#passwordVerification', pw);
await page.fill('#name', 'AgentKeys PoW Test');
await page.fill('#company', 'Testing');
console.log('form filled, clicking Register...');

await page.click('#captcha-button');
const clickAt = Date.now();
console.log('clicked at', new Date(clickAt).toISOString());

// Poll every 2s for up to 3 minutes to see how the state evolves
for (let i = 0; i < 90; i++) {
  await page.waitForTimeout(2000);
  const elapsedS = Math.round((Date.now() - clickAt) / 1000);
  const state = await page.evaluate(() => {
    const btn = document.getElementById('captcha-button');
    const sol = document.querySelector('input[name="captchaSolution"]');
    return {
      url: location.href,
      btnText: btn ? (btn.textContent||'').trim() : 'gone',
      btnDisabled: btn ? btn.disabled : null,
      captchaSolution: sol ? (sol.value ? `SET(${sol.value.length})` : 'EMPTY') : 'gone',
      errors: Array.from(document.querySelectorAll('[role="alert"], [class*="error" i]')).filter(e => !!(e.offsetWidth||e.offsetHeight)).map(e => (e.textContent||'').trim().slice(0,150)).slice(0,3),
    };
  }).catch(() => ({error: 'page closed'}));
  console.log(`t=${elapsedS}s url=${state.url?.replace('https://api-dashboard.search.brave.com','')} btn=${JSON.stringify(state.btnText)} dis=${state.btnDisabled} sol=${state.captchaSolution} err=${JSON.stringify(state.errors||[])}`);
  if (state.url && !state.url.includes('/register')) {
    console.log('URL advanced!', state.url);
    break;
  }
  if (state.btnText && state.btnText !== 'Verifying' && state.btnText !== 'Register') {
    console.log('button text changed:', state.btnText);
    break;
  }
}
process.exit(0);
