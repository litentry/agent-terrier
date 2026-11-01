import { chromium } from 'playwright';
const browser = await chromium.connectOverCDP('http://localhost:9222');
const ctx = browser.contexts()[0];
const page = ctx.pages()[0];
// Navigate to register page fresh
await page.goto('https://api-dashboard.search.brave.com/register', { waitUntil: 'networkidle', timeout: 15000 });
await page.waitForTimeout(1500);
const state = await page.evaluate(() => {
  const btn = document.getElementById('captcha-button');
  const sol = document.querySelector('input[name="captchaSolution"]');
  // Look at ALL scripts, not just with captcha in name
  const allScripts = Array.from(document.scripts).map(s => s.src).filter(Boolean);
  // Inspect the button's event handlers via getAttribute
  return {
    buttonText: btn ? (btn.textContent||'').trim() : null,
    buttonDisabled: btn ? btn.disabled : null,
    buttonClasses: btn ? btn.className.slice(0,100) : null,
    captchaSolutionValue: sol ? (sol.value ? `SET (len=${sol.value.length})` : 'EMPTY') : 'no input',
    // Check if there's a Web Worker reference
    hasWorker: typeof Worker !== 'undefined',
    // Scripts on the page
    scriptCount: allScripts.length,
    // Brave-specific script names (they probably include the PoW lib)
    braveScripts: allScripts.filter(s => /brave\.com|search-api|captcha/i.test(s)).slice(0, 10),
  };
});
console.log(JSON.stringify(state, null, 2));
process.exit(0);
