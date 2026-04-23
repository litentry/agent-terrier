import { chromium } from 'playwright';
const browser = await chromium.connectOverCDP('http://localhost:9222');
const ctx = browser.contexts()[0];
const page = ctx.pages().find(p => p.url().includes('brave.com')) ?? ctx.pages()[0];
console.log('URL:', page.url());
const state = await page.evaluate(() => {
  const btn = document.getElementById('captcha-button');
  const sol = document.querySelector('input[name="captchaSolution"]');
  return {
    buttonText: btn ? (btn.textContent||'').trim().slice(0,50) : 'no captcha-button',
    buttonDisabled: btn ? btn.disabled : null,
    captchaSolutionValue: sol ? (sol.value ? `SET (len=${sol.value.length})` : 'EMPTY') : 'no captchaSolution input',
    // What captcha libs is the page loading?
    scriptSrcs: Array.from(document.scripts).map(s => s.src).filter(s => /captcha|challenge|verify|pow|turnstile|hcaptcha|friendly/i.test(s)).slice(0,10),
    // Any iframes?
    iframeSrcs: Array.from(document.querySelectorAll('iframe')).map(f => f.src).filter(Boolean).slice(0,10),
    // Network: captcha-related fetch endpoints if we inspect performance timing
    captchaPerf: performance.getEntriesByType('resource').filter(r => /captcha|challenge|verify|pow|friendly|mcaptcha|hcaptcha/i.test(r.name)).map(r => ({ name: r.name, duration: Math.round(r.duration) })).slice(0,10),
  };
});
console.log(JSON.stringify(state, null, 2));
process.exit(0);
