import { chromium } from 'playwright';
const browser = await chromium.connectOverCDP('http://localhost:9222');
const page = browser.contexts()[0].pages()[0];
console.log('url:', page.url());
console.log('title:', await page.title());
await page.waitForTimeout(2000);

const state = await page.evaluate(() => {
  const bodyText = (document.body.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 2000);
  const headings = Array.from(document.querySelectorAll('h1,h2,h3')).map(h => (h.textContent||'').trim());
  const buttons = Array.from(document.querySelectorAll('button')).map(b => ({
    text: (b.textContent || '').trim().slice(0, 80),
    disabled: b.disabled,
    type: b.type,
  })).filter(b => b.text);
  const inputs = Array.from(document.querySelectorAll('input')).map(i => ({
    type: i.type, name: i.name, id: i.id, placeholder: i.placeholder, autocomplete: i.autocomplete,
  }));
  const links = Array.from(document.querySelectorAll('a')).slice(0, 10).map(a => ({
    text: (a.textContent||'').trim().slice(0, 60), href: (a.href||'').slice(0, 80),
  }));
  return { bodyText, headings, buttons, inputs, links };
});
console.log(JSON.stringify(state, null, 2));
process.exit(0);
