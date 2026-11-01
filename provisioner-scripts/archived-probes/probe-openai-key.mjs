import { chromium } from 'playwright';
const browser = await chromium.connectOverCDP('http://localhost:9222');
const page = browser.contexts()[0].pages()[0];
console.log('url:', page.url());

const keys = await page.evaluate(() => {
  const out = [];
  // Codes
  document.querySelectorAll('code, pre').forEach(el => {
    const txt = (el.textContent || '').trim();
    if (txt.startsWith('sk-')) out.push({tag: el.tagName, text: txt.slice(0, 60)});
  });
  // Inputs
  document.querySelectorAll('input, textarea').forEach(el => {
    const v = el.value || '';
    if (v.startsWith('sk-')) out.push({tag: el.tagName, type: el.type, value: v.slice(0, 60)});
  });
  // Any span/div with sk-
  document.querySelectorAll('span,div,p,output').forEach(el => {
    const txt = (el.textContent || '').trim();
    if (/^sk-[A-Za-z0-9_-]{40,}$/.test(txt)) out.push({tag: el.tagName, text: txt.slice(0, 60)});
  });
  return out;
});
console.log('key elements:', JSON.stringify(keys, null, 2));
process.exit(0);
