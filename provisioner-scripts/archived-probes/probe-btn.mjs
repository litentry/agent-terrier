import { chromium } from 'playwright';
const browser = await chromium.connectOverCDP('http://localhost:9222');
const page = browser.contexts()[0].pages()[0];
console.log('url:', page.url());

// Try the same filter approach the recorder uses
for (const [label, rx] of [
  ['exact', /^Create new secret key$/i],
  ['substring', /Create new secret key/i],
]) {
  const count = await page.locator('button').filter({ hasText: rx }).count();
  console.log(`${label} (hasText regex): ${count} matches`);
}

// Direct query
const raw = await page.evaluate(() => {
  const btns = Array.from(document.querySelectorAll('button'));
  return btns.map(b => ({
    text: b.textContent,
    innerHTML: b.innerHTML.slice(0, 200),
    visible: !!(b.offsetWidth || b.offsetHeight),
    disabled: b.disabled,
  })).filter(b => b.text && b.text.toLowerCase().includes('create'));
});
console.log('buttons with Create in innerText:', JSON.stringify(raw, null, 2));
process.exit(0);
