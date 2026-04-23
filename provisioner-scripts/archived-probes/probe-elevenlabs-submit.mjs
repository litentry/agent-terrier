import { chromium } from 'playwright';
const browser = await chromium.connectOverCDP('http://localhost:9222');
const ctx = browser.contexts()[0];
const page = ctx.pages()[0];

const inspect = async (label) => {
  const data = await page.evaluate(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    return {
      submitCandidates: btns
        .map(b => ({
          text: (b.textContent||'').trim().slice(0, 60),
          disabled: b.disabled,
          type: b.type,
          agent: b.getAttribute('data-agent-id'),
          hasSignup: /sign.?up|register|continue|create/i.test(b.textContent||''),
        }))
        .filter(b => b.hasSignup || b.text.length > 0 && b.text.length < 50),
      googleBtns: btns.filter(b => /google/i.test(b.textContent||'')).map(b=>({text:(b.textContent||'').trim().slice(0,40),disabled:b.disabled})),
    };
  });
  console.log(label, JSON.stringify(data, null, 2));
};

await inspect('initial');

// See if there's a Google sign-up button (not Sign up) or maybe the flow is different
// Check page title and main heading
const title = await page.evaluate(() => ({
  title: document.title,
  h1: Array.from(document.querySelectorAll('h1,h2')).map(h => h.textContent).slice(0,3),
  url: location.href,
}));
console.log('page:', JSON.stringify(title));

process.exit(0);
