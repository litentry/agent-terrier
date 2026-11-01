import { chromium } from 'playwright';
const browser = await chromium.connectOverCDP('http://localhost:9222');
const page = browser.contexts()[0].pages().find(p => p.url().includes('openai.com')) ?? browser.contexts()[0].pages()[0];
console.log('url:', page.url());
console.log('title:', await page.title());

const state = await page.evaluate(() => {
  const inputs = Array.from(document.querySelectorAll('input')).map(i => ({
    type: i.type, name: i.name, id: i.id, placeholder: i.placeholder, autocomplete: i.autocomplete, required: i.required, disabled: i.disabled,
  }));
  const buttons = Array.from(document.querySelectorAll('button')).map(b => ({
    text: (b.textContent || '').trim().slice(0, 80),
    type: b.type, disabled: b.disabled, class: b.className.slice(0, 60), ariaLabel: b.getAttribute('aria-label'),
  })).filter(b => b.text);
  const iframes = Array.from(document.querySelectorAll('iframe')).map(i => i.src.slice(0, 200));
  const captchaIndicators = {
    hcaptcha: !!document.querySelector('[class*="hcaptcha" i], iframe[src*="hcaptcha.com"]'),
    recaptcha: !!document.querySelector('[class*="recaptcha" i], iframe[src*="recaptcha"]'),
    turnstile: !!document.querySelector('iframe[src*="challenges.cloudflare.com"], input[name="cf-turnstile-response"]'),
  };
  const bodyText = document.body.textContent?.slice(0, 1500).replace(/\s+/g, ' ') ?? '';
  return { inputs, buttons, iframes, captchaIndicators, bodyText };
});
console.log(JSON.stringify(state, null, 2));
process.exit(0);
