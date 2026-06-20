import { chromium } from 'playwright';
const browser = await chromium.connectOverCDP('http://localhost:9222');
const ctx = browser.contexts()[0];
await ctx.clearCookies();
const page = ctx.pages()[0];
await page.goto('https://elevenlabs.io/app/sign-up', { waitUntil: 'networkidle', timeout: 30000 });
await page.waitForTimeout(2000);

// Dismiss cookie banner if present
const acceptBtn = page.locator('button#CybotCookiebotDialogBodyButtonAccept').first();
if (await acceptBtn.isVisible().catch(() => false)) {
  await acceptBtn.click({ force: true });
  console.log('cookie banner dismissed');
  await page.waitForTimeout(500);
}

const inspect = async (label) => {
  const data = await page.evaluate(() => {
    const inputs = Array.from(document.querySelectorAll('input[type="email"], input[type="password"], input[type="text"]:not([name="h-captcha-response"])'));
    const submit = document.querySelector('form button[type="submit"]');
    const taList = Array.from(document.querySelectorAll('textarea[name="h-captcha-response"]'));
    return {
      inputs: inputs.map(i => ({ name: i.name, type: i.type, value_len: i.value?.length ?? 0, placeholder: i.placeholder })),
      submit: submit ? { disabled: submit.disabled, text: (submit.textContent||'').trim().slice(0,40) } : null,
      captcha_textareas: taList.map(t => ({ id: t.id, value_len: t.value?.length ?? 0 })),
    };
  });
  console.log(label, JSON.stringify(data, null, 2));
};

console.log('=== initial state ===');
await inspect('0 - on page load');

// Fill email
const emails = await page.locator('input[type="email"]').all();
console.log('email inputs:', emails.length);
if (emails.length) {
  await emails[0].click();
  await emails[0].pressSequentially('bot-probe-test@bots.example.invalid', { delay: 60 });
}
await page.waitForTimeout(500);
await inspect('1 - after email');

// Fill password
const passwords = await page.locator('input[type="password"]').all();
console.log('password inputs:', passwords.length);
for (let i = 0; i < passwords.length; i++) {
  await passwords[i].click();
  await passwords[i].pressSequentially('Stg6-test-xYzQ9okFg', { delay: 50 });
}
await page.waitForTimeout(800);
await inspect('2 - after password(s)');

// wait 10s more to see if invisible captcha auto-executes
for (let i = 0; i < 5; i++) {
  await page.waitForTimeout(2000);
  await inspect(`3 - +${(i+1)*2}s`);
}

// Try clicking Sign up (even if disabled, playwright force:true will try)
console.log('=== attempting submit click (force) ===');
const submit = page.locator('form button[type="submit"]').first();
await submit.click({ force: true }).catch(e => console.log('click err:', e.message.split('\n')[0]));
await page.waitForTimeout(3000);
await inspect('4 - after force click');

// See if challenge appeared
const challengeVisible = await page.locator('iframe[src*="hcaptcha.com"][src*="frame=challenge"]').first().isVisible({timeout: 3000}).catch(() => false);
console.log('challenge iframe visible:', challengeVisible);

console.log('URL after all attempts:', page.url());
process.exit(0);
