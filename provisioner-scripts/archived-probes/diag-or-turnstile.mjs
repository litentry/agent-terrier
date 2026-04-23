// Probe: after clicking Continue, poll for Turnstile to resolve and check if
// Clerk advances to the email-verification step. If Turnstile never resolves
// in headless, the scraper cannot proceed past signup without Stage 5b.
import { chromium } from "playwright";
import { mkdir, writeFile } from "fs/promises";

const OUT = "/tmp/or-turnstile";
const EMAIL = process.env.AGENTKEYS_SIGNUP_EMAIL ?? process.env.AGENTKEYS_EMAIL_USER;
if (!EMAIL) { console.error("ERROR: email env required"); process.exit(2); }
await mkdir(OUT, { recursive: true });

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  viewport: { width: 1280, height: 900 },
  locale: "en-US",
  timezoneId: "America/Los_Angeles",
});
const page = await ctx.newPage();

async function snap(label) {
  await page.screenshot({ path: `${OUT}/${label}.png`, fullPage: true });
  await writeFile(`${OUT}/${label}.html`, await page.content());
}

async function turnstileState() {
  return page.$$eval(
    'input[name="cf-turnstile-response"]',
    inputs => inputs.map(i => ({ id: i.id, value: i.value, hasValue: i.value && i.value.length > 0 }))
  );
}

async function formState() {
  const headings = await page.$$eval("h1, h2, h3, p", els =>
    els.map(e => (e.innerText || "").trim()).filter(t => t && t.length < 150).slice(0, 10));
  const buttons = await page.$$eval("button", btns =>
    btns.map(b => ({ text: (b.innerText || "").trim().slice(0, 40), disabled: b.disabled, dataLoc: b.getAttribute("data-localization-key") })).filter(b => b.text || b.dataLoc));
  const inputs = await page.$$eval("input", ins =>
    ins.map(i => ({ id: i.id, type: i.getAttribute("type"), name: i.getAttribute("name") })));
  const errors = await page.$$eval('[role="alert"], .cl-formFieldError, .cl-alertText', els =>
    els.map(e => (e.innerText || "").trim()).filter(Boolean));
  return { url: page.url(), headings, buttons, inputs, errors };
}

try {
  console.log(`email: ${EMAIL}`);
  await page.goto("https://openrouter.ai/auth", { waitUntil: "networkidle", timeout: 30_000 });

  await page.fill('#emailAddress-field', EMAIL);
  // Use realistic password (strong, varied)
  await page.fill('#password-field', `Stg5-${Date.now()}-xZq9!ok`);
  await page.locator('label[for="legalAccepted-field"]').click().catch(() => page.check('#legalAccepted-field'));

  await snap("01-filled");
  console.log("state before submit:");
  console.log(JSON.stringify(await turnstileState(), null, 2));

  await page.locator('button[data-localization-key="formButtonPrimary"]').first().click({ timeout: 5_000 });
  console.log("\nclicked Continue — polling Turnstile for 60s...");

  // Poll for up to 60s: watch Turnstile response value + form advance
  for (let s = 0; s < 60; s += 3) {
    await page.waitForTimeout(3000);
    const ts = await turnstileState();
    const fs = await formState();
    const hasTs = ts.some(t => t.hasValue);
    const submitted = !fs.url.includes("sign-up") || fs.headings.some(h => /verify|verification|code/i.test(h));
    console.log(`  t=${s+3}s: ts_solved=${hasTs} url=${fs.url.slice(0, 60)} headings=[${fs.headings.slice(0, 3).join(" | ")}] errors=[${fs.errors.slice(0, 2).join(" | ")}]`);
    if (submitted) {
      console.log("  → FORM ADVANCED");
      await snap(`advanced-at-${s+3}s`);
      console.log(JSON.stringify(fs, null, 2));
      break;
    }
    if (fs.errors.length && fs.errors.some(e => e && !/password meets/i.test(e))) {
      console.log("  → ERROR BRANCH");
      await snap(`error-at-${s+3}s`);
      console.log("errors:", fs.errors);
      break;
    }
  }
  await snap("99-final");
  console.log("\nfinal state:", JSON.stringify(await formState(), null, 2));
  console.log("final turnstile:", JSON.stringify(await turnstileState(), null, 2));
  console.log("DONE");
} catch (err) {
  console.error(`FATAL: ${err.message}`);
  await snap("99-error").catch(() => {});
  process.exit(1);
} finally {
  await browser.close();
}
