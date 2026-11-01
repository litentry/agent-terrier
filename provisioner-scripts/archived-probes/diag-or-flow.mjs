// Full-flow Clerk signup probe for OpenRouter. Walks through every post-submit
// DOM state, capturing screenshots + HTML + candidate inventory after each
// user-initiated transition. Used to design the scraper's new selectors.
//
// Usage (from provisioner-scripts/):
//   node diag-or-flow.mjs
// Writes artifacts to /tmp/or-flow/.
import { chromium } from "playwright";
import { mkdir, writeFile } from "fs/promises";

const OUT = "/tmp/or-flow";
const EMAIL = process.env.AGENTKEYS_SIGNUP_EMAIL ?? process.env.AGENTKEYS_EMAIL_USER;
if (!EMAIL) { console.error("ERROR: AGENTKEYS_SIGNUP_EMAIL or AGENTKEYS_EMAIL_USER required"); process.exit(2); }

await mkdir(OUT, { recursive: true });

async function snap(page, label) {
  try {
    const url = page.url();
    const title = await page.title();
    const html = await page.content();
    await page.screenshot({ path: `${OUT}/${label}.png`, fullPage: true });
    await writeFile(`${OUT}/${label}.html`, html);
    const candidates = await page.$$eval(
      "input, button, a[role='button']",
      nodes => nodes.map(n => ({
        tag: n.tagName.toLowerCase(),
        type: n.getAttribute("type"),
        name: n.getAttribute("name"),
        id: n.id,
        placeholder: n.getAttribute("placeholder"),
        text: (n.innerText || n.value || "").slice(0, 80).replace(/\s+/g, " ").trim(),
        ariaLabel: n.getAttribute("aria-label"),
        dataLocalization: n.getAttribute("data-localization-key"),
      })).filter(c => c.id || c.name || c.placeholder || c.text || c.ariaLabel)
    );
    await writeFile(`${OUT}/${label}.candidates.json`, JSON.stringify(candidates, null, 2));
    console.log(`\n[${label}] url=${url} title="${title}"`);
    console.log(`  inputs:`, candidates.filter(c => c.tag === "input").map(c => `${c.id || c.name} (type=${c.type}, placeholder="${c.placeholder}")`));
    console.log(`  buttons:`, candidates.filter(c => c.tag === "button" || c.tag === "a").map(c => `"${c.text}" (id=${c.id}, data-loc=${c.dataLocalization})`));
  } catch (err) {
    console.log(`  snapshot ${label} FAILED: ${err.message}`);
  }
}

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
});
const page = await ctx.newPage();

try {
  console.log(`Probe email: ${EMAIL}`);

  // STATE 1: landing
  await page.goto("https://openrouter.ai/auth", { waitUntil: "networkidle", timeout: 30_000 });
  await snap(page, "01-landing");

  // STATE 2: fill all three fields (email + password + legal checkbox)
  await page.waitForSelector('#emailAddress-field', { timeout: 10_000 });
  await page.fill('#emailAddress-field', EMAIL);
  await page.fill('#password-field', `AgKe-${Date.now()}-Pw!9xZ`);
  // legal checkbox: click the label or the input. Checkbox inputs are often
  // display:none in Radix UI — clicking the label is the reliable path.
  try {
    await page.locator('label[for="legalAccepted-field"]').click();
  } catch {
    await page.check('#legalAccepted-field').catch(() => {});
  }
  await snap(page, "02-all-filled");

  // Click the form's primary button.
  await page.locator('button[data-localization-key="formButtonPrimary"]').first().click({ timeout: 5_000 });
  console.log("\nclicked formButtonPrimary");
  // Give Clerk time to transition. Use waitForLoadState + small fixed delay for the DOM to settle.
  await page.waitForLoadState("networkidle", { timeout: 15_000 }).catch(() => {});
  await page.waitForTimeout(2000);
  await snap(page, "03-after-submit");

  // STATE 3: enumerate inputs — should now be the OTP-entry step
  const step3Candidates = await page.$$eval("input", inputs =>
    inputs.map(i => ({
      id: i.id, name: i.getAttribute("name"), type: i.getAttribute("type"),
      placeholder: i.getAttribute("placeholder"), ariaLabel: i.getAttribute("aria-label"),
      inputMode: i.getAttribute("inputmode"),
      autocomplete: i.getAttribute("autocomplete"),
      maxlength: i.getAttribute("maxlength"),
    }))
  );
  console.log(`\nstep 3 all inputs:`, JSON.stringify(step3Candidates, null, 2));

  // Save localization keys + any text blocks that identify this step
  const headings = await page.$$eval("h1, h2, h3, p", els =>
    els.map(e => (e.innerText || "").trim()).filter(t => t && t.length < 200)
  );
  console.log(`\nstep 3 headings/paras:`, headings.slice(0, 10));

  // Error messages?
  const errors = await page.$$eval('[role="alert"], .cl-formFieldError, .cl-alertText, [data-localization-key*="error"]', els =>
    els.map(e => (e.innerText || "").trim()).filter(Boolean)
  );
  if (errors.length) console.log(`\nerrors visible:`, errors);

  console.log("\nDONE — inspect /tmp/or-flow/");
} catch (err) {
  console.error(`FATAL: ${err.message}`);
  await snap(page, "99-error").catch(() => {});
  process.exit(1);
} finally {
  await browser.close();
}
