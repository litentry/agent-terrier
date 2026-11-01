// Diagnostic: step through OpenRouter signup manually, saving a screenshot +
// HTML snapshot at each checkpoint. Captures where the real DOM diverges from
// the scraper's selectors.
//
// Usage (from repo root):
//   cd provisioner-scripts
//   node diag-openrouter.mjs
// Writes artifacts to /tmp/or-diag/ so we can inspect after the run.
import { chromium } from "playwright";
import { mkdir, writeFile } from "fs/promises";

const OUT = "/tmp/or-diag";
const EMAIL = process.env.AGENTKEYS_SIGNUP_EMAIL ?? process.env.AGENTKEYS_EMAIL_USER;
if (!EMAIL) {
  console.error("ERROR: set AGENTKEYS_SIGNUP_EMAIL or AGENTKEYS_EMAIL_USER");
  process.exit(2);
}

await mkdir(OUT, { recursive: true });

async function snap(page, label) {
  try {
    const url = page.url();
    const title = await page.title();
    const html = await page.content();
    await page.screenshot({ path: `${OUT}/${label}.png`, fullPage: true });
    await writeFile(`${OUT}/${label}.html`, html);
    await writeFile(`${OUT}/${label}.meta.txt`,
      `url: ${url}\ntitle: ${title}\nhtml_len: ${html.length}\n`);
    console.log(`  snapshot ${label}: url=${url} title="${title}"`);
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
  console.log(`Using signup email: ${EMAIL}`);
  console.log("1) goto https://openrouter.ai/auth");
  await page.goto("https://openrouter.ai/auth", { waitUntil: "networkidle", timeout: 30_000 });
  await snap(page, "01-landed");

  console.log("2) looking for any email-like input");
  // Broad probe — whatever the scraper's 'input[name="email"]' misses.
  const candidates = await page.$$eval(
    "input, button",
    nodes => nodes.map(n => ({
      tag: n.tagName.toLowerCase(),
      type: n.getAttribute("type"),
      name: n.getAttribute("name"),
      id: n.id,
      placeholder: n.getAttribute("placeholder"),
      text: (n.innerText || n.value || "").slice(0, 80),
      ariaLabel: n.getAttribute("aria-label"),
    }))
  );
  await writeFile(`${OUT}/02-candidates.json`, JSON.stringify(candidates, null, 2));
  console.log(`   wrote ${candidates.length} candidates to ${OUT}/02-candidates.json`);
  const emailLikely = candidates.filter(c =>
    c.tag === "input" && (
      c.type === "email" ||
      c.name?.includes("email") ||
      c.id?.includes("email") ||
      c.placeholder?.toLowerCase().includes("email") ||
      c.ariaLabel?.toLowerCase().includes("email")
    )
  );
  console.log(`   email-like inputs:`, emailLikely);

  console.log("3) looking for sign-in / sign-up CTA buttons");
  const buttons = candidates.filter(c =>
    c.tag === "button" && /sign|continue|next|submit|start/i.test(c.text || "")
  );
  console.log(`   sign-up-likely buttons:`, buttons);

  await snap(page, "02-inspected");

  // If there's an obvious email input + sign-up button, try submitting
  if (emailLikely.length > 0) {
    const e0 = emailLikely[0];
    const selector =
      e0.id ? `#${e0.id}` :
      e0.name ? `input[name="${e0.name}"]` :
      `input[type="${e0.type}"]`;
    console.log(`4) attempting fill on ${selector} with ${EMAIL}`);
    await page.fill(selector, EMAIL);
    await snap(page, "03-filled");

    // `buttons` is already the sign/continue/next/submit/start-filtered set.
    const submitBtn = buttons[0];
    if (submitBtn) {
      console.log(`5) clicking button: text="${submitBtn.text}"`);
      await page.getByRole("button", { name: new RegExp(submitBtn.text?.split("\n")[0] ?? "", "i") }).first().click();
      await page.waitForTimeout(3000);
      await snap(page, "04-after-submit");
    } else {
      console.log("5) no obvious submit button — skipped click");
    }
  }

  console.log("DONE — inspect artifacts under /tmp/or-diag/");
} catch (err) {
  console.error(`FATAL: ${err.message}`);
  await snap(page, "99-error").catch(() => {});
  process.exit(1);
} finally {
  await browser.close();
}
