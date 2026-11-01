// Probe: does OpenRouter's SIGN-IN (not sign-up) page have Turnstile?
// If sign-in is clean, we can pivot Stage 5a's strategy from "create new account"
// to "sign in to existing account and mint a new API key" — which is what the
// user actually wants anyway.
import { chromium } from "playwright";
import { mkdir, writeFile } from "fs/promises";

const OUT = "/tmp/or-signin";
await mkdir(OUT, { recursive: true });

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({
  userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  viewport: { width: 1280, height: 900 },
});
const page = await ctx.newPage();

try {
  // Try /sign-in directly
  await page.goto("https://openrouter.ai/sign-in", { waitUntil: "networkidle", timeout: 30_000 });
  await page.screenshot({ path: `${OUT}/signin.png`, fullPage: true });
  await writeFile(`${OUT}/signin.html`, await page.content());

  const inputs = await page.$$eval("input", ins => ins.map(i => ({
    id: i.id, name: i.getAttribute("name"), type: i.getAttribute("type"),
    placeholder: i.getAttribute("placeholder"),
  })));
  const buttons = await page.$$eval("button", bs => bs.map(b => ({
    text: (b.innerText || "").trim().slice(0, 40),
    disabled: b.disabled,
    dataLoc: b.getAttribute("data-localization-key"),
  })).filter(b => b.text || b.dataLoc));
  const headings = await page.$$eval("h1, h2, h3, p", els =>
    els.map(e => (e.innerText || "").trim()).filter(t => t && t.length < 150).slice(0, 15));

  const hasTurnstile = inputs.some(i => i.name === "cf-turnstile-response");

  console.log(`url: ${page.url()}`);
  console.log(`turnstile present on sign-in: ${hasTurnstile}`);
  console.log(`\nheadings:`);
  headings.forEach(h => console.log(`  ${h}`));
  console.log(`\ninputs:`);
  inputs.forEach(i => console.log(`  id=${i.id} name=${i.name} type=${i.type} placeholder="${i.placeholder}"`));
  console.log(`\nbuttons:`);
  buttons.forEach(b => console.log(`  text="${b.text}" disabled=${b.disabled} data-loc=${b.dataLoc}`));

  console.log("DONE");
} catch (err) {
  console.error(`FATAL: ${err.message}`);
  process.exit(1);
} finally {
  await browser.close();
}
