import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import type { Page } from "playwright";

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), "pages");

function readFixture(filename: string): string {
  return readFileSync(join(fixtureDir, filename), "utf-8");
}

const routeMap: Record<string, string> = {
  "/": "signup.html",
  "/auth": "signup.html",
  "/signup": "signup.html",
  "/verify": "verify.html",
  "/dashboard": "dashboard.html",
  "/keys": "keys.html",
};

export async function setupMockSite(page: Page, baseUrl: string): Promise<void> {
  await page.route(`${baseUrl}/**`, (route) => {
    const url = new URL(route.request().url());
    const fixtureName = routeMap[url.pathname] ?? routeMap["/"];
    const body = readFixture(fixtureName);
    route.fulfill({
      status: 200,
      contentType: "text/html",
      body,
    });
  });
}

export function makePhantomMockSite(phantomKey: string) {
  return async (page: Page, baseUrl: string): Promise<void> => {
    const keysHtml = `<!DOCTYPE html>
<html>
<head><title>API Keys</title></head>
<body>
  <h1>API Keys</h1>
  <button id="create-key-btn">Create Key</button>
  <div id="key-container" style="display:none;">
    <span data-testid="new-api-key">${phantomKey}</span>
  </div>
  <script>
    document.getElementById('create-key-btn').addEventListener('click', function() {
      document.getElementById('key-container').style.display = 'block';
    });
  </script>
</body>
</html>`;

    await page.route(`${baseUrl}/**`, (route) => {
      const url = new URL(route.request().url());
      if (url.pathname === "/keys") {
        route.fulfill({ status: 200, contentType: "text/html", body: keysHtml });
      } else {
        const fixtureName = routeMap[url.pathname] ?? routeMap["/"];
        const body = readFixture(fixtureName);
        route.fulfill({ status: 200, contentType: "text/html", body });
      }
    });
  };
}
