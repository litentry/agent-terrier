import { createServer } from 'node:http';
import { readFile, realpath, stat } from 'node:fs/promises';
import { extname, resolve, sep } from 'node:path';
import { Readable } from 'node:stream';
import { pathToFileURL } from 'node:url';

const contentTypes = {
  '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css',
  '.html': 'text/html; charset=utf-8', '.json': 'application/json',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.webp': 'image/webp', '.ico': 'image/x-icon', '.woff2': 'font/woff2',
  '.wasm': 'application/wasm', '.webmanifest': 'application/manifest+json',
};

export function createWebServer({ clientDirectory, fetchHandler }) {
  return createServer(async (request, response) => {
    try {
      const requestUrl = new URL(request.url || '/', 'http://localhost');
      const pathname = decodeURIComponent(requestUrl.pathname);
      if (['GET', 'HEAD'].includes(request.method) && !pathname.endsWith('/')) {
        const root = await realpath(clientDirectory);
        const candidate = resolve(root, `.${pathname}`);
        const actual = await realpath(candidate).catch(() => null);
        if (actual?.startsWith(root + sep) && (await stat(actual)).isFile()) {
          response.writeHead(200, {
            'content-type': contentTypes[extname(actual)] || 'application/octet-stream',
            'x-content-type-options': 'nosniff',
          });
          response.end(request.method === 'HEAD' ? undefined : await readFile(actual));
          return;
        }
      }
      const method = request.method || 'GET';
      const hasBody = !['GET', 'HEAD'].includes(method);
      const headers = new Headers();
      for (const [name, value] of Object.entries(request.headers)) {
        for (const item of Array.isArray(value) ? value : [value]) {
          if (item !== undefined) headers.append(name, item);
        }
      }
      requestUrl.host = request.headers.host || 'localhost';
      const result = await fetchHandler(new Request(requestUrl, {
        method, headers,
        ...(hasBody ? { body: Readable.toWeb(request), duplex: 'half' } : {}),
      }));
      result.headers.forEach((value, name) => response.setHeader(name, value));
      const cookies = result.headers.getSetCookie();
      if (cookies.length) response.setHeader('set-cookie', cookies);
      response.writeHead(result.status);
      if (result.body && method !== 'HEAD') {
        Readable.fromWeb(result.body).on('error', () => response.destroy()).pipe(response);
      } else {
        response.end();
      }
    } catch {
      if (!response.headersSent) response.writeHead(500, { 'content-type': 'text/plain' });
      response.end('Request failed');
    }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const root = process.cwd();
  const { default: entry } = await import(pathToFileURL(resolve(root, 'dist/server/server.js')));
  const port = Number(process.env.PORT || 3119);
  const hostname = process.env.HOST || '127.0.0.1';
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
  createWebServer({
    clientDirectory: resolve(root, 'dist/client'),
    fetchHandler: (request) => entry.fetch(request),
  }).listen(port, hostname, () => console.log(`Browser display listening at http://${hostname}:${port}`));
}
