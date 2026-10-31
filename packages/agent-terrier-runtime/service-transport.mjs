import { spawn } from 'node:child_process';
import http from 'node:http';
import http2 from 'node:http2';
import { Duplex } from 'node:stream';
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';

const MAX_SERVICES = 12;
const MAX_REQUEST_BYTES = 1024 * 1024;
const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;
const MAX_STREAMS = 16;
const REQUEST_TIMEOUT_MS = 60_000;
const SERVICE_HEADER = 'x-terrier-local-service';
const CLIENT_PATH = 'packages/agent-terrier-runtime/service-transport.mjs';
const HOP_HEADERS = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', SERVICE_HEADER]);

function serviceNames(values) {
  if (!Array.isArray(values) || values.length === 0 || values.length > MAX_SERVICES
      || new Set(values).size !== values.length || values.some((name) => !/^[a-z][a-z0-9-]{0,31}$/.test(name))) {
    throw new Error('Invalid local service names');
  }
  return values;
}

export function validateTargets(values) {
  if (!values || typeof values !== 'object' || Array.isArray(values)) throw new Error('Invalid service targets');
  const targets = new Map();
  for (const name of serviceNames(Object.keys(values))) {
    const target = new URL(values[name]);
    if (target.protocol !== 'http:' || !['127.0.0.1', '[::1]', 'localhost'].includes(target.hostname)
        || target.username || target.password || target.search || target.hash) {
      throw new Error('Service targets must be explicit local HTTP endpoints without embedded credentials');
    }
    targets.set(name, target);
  }
  return targets;
}

function headersWithoutHopFields(headers) {
  const nominated = new Set(String(headers.connection ?? '').split(',').map((name) => name.trim().toLowerCase()));
  return Object.fromEntries(Object.entries(headers).filter(([name]) => !name.startsWith(':')
    && !HOP_HEADERS.has(name.toLowerCase()) && !nominated.has(name.toLowerCase())));
}

function refuse(response, status) {
  if (response.writableEnded || response.destroyed) return;
  if (response.headersSent) { response.destroy(); return; }
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify({ error: 'local_service_transport_refused' }));
}

export function createTransportServer(values) {
  const targets = validateTargets(values);
  const server = http2.createServer({ settings: { maxConcurrentStreams: MAX_STREAMS, maxHeaderListSize: 16 * 1024 } });
  const sessions = new Set();
  server.on('session', (session) => {
    sessions.add(session);
    session.on('close', () => sessions.delete(session));
    session.on('error', () => session.destroy());
  });
  server.on('request', (request, response) => {
    const base = targets.get(request.headers[SERVICE_HEADER]);
    if (!base) { refuse(response, 403); return; }
    if (!['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(request.method)) {
      refuse(response, 405); return;
    }
    if (!request.url.startsWith('/') || request.url.startsWith('//') || request.url.includes('\\')) {
      refuse(response, 400); return;
    }
    const prefix = base.pathname.replace(/\/$/, '');
    const destination = new URL(base.origin + request.url);
    if (destination.origin !== base.origin || (prefix && !destination.pathname.startsWith(prefix + '/'))) {
      refuse(response, 400); return;
    }
    if (Number(request.headers['content-length'] ?? 0) > MAX_REQUEST_BYTES) {
      refuse(response, 413); return;
    }
    const upstream = http.request(destination, { method: request.method,
      headers: headersWithoutHopFields(request.headers) });
    const deadline = setTimeout(() => upstream.destroy(), REQUEST_TIMEOUT_MS);
    let requestBytes = 0;
    request.on('data', (chunk) => {
      requestBytes += chunk.length;
      if (requestBytes > MAX_REQUEST_BYTES) { refuse(response, 413); upstream.destroy(); request.unpipe(upstream); }
    });
    request.on('error', () => upstream.destroy());
    response.on('close', () => { clearTimeout(deadline); upstream.destroy(); });
    upstream.on('error', () => { if (!response.writableEnded) refuse(response, 502); });
    upstream.on('response', (received) => {
      if (received.statusCode >= 300 && received.statusCode < 400) {
        refuse(response, 502); received.destroy(); return;
      }
      let responseBytes = 0;
      response.writeHead(received.statusCode, headersWithoutHopFields(received.headers));
      received.on('data', (chunk) => {
        responseBytes += chunk.length;
        if (responseBytes > MAX_RESPONSE_BYTES) { received.destroy(); response.destroy(); }
      });
      received.on('error', () => response.destroy());
      received.pipe(response);
    });
    request.pipe(upstream);
  });
  return { attach(stream) { server.emit('connection', stream); }, close() {
    for (const session of sessions) session.destroy();
    server.close();
  } };
}

async function startClient(names) {
  serviceNames(names);
  const stream = Duplex.from({ readable: process.stdin, writable: process.stdout });
  const session = http2.connect('http://localhost', { createConnection: () => stream });
  const listeners = [];
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    for (const listener of listeners) { listener.close(); listener.closeAllConnections(); }
    session.destroy();
    process.stdin.destroy();
  };
  session.on('error', stop);
  session.on('close', stop);
  process.stdin.on('end', stop);
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
  const ports = {};
  for (const name of serviceNames(names)) {
    const listener = http.createServer({ maxHeaderSize: 16 * 1024 }, (request, response) => {
      if (session.destroyed || !request.url.startsWith('/') || request.url.startsWith('//')) {
        refuse(response, 503); return;
      }
      const forwarded = session.request({ ...headersWithoutHopFields(request.headers), ':method': request.method,
        ':path': request.url, [SERVICE_HEADER]: name });
      forwarded.on('response', (headers) => {
        if (response.writableEnded || response.destroyed) { forwarded.close(); return; }
        response.writeHead(headers[':status'], headersWithoutHopFields(headers));
        forwarded.pipe(response);
      });
      forwarded.on('error', () => { if (!response.writableEnded) refuse(response, 502); });
      response.on('close', () => forwarded.close());
      request.on('error', () => forwarded.close());
      request.pipe(forwarded);
    });
    listeners.push(listener);
    listener.requestTimeout = REQUEST_TIMEOUT_MS;
    await new Promise((resolve, reject) => {
      listener.once('error', reject);
      listener.listen(0, '127.0.0.1', resolve);
    });
    ports[name] = listener.address().port;
  }
  process.stderr.write(JSON.stringify({ protocol: 1, ports }) + '\n');
}

async function startHost(values) {
  const targets = JSON.parse(values.targets);
  const services = [...validateTargets(targets).keys()];
  if (!values.socket?.startsWith('/') || !/^[a-f0-9]{64}$/.test(values.container ?? '')) {
    throw new Error('An absolute local Docker socket and full container identity are required');
  }
  const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => ['PATH', 'HOME', 'TMPDIR', 'DOCKER_CONFIG'].includes(name)));
  const child = spawn('docker', ['--host', `unix://${values.socket}`, 'exec', '--interactive', values.container,
    'node', CLIENT_PATH, 'client', '--services', JSON.stringify(services)], { env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
  const transport = createTransportServer(targets);
  transport.attach(Duplex.from({ readable: child.stdout, writable: child.stdin }));
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    transport.close();
    child.stdin.end();
    child.kill('SIGTERM');
    process.stdin.destroy();
  };
  child.on('error', stop);
  child.on('exit', (code) => { if (!stopping && code !== 0) process.exitCode = 1; stop(); });
  process.stdin.resume();
  process.stdin.on('end', stop);
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
  const ready = await new Promise((resolve, reject) => {
    let buffered = '';
    const timeout = setTimeout(() => { stop(); reject(new Error('Transport startup timeout')); }, 10_000);
    child.once('exit', () => { clearTimeout(timeout); reject(new Error('Transport startup failed')); });
    child.stderr.on('data', (chunk) => {
      buffered += chunk;
      if (buffered.length > 4096) { clearTimeout(timeout); stop(); reject(new Error('Invalid transport readiness')); return; }
      if (!buffered.includes('\n')) return;
      try {
        const message = JSON.parse(buffered.trim());
        if (message.protocol !== 1 || Object.keys(message.ports).sort().join() !== services.sort().join()
            || Object.values(message.ports).some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) {
          throw new Error('Invalid transport readiness');
        }
        clearTimeout(timeout); resolve(message);
      } catch (error) { clearTimeout(timeout); stop(); reject(error); }
    });
  });
  const endpoints = Object.fromEntries(Object.entries(ready.ports).map(([name, port]) => {
    const endpoint = new URL(targets[name]);
    endpoint.hostname = '127.0.0.1';
    endpoint.port = String(port);
    return [name, endpoint.toString()];
  }));
  process.stdout.write(JSON.stringify({ protocol: 1, endpoints }) + '\n');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: {
    services: { type: 'string' }, targets: { type: 'string' }, socket: { type: 'string' }, container: { type: 'string' },
  } });
  const operation = positionals[0] === 'client' ? startClient(JSON.parse(values.services))
    : positionals[0] === 'host' ? startHost(values) : Promise.reject(new Error('Invalid transport mode'));
  operation.catch(() => { process.stderr.write('Local service transport failed.\n'); process.exitCode = 1; });
}
