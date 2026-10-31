#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { mkdir, lstat, readFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import path from 'node:path';
import { Context } from '@deepseek-ai/cordis';
import AgentRegistry from '@deepseek-ai/dsh-agent';
import AgentLoop from '@deepseek-ai/dsh-agent-loop';
import WebServer from '@deepseek-ai/dsh-host-webserver';
import LlmRuntime from '@deepseek-ai/dsh-llm';
import * as ModelAdapter from '@deepseek-ai/dsh-llm-deepseek';
import SessionStore from '@deepseek-ai/dsh-session';
import SessionPersistence from '@deepseek-ai/dsh-session-persistence-jsonl';
import SystemPrompt from '@deepseek-ai/dsh-system-prompt';
import ToolRuntime from '@deepseek-ai/dsh-tools';
import Credentials from '@agentkeys/dsh-suite/credentials';
import * as Actions from '@agentkeys/dsh-suite/actions';
import * as Guard from '@agentkeys/dsh-suite/guard';
import * as Presets from '@agentkeys/dsh-suite/presets';
import * as Sessions from '@agentkeys/dsh-suite/sessions';
import * as Bridge from '@agentkeys/dsh-suite/bridge';
import { DEFAULT_GRANTS_URL } from '@agentkeys/dsh-suite/grants';
import { API_KEY, BASE_URL, MODEL_ID } from '@agentkeys/dsh-suite/runtime-config';

const MAX_REPLY_TOKENS = 1024;

class ConfigurationError extends Error {}

function required(name) {
  const value = process.env[name];
  if (!value || /[\s\x00-\x1f\x7f]/.test(value)) throw new ConfigurationError(`Missing or invalid ${name}`);
  return value;
}

async function privateDirectory(directory) {
  if (!path.isAbsolute(directory) || path.resolve(directory) !== directory || directory === '/') {
    throw new ConfigurationError('Runtime directories must use canonical absolute paths');
  }
  let ancestor = path.parse(directory).root;
  for (const segment of directory.split(path.sep).filter(Boolean)) {
    ancestor = path.join(ancestor, segment);
    let metadata;
    try {
      metadata = await lstat(ancestor);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await mkdir(ancestor, { mode: 0o700 });
      metadata = await lstat(ancestor);
    }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new ConfigurationError('Runtime directory paths must not contain links or non-directories');
    }
    if (ancestor === directory && ((metadata.mode & 0o077) || metadata.uid !== process.getuid())) {
      throw new ConfigurationError('Runtime directories must be private and owned by the current user');
    }
  }
}

function localEndpoint(value) {
  let endpoint;
  try { endpoint = new URL(value); } catch { throw new ConfigurationError('Invalid local endpoint'); }
  if (endpoint.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]', 'host.docker.internal'].includes(endpoint.hostname)
      || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new ConfigurationError('Runtime endpoints must use local HTTP without embedded credentials');
  }
  return endpoint;
}

async function main() {
  process.umask(0o077);
  const { values } = parseArgs({ options: {
    'state-dir': { type: 'string' },
    'work-dir': { type: 'string' },
    port: { type: 'string' },
    'daemon-url': { type: 'string' },
  } });
  if (!values['state-dir'] || !values['work-dir'] || !values.port || !values['daemon-url']) {
    throw new ConfigurationError('Set --state-dir, --work-dir, --port and --daemon-url');
  }
  const port = Number(values.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new ConfigurationError('Invalid runtime port');
  const baseURL = localEndpoint(required(BASE_URL));
  const daemonURL = localEndpoint(values['daemon-url']);
  if (daemonURL.pathname !== '/') {
    throw new ConfigurationError('The daemon endpoint must be an origin without a path');
  }
  required(API_KEY);
  const model = required(MODEL_ID);
  const bridgeToken = required('AGENTKEYS_BRIDGE_TOKEN');
  const recipe = JSON.parse(await readFile(new URL('../../presets/local-models.json', import.meta.url), 'utf8'));
  await privateDirectory(values['state-dir']);
  await privateDirectory(values['work-dir']);
  process.env.DSH_HOME = values['state-dir'];
  const context = new Context();
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    await context.fiber.dispose();
    process.exit(0);
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  try {
    await context.plugin(LlmRuntime);
    await context.plugin(SessionStore);
    await context.plugin(SessionPersistence, { root: path.join(values['state-dir'], 'sessions'), compression: 'none' });
    await context.plugin(SystemPrompt, {});
    await context.plugin(ToolRuntime, {});
    await context.plugin(AgentRegistry);
    await context.plugin(Credentials, {});
    await context.plugin(ModelAdapter, {
      baseURL: baseURL.toString(), apiKeyEnv: API_KEY,
      thinking: 'disabled', reasoningEffort: 'off', maxTokens: MAX_REPLY_TOKENS,
      defaultContextWindow: recipe.runtime.context_length,
      models: [{ id: model, contextWindow: recipe.runtime.context_length }],
    });
    const grantsUrl = new URL(new URL(DEFAULT_GRANTS_URL).pathname, daemonURL).toString();
    await context.plugin(Guard, { bridgeToken, grantsUrl });
    await context.plugin(Presets, { bridgeToken, grantsUrl });
    await context.plugin(Actions, { bridgeToken, daemonUrl: daemonURL.toString() });
    await context.plugin(AgentLoop, { agents: [] });
    await context.plugin(Sessions, { homeDir: values['state-dir'] });
    await context.plugin(WebServer, { host: '127.0.0.1', port });
    await context.plugin(Bridge, {
      cwd: values['work-dir'], homeDir: values['state-dir'], bridgeToken,
      engine: 'dsh', provider: 'deepseek-official', model,
    });
    const deadline = Date.now() + 10_000;
    while (true) {
      const health = await fetch(`http://127.0.0.1:${port}/healthz`, { signal: AbortSignal.timeout(1_000), redirect: 'error' });
      await health.body?.cancel();
      if (health.ok) break;
      if (Date.now() >= deadline) throw new Error('Agent initialization timeout');
      await delay(50);
    }
    process.stdout.write(JSON.stringify({ ready: true, host: '127.0.0.1', port }) + '\n');
  } catch (error) {
    await context.fiber.dispose();
    throw error;
  }
}

main().catch((error) => {
  process.stderr.write(error instanceof ConfigurationError ? `${error.message}\n`
    : 'Local agent runtime startup failed; check explicit configuration and dependencies.\n');
  process.exitCode = 1;
});
