export type VerifyResult =
  | { valid: true }
  | { valid: false; reason: "phantom" | "endpoint_down" | "rate_limited" };

interface ServiceConfig {
  url: string;
  method: string;
  authHeader: (key: string) => string;
}

const SERVICE_CONFIG: Record<string, ServiceConfig> = {
  openrouter: {
    url: "https://openrouter.ai/api/v1/models",
    method: "GET",
    authHeader: (key) => `Bearer ${key}`,
  },
};

export async function verify(opts: {
  service: string;
  key: string;
  fetchFn?: typeof fetch;
}): Promise<VerifyResult> {
  const config = SERVICE_CONFIG[opts.service];
  if (!config) {
    throw new Error(`unknown service: ${opts.service}`);
  }

  const fetchFn = opts.fetchFn ?? globalThis.fetch;
  const signal = AbortSignal.timeout(10_000);

  let response: Response;
  try {
    response = await fetchFn(config.url, {
      method: config.method,
      headers: { Authorization: config.authHeader(opts.key) },
      signal,
    });
  } catch {
    return { valid: false, reason: "endpoint_down" };
  }

  if (response.status === 200) {
    return { valid: true };
  }

  if (response.status === 401 || response.status === 403) {
    return { valid: false, reason: "phantom" };
  }

  if (response.status === 429) {
    return { valid: false, reason: "rate_limited" };
  }

  return { valid: false, reason: "endpoint_down" };
}
