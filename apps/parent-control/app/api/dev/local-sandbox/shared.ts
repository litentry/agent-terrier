// #631 — shared config for the local dsh test-twin proxy routes. The bridge
// URL is a server-side env knob with the run-local.sh default; it never
// reaches the browser.
export function bridgeBase(): string {
  return process.env.AGENTKEYS_LOCAL_SANDBOX_BRIDGE_URL ?? 'http://127.0.0.1:18090';
}

// #715 — the bridge's chat route is fail-closed on the in-pod bearer; the
// twin arms `sbt1_local` by default (run-local.sh), overridable per env.
export function bridgeAuthHeaders(): Record<string, string> {
  const token = process.env.AGENTKEYS_LOCAL_SANDBOX_BRIDGE_TOKEN ?? 'sbt1_local';
  return token ? { authorization: `Bearer ${token}` } : {};
}

export function sandboxDownBody(): { ok: false; phase: 'down'; error: string } {
  return {
    ok: false,
    phase: 'down',
    error: 'local sandbox not running — start it with: bash docker/dsh-sandbox/run-local.sh',
  };
}
