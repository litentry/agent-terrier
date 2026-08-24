// #631 — shared config for the local dsh test-twin proxy routes. The bridge
// URL is a server-side env knob with the run-local.sh default; it never
// reaches the browser.
export function bridgeBase(): string {
  return process.env.AGENTKEYS_LOCAL_SANDBOX_BRIDGE_URL ?? 'http://127.0.0.1:18090';
}

export function sandboxDownBody(): { ok: false; phase: 'down'; error: string } {
  return {
    ok: false,
    phase: 'down',
    error: 'local sandbox not running — start it with: bash docker/dsh-sandbox/run-local.sh',
  };
}
