export function HostedConsolePreview() {
  return (
    <main className="hosted-console-preview">
      <section className="onboard-card" aria-labelledby="hosted-console-title">
        <p className="hosted-console-label">agentKeys · hosted console preview</p>
        <h1 id="hosted-console-title">Browser sign-in is not available yet.</h1>
        <p>
          This preview does not create an account, verify an email address, or connect a passkey.
        </p>
        <p>
          Account access and agent management will become available in a later update.
        </p>
      </section>
    </main>
  );
}
