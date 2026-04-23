// Diagnostic: IMAP auth + folder scan for OpenRouter verification emails.
// Usage (from provisioner-scripts/): node diag-imap.mjs
// Requires AGENTKEYS_EMAIL_{USER,PASSWORD,HOST,PORT} exported.
import { ImapFlow } from "imapflow";

const user = process.env.AGENTKEYS_EMAIL_USER;
const pass = process.env.AGENTKEYS_EMAIL_PASSWORD;
const host = process.env.AGENTKEYS_EMAIL_HOST ?? "imap.gmail.com";
const port = parseInt(process.env.AGENTKEYS_EMAIL_PORT ?? "993", 10);

if (!user || !pass) {
  console.error("ERROR: AGENTKEYS_EMAIL_USER and AGENTKEYS_EMAIL_PASSWORD required");
  process.exit(2);
}

const client = new ImapFlow({
  host, port, secure: true,
  auth: { user, pass },
  logger: false,
});

try {
  console.log(`1) connecting as ${user}...`);
  await client.connect();
  console.log("   OK");

  console.log("2) listing mailboxes...");
  const listResult = await client.list();
  const mailboxes = listResult.map(b => b.path);
  console.log(`   found ${mailboxes.length} mailboxes: ${mailboxes.join(", ")}`);

  // Gmail key folders
  const candidates = ["INBOX", "[Gmail]/Spam", "[Gmail]/All Mail", "[Gmail]/Trash"];
  for (const box of candidates) {
    if (!mailboxes.includes(box)) continue;
    try {
      await client.mailboxOpen(box);
      const uids = await client.search({
        from: "noreply@openrouter.ai",
        since: new Date(Date.now() - 24 * 3600 * 1000), // last 24h
      });
      console.log(`3) [${box}] openrouter emails (last 24h): ${uids.length}`);
      // Show the most recent one's envelope
      if (uids.length > 0) {
        const msg = await client.fetchOne(uids[uids.length - 1], { envelope: true, source: false });
        if (msg) {
          console.log(`     most recent: from=${msg.envelope.from?.[0]?.address} subject="${msg.envelope.subject}" date=${msg.envelope.date}`);
          console.log(`     TO: ${JSON.stringify(msg.envelope.to?.map(t => t.address))}`);
        }
      }
    } catch (err) {
      console.log(`   [${box}] error: ${err.message}`);
    }
  }

  // Broader search: anything mentioning openrouter in subject (catches forwards, digest emails)
  console.log("4) broader search in INBOX for 'openrouter' subject (last 24h):");
  try {
    await client.mailboxOpen("INBOX");
    const uids = await client.search({
      subject: "openrouter",
      since: new Date(Date.now() - 24 * 3600 * 1000),
    });
    console.log(`   found ${uids.length}`);
  } catch (err) {
    console.log(`   error: ${err.message}`);
  }

} catch (err) {
  console.error(`FATAL: ${err.message}`);
  console.error(err.stack);
  process.exit(1);
} finally {
  await client.logout().catch(() => {});
}
console.log("DONE");
