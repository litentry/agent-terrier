import { describe, it, expect } from "vitest";
import { fetchVerificationCode, type ImapClientLike } from "./email.js";

function makeMockClient(emails: Array<{
  from: string;
  subject: string;
  body: string;
}>): ImapClientLike {
  const uids = emails.map((_, i) => i + 1);
  return {
    connect: async () => {},
    close: async () => {},
    mailboxOpen: async () => {},
    search: async () => uids,
    fetchOne: async (uid: number) => {
      const email = emails[uid - 1];
      if (!email) return null;
      return {
        envelope: {
          from: [{ address: email.from }],
          subject: email.subject,
        },
        source: Buffer.from(email.body, "utf-8"),
      };
    },
  };
}

function makeEmptyClient(): ImapClientLike {
  return {
    connect: async () => {},
    close: async () => {},
    mailboxOpen: async () => {},
    search: async () => [],
    fetchOne: async () => null,
  };
}

describe("email", () => {
  it("fetch_code_happy", async () => {
    const mockClient = makeMockClient([
      {
        from: "noreply@example.com",
        subject: "Your verification code",
        body: "Your code is 123456. Use it now.",
      },
    ]);

    const code = await fetchVerificationCode({
      from: /noreply@example\.com/,
      subject: /verification code/i,
      codeRegex: /Your code is (\d+)/,
      timeoutMs: 5000,
      imapClientFactory: () => mockClient,
    });

    expect(code).toBe("123456");
  });

  it("fetch_code_timeout", async () => {
    const emptyClient = makeEmptyClient();

    await expect(
      fetchVerificationCode({
        from: /noreply@example\.com/,
        subject: /verification code/i,
        codeRegex: /Your code is (\d+)/,
        timeoutMs: 50,
        pollIntervalMs: 20,
        imapClientFactory: () => emptyClient,
      })
    ).rejects.toMatchObject({ code: "EMAIL_TIMEOUT" });
  });

  it("fetch_code_wrong_pattern", async () => {
    const wrongSenderClient = makeMockClient([
      {
        from: "spam@wrong-sender.com",
        subject: "Your verification code",
        body: "Your code is 999999.",
      },
    ]);

    await expect(
      fetchVerificationCode({
        from: /noreply@example\.com/,
        subject: /verification code/i,
        codeRegex: /Your code is (\d+)/,
        timeoutMs: 200,
        pollIntervalMs: 20,
        imapClientFactory: () => wrongSenderClient,
      })
    ).rejects.toMatchObject({ code: "EMAIL_TIMEOUT" });
  });
});
