import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { fetchViaSesS3 } from "../../../src/lib/email-backends/ses-s3.js";
import { S3Client } from "@aws-sdk/client-s3";

function makeMockS3(emlContents: string[], lastModified?: Array<Date | undefined>): S3Client {
  const s3 = new S3Client({ region: "us-east-1" });

  const objects = emlContents.map((_, i) => ({
    Key: `inbound/msg-${i}.eml`,
    LastModified: lastModified?.[i],
  }));

  vi.spyOn(s3, "send").mockImplementation(async (command: unknown) => {
    const cmd = command as { constructor: { name: string } };
    if (cmd.constructor.name === "ListObjectsV2Command") {
      return { Contents: objects };
    }
    if (cmd.constructor.name === "GetObjectCommand") {
      const getCmd = command as { input: { Key: string } };
      const idx = objects.findIndex((o) => o.Key === getCmd.input.Key);
      if (idx === -1 || !emlContents[idx]) return { Body: null };
      const content = emlContents[idx];
      const readable = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(content));
          controller.close();
        },
      }) as unknown as NodeJS.ReadableStream;
      return { Body: readable };
    }
    return {};
  });

  return s3;
}

function buildEml(from: string, subject: string, body: string): string {
  return [
    `From: ${from}`,
    `Subject: ${subject}`,
    `Content-Type: text/plain`,
    ``,
    body,
  ].join("\r\n");
}

describe("ses-s3 backend", () => {
  beforeEach(() => {
    process.env["AGENTKEYS_SES_BUCKET"] = "test-ses-bucket";
  });

  afterEach(() => {
    delete process.env["AGENTKEYS_SES_BUCKET"];
    vi.restoreAllMocks();
  });

  it("extracts code from a matching .eml object", async () => {
    const eml = buildEml(
      "noreply@example.com",
      "Your verification code",
      "Your code is 789012. Do not share."
    );
    const s3 = makeMockS3([eml]);

    const code = await fetchViaSesS3(
      {
        from: /noreply@example\.com/,
        subject: /verification code/i,
        codeRegex: /(\d{6})/,
        timeoutMs: 5000,
      },
      s3
    );

    expect(code).toBe("789012");
  });

  it("skips objects with non-matching from header", async () => {
    const eml = buildEml(
      "spam@wrong.com",
      "Your verification code",
      "Code: 111111"
    );
    const s3 = makeMockS3([eml]);

    await expect(
      fetchViaSesS3(
        {
          from: /noreply@example\.com/,
          subject: /verification code/i,
          codeRegex: /(\d{6})/,
          timeoutMs: 80,
          pollIntervalMs: 20,
        },
        s3
      )
    ).rejects.toMatchObject({ code: "EMAIL_TIMEOUT" });
  });

  it("skips objects with non-matching subject header", async () => {
    const eml = buildEml(
      "noreply@example.com",
      "Newsletter",
      "Code: 222222"
    );
    const s3 = makeMockS3([eml]);

    await expect(
      fetchViaSesS3(
        {
          from: /noreply@example\.com/,
          subject: /verification code/i,
          codeRegex: /(\d{6})/,
          timeoutMs: 80,
          pollIntervalMs: 20,
        },
        s3
      )
    ).rejects.toMatchObject({ code: "EMAIL_TIMEOUT" });
  });

  it("times out when bucket is empty", async () => {
    const s3 = new S3Client({ region: "us-east-1" });
    vi.spyOn(s3, "send").mockResolvedValue({ Contents: [] } as never);

    await expect(
      fetchViaSesS3(
        {
          from: /noreply@example\.com/,
          subject: /verification code/i,
          codeRegex: /(\d{6})/,
          timeoutMs: 80,
          pollIntervalMs: 20,
        },
        s3
      )
    ).rejects.toMatchObject({ code: "EMAIL_TIMEOUT" });
  });

  it("throws clear error when AGENTKEYS_SES_BUCKET is missing", async () => {
    delete process.env["AGENTKEYS_SES_BUCKET"];
    const s3 = new S3Client({ region: "us-east-1" });

    await expect(
      fetchViaSesS3(
        {
          from: /./,
          subject: /./,
          codeRegex: /(\d{6})/,
          timeoutMs: 5000,
        },
        s3
      )
    ).rejects.toThrow("AGENTKEYS_SES_BUCKET");
  });

  it("handles multiple objects and returns first code match", async () => {
    const emls = [
      buildEml("spam@wrong.com", "Promo", "nothing here"),
      buildEml("noreply@example.com", "Your verification code", "Code: 345678"),
    ];
    const s3 = makeMockS3(emls);

    const code = await fetchViaSesS3(
      {
        from: /noreply@example\.com/,
        subject: /verification code/i,
        codeRegex: /(\d{6})/,
        timeoutMs: 5000,
      },
      s3
    );

    expect(code).toBe("345678");
  });

  describe("synthetic magic-link verification", () => {
    // Exact regexes as used in openrouter-cdp.ts magic-link branch. If those
    // diverge, this test catches it.
    const MAGIC_LINK_FROM = /@openrouter\.ai|clerk/i;
    const MAGIC_LINK_SUBJECT =
      /sign[\s-]?up.*link|sign[\s-]?in.*link|magic.*link|verify|verification|confirm/i;
    const MAGIC_LINK_URL =
      /(https:\/\/[^\s<>"'\)]*(?:clerk|\/verify|ticket=|verification)[^\s<>"'\)]*)/i;

    const SAMPLE_FROM = "OpenRouter <notifications@openrouter.ai>";
    const SAMPLE_SUBJECT = "Your sign up link";
    const SAMPLE_QP_BODY = [
      "Content-Type: text/html; charset=utf-8",
      "Content-Transfer-Encoding: quoted-printable",
      "",
      "<html><body><p>Click to verify:</p>",
      "<a href=3D\"https=3A=2F=2Fclerk=2Eopenrouter=2Eai=2Fv1=2Fverify=3F__clerk_=",
      "ticket=3Dabc123def456ghi789jkl&__clerk_redirect=3Dhttps=253A=252F=252Fope=",
      "nrouter=2Eai=2F\">Verify email</a>",
      "</body></html>",
    ].join("\r\n");

    const sampleVerificationEmail = [
      `From: ${SAMPLE_FROM}`,
      `Subject: ${SAMPLE_SUBJECT}`,
      `MIME-Version: 1.0`,
      SAMPLE_QP_BODY,
    ].join("\r\n");

    it("accepts notifications@openrouter.ai and extracts the Clerk URL", async () => {
      const s3 = makeMockS3([sampleVerificationEmail]);

      const url = await fetchViaSesS3(
        {
          from: MAGIC_LINK_FROM,
          subject: MAGIC_LINK_SUBJECT,
          codeRegex: MAGIC_LINK_URL,
          timeoutMs: 5000,
        },
        s3
      );

      expect(url).toMatch(/^https:\/\/clerk\.openrouter\.ai\/v1\/verify\?/);
      expect(url).toContain("__clerk_ticket=abc123def456ghi789jkl");
      expect(() => new URL(url)).not.toThrow();
    });

    it("skips non-verify emails from the same sender", async () => {
      const marketingEml = buildEml(
        SAMPLE_FROM,
        "Weekly credit summary from OpenRouter",
        "You used 1,234 credits this week."
      );
      const s3 = makeMockS3([marketingEml]);

      await expect(
        fetchViaSesS3(
          {
            from: MAGIC_LINK_FROM,
            subject: MAGIC_LINK_SUBJECT,
            codeRegex: MAGIC_LINK_URL,
            timeoutMs: 80,
            pollIntervalMs: 20,
          },
          s3
        )
      ).rejects.toMatchObject({ code: "EMAIL_TIMEOUT" });
    });

    // Subjects seen across Stage 6 runs — all must match MAGIC_LINK_SUBJECT.
    // If OpenRouter/Clerk changes subject copy again, add to this list and
    // the regex stays honest.
    const OBSERVED_VERIFY_SUBJECTS = [
      "Your sign up link",
      "Your sign-up link",
      "Your sign in link",
      "Verify your email for OpenRouter",
      "Verify your email address",
      "Confirm your email",
      "Your magic link",
    ];

    it.each(OBSERVED_VERIFY_SUBJECTS)("matches observed subject %j", (subject) => {
      expect(MAGIC_LINK_SUBJECT.test(subject)).toBe(true);
    });

    // Non-verify subjects from same sender — MUST be rejected.
    const NON_VERIFY_SUBJECTS = [
      "Weekly credit summary from OpenRouter",
      "Your account usage report",
      "New model available on OpenRouter",
    ];

    it.each(NON_VERIFY_SUBJECTS)("rejects non-verify subject %j", (subject) => {
      expect(MAGIC_LINK_SUBJECT.test(subject)).toBe(false);
    });

    it("rejects verification emails older than freshnessGraceMs (prior-run leftovers)", async () => {
      const staleEml = [
        `From: OpenRouter <notifications@openrouter.ai>`,
        `Subject: Your sign up link`,
        ``,
        `Sign up: https://clerk.openrouter.ai/v1/verify?token=STALE_TOKEN_OLD`,
      ].join("\r\n");

      const now = new Date();
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
      const s3 = makeMockS3([staleEml], [oneHourAgo]);

      await expect(
        fetchViaSesS3(
          {
            from: MAGIC_LINK_FROM,
            subject: MAGIC_LINK_SUBJECT,
            codeRegex: MAGIC_LINK_URL,
            timeoutMs: 150,
            pollIntervalMs: 30,
            freshnessGraceMs: 60_000, // 60s window
          },
          s3
        )
      ).rejects.toMatchObject({ code: "EMAIL_TIMEOUT" });
    });

    it("picks the fresh verification email when bucket has both stale + fresh", async () => {
      const staleEml = [
        `From: OpenRouter <notifications@openrouter.ai>`,
        `Subject: Your sign up link`,
        ``,
        `Link: https://clerk.openrouter.ai/v1/verify?token=STALE_OLD_TOKEN`,
      ].join("\r\n");

      const freshEml = [
        `From: OpenRouter <notifications@openrouter.ai>`,
        `Subject: Your sign up link`,
        ``,
        `Link: https://clerk.openrouter.ai/v1/verify?token=FRESH_NEW_TOKEN`,
      ].join("\r\n");

      const now = new Date();
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
      const s3 = makeMockS3([staleEml, freshEml], [oneHourAgo, now]);

      const url = await fetchViaSesS3(
        {
          from: MAGIC_LINK_FROM,
          subject: MAGIC_LINK_SUBJECT,
          codeRegex: MAGIC_LINK_URL,
          timeoutMs: 2000,
          freshnessGraceMs: 60_000,
        },
        s3
      );

      expect(url).toContain("token=FRESH_NEW_TOKEN");
      expect(url).not.toContain("STALE_OLD_TOKEN");
    });

    it("extracts URLs that contain &amp; (HTML-entity-encoded) from plain-text body", async () => {
      const sampleBody = [
        "Content-Type: text/plain; charset=us-ascii",
        "",
        "Use the following link to sign up to OpenRouter: https://clerk.openrouter.ai/v1/verify?_clerk_js_version=test-client&amp;token=synthetic-verification-token",
        "",
        "Synthetic verification message.",
      ].join("\r\n");

      const eml = [
        `From: OpenRouter <notifications@openrouter.ai>`,
        `Subject: Your sign up link`,
        `MIME-Version: 1.0`,
        sampleBody,
      ].join("\r\n");

      const s3 = makeMockS3([eml]);

      const url = await fetchViaSesS3(
        {
          from: MAGIC_LINK_FROM,
          subject: MAGIC_LINK_SUBJECT,
          codeRegex: MAGIC_LINK_URL,
          timeoutMs: 5000,
        },
        s3
      );

      expect(url).toContain("https://clerk.openrouter.ai/v1/verify");
      expect(url).toContain("_clerk_js_version=test-client");
      // Must capture past the &amp; boundary — this is the bug-regression guard.
      expect(url).toContain("token=synthetic-verification-token");
    });

    it("ignores mixed bucket noise and returns only the matching verification URL", async () => {
      const emls = [
        buildEml(
          "Amazon Web Services <no-reply-aws@amazon.com>",
          "Amazon SES Setup",
          "ses notification"
        ),
        buildEml(
          "Example Service <operator@example.net>",
          "Internal note",
          "unrelated"
        ),
        buildEml(
          SAMPLE_FROM,
          "Weekly credit summary",
          "Not a verify email."
        ),
        sampleVerificationEmail,
      ];
      const s3 = makeMockS3(emls);

      const url = await fetchViaSesS3(
        {
          from: MAGIC_LINK_FROM,
          subject: MAGIC_LINK_SUBJECT,
          codeRegex: MAGIC_LINK_URL,
          timeoutMs: 5000,
        },
        s3
      );

      expect(url).toContain("clerk.openrouter.ai/v1/verify");
    });
  });
});
