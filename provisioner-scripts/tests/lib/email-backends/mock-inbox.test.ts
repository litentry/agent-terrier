import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { fetchViaMockInbox } from "../../../src/lib/email-backends/mock-inbox.js";

const FIXED_ADDRESS = "bot-test@agentkeys-email.io";
const FIXED_TOKEN = "test-session-token";

function makeMessage(overrides: {
  from?: string;
  subject?: string;
  body?: string;
  msg_id?: string;
  received_at?: number;
}) {
  return {
    msg_id: overrides.msg_id ?? "msg-1",
    from: overrides.from ?? "noreply@example.com",
    subject: overrides.subject ?? "Your code",
    body: overrides.body ?? "Your code is 123456",
    received_at: overrides.received_at ?? 1000,
  };
}

function setupEnv() {
  process.env["AGENTKEYS_SIGNUP_EMAIL"] = FIXED_ADDRESS;
  process.env["AGENTKEYS_SESSION_TOKEN"] = FIXED_TOKEN;
  process.env["AGENTKEYS_BACKEND_URL"] = "http://127.0.0.1:8090";
}

function clearEnv() {
  delete process.env["AGENTKEYS_SIGNUP_EMAIL"];
  delete process.env["AGENTKEYS_SESSION_TOKEN"];
  delete process.env["AGENTKEYS_BACKEND_URL"];
}

describe("mock-inbox backend", () => {
  beforeEach(() => {
    setupEnv();
  });

  afterEach(() => {
    clearEnv();
    vi.restoreAllMocks();
  });

  it("returns code on first poll when matching message present", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [makeMessage({ body: "Your code is 654321" })],
    });
    vi.stubGlobal("fetch", fetchMock);

    const code = await fetchViaMockInbox({
      from: /noreply@example\.com/,
      subject: /Your code/i,
      codeRegex: /(\d{6})/,
      timeoutMs: 5000,
    });

    expect(code).toBe("654321");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const calledUrl: string = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toContain("/mock/inbox/messages");
    expect(calledUrl).toContain(encodeURIComponent(FIXED_ADDRESS));
  });

  it("uses Authorization: Bearer header with session token", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [makeMessage({})],
    });
    vi.stubGlobal("fetch", fetchMock);

    await fetchViaMockInbox({
      from: /noreply@example\.com/,
      subject: /Your code/i,
      codeRegex: /(\d{6})/,
      timeoutMs: 5000,
    });

    const calledInit = fetchMock.mock.calls[0][1] as RequestInit;
    expect((calledInit.headers as Record<string, string>)["Authorization"]).toBe(
      `Bearer ${FIXED_TOKEN}`
    );
  });

  it("polls until matching message arrives", async () => {
    let callCount = 0;
    const fetchMock = vi.fn().mockImplementation(async () => {
      callCount++;
      const messages =
        callCount < 3
          ? []
          : [makeMessage({ body: "Code: 999888" })];
      return { ok: true, json: async () => messages };
    });
    vi.stubGlobal("fetch", fetchMock);

    const code = await fetchViaMockInbox({
      from: /noreply@example\.com/,
      subject: /Your code/i,
      codeRegex: /(\d{6})/,
      timeoutMs: 5000,
      pollIntervalMs: 10,
    });

    expect(code).toBe("999888");
    expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(3);
  });

  it("times out when no matching message arrives", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [],
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      fetchViaMockInbox({
        from: /noreply@example\.com/,
        subject: /Your code/i,
        codeRegex: /(\d{6})/,
        timeoutMs: 80,
        pollIntervalMs: 20,
      })
    ).rejects.toMatchObject({ code: "EMAIL_TIMEOUT" });
  });

  it("skips messages that don't match from filter", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [makeMessage({ from: "spam@wrong.com", body: "Code: 111111" })],
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      fetchViaMockInbox({
        from: /noreply@example\.com/,
        subject: /Your code/i,
        codeRegex: /(\d{6})/,
        timeoutMs: 80,
        pollIntervalMs: 20,
      })
    ).rejects.toMatchObject({ code: "EMAIL_TIMEOUT" });
  });

  it("throws clear error when AGENTKEYS_SESSION_TOKEN is missing", async () => {
    delete process.env["AGENTKEYS_SESSION_TOKEN"];

    await expect(
      fetchViaMockInbox({
        from: /./,
        subject: /./,
        codeRegex: /(\d{6})/,
        timeoutMs: 5000,
      })
    ).rejects.toThrow("AGENTKEYS_SESSION_TOKEN");
  });

  it("throws clear error when AGENTKEYS_SIGNUP_EMAIL is missing", async () => {
    delete process.env["AGENTKEYS_SIGNUP_EMAIL"];

    await expect(
      fetchViaMockInbox({
        from: /./,
        subject: /./,
        codeRegex: /(\d{6})/,
        timeoutMs: 5000,
      })
    ).rejects.toThrow("AGENTKEYS_SIGNUP_EMAIL");
  });

  it("uses default backend URL when AGENTKEYS_BACKEND_URL is not set", async () => {
    delete process.env["AGENTKEYS_BACKEND_URL"];

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [makeMessage({})],
    });
    vi.stubGlobal("fetch", fetchMock);

    await fetchViaMockInbox({
      from: /noreply@example\.com/,
      subject: /Your code/i,
      codeRegex: /(\d{6})/,
      timeoutMs: 5000,
    });

    const calledUrl: string = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toContain("http://127.0.0.1:8090");
  });
});
