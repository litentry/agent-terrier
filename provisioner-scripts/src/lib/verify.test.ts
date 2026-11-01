import { describe, it, expect } from "vitest";
import { verify } from "./verify.js";

function makeMockFetch(status: number): typeof fetch {
  return async () =>
    ({
      status,
      ok: status >= 200 && status < 300,
    }) as Response;
}

describe("verify", () => {
  it("valid_key_returns_true", async () => {
    const result = await verify({
      service: "openrouter",
      key: "sk-or-v1-valid",
      fetchFn: makeMockFetch(200),
    });
    expect(result).toEqual({ valid: true });
  });

  it("invalid_key_returns_false_phantom", async () => {
    const result = await verify({
      service: "openrouter",
      key: "sk-or-v1-phantom",
      fetchFn: makeMockFetch(401),
    });
    expect(result).toEqual({ valid: false, reason: "phantom" });
  });

  it("endpoint_down_distinction", async () => {
    const result = await verify({
      service: "openrouter",
      key: "sk-or-v1-anything",
      fetchFn: makeMockFetch(503),
    });
    expect(result).toEqual({ valid: false, reason: "endpoint_down" });
  });
});
