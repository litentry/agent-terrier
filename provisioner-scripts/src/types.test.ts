import { describe, it, expect, vi } from "vitest";
import { emit, parseEventLine, type ProvisionEvent } from "./types.js";

describe("types", () => {
  it("emit_single_line", () => {
    const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      const event: ProvisionEvent = { type: "progress", step: "creating_account" };
      emit(event);
      expect(writeSpy).toHaveBeenCalledTimes(1);
      const arg = writeSpy.mock.calls[0][0] as string;
      expect(arg.endsWith("\n")).toBe(true);
      const jsonPart = arg.slice(0, arg.length - 1);
      expect(jsonPart.includes("\n")).toBe(false);
    } finally {
      writeSpy.mockRestore();
    }
  });

  it("roundtrip_all_variants", () => {
    const variants: ProvisionEvent[] = [
      { type: "progress", step: "waiting_for_email" },
      {
        type: "tripwire",
        kind: "selector_timeout",
        step: "submit_button",
        elapsed_ms: 15000,
      },
      { type: "success", api_key: "sk-or-v1-abcd1234" },
      { type: "error", code: "store_failed", details: "backend returned 500" },
    ];
    for (const variant of variants) {
      const line = JSON.stringify(variant);
      const parsed = parseEventLine(line);
      expect(parsed).toEqual(variant);
    }
  });

  it("parse_malformed_returns_null", () => {
    expect(parseEventLine("not json")).toBeNull();
  });
});
