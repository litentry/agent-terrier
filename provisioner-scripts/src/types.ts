export type TripwireKind =
  | "selector_timeout"
  | "unexpected_nav"
  | "http5xx"
  | "email_timeout"
  | "verification_failed";

export type ProvisionErrorCode =
  | "provision_in_progress"
  | "tripwire_exhausted"
  | "email_backend_down"
  | "verification_endpoint_down"
  | "store_failed"
  | "malformed_event"
  | "timeout"
  | "internal";

export type ProvisionEvent =
  | { type: "progress"; step: string }
  | { type: "tripwire"; kind: TripwireKind; step: string; elapsed_ms: number }
  | { type: "success"; api_key: string }
  | { type: "error"; code: ProvisionErrorCode; details: string };

export function emit(event: ProvisionEvent): void {
  process.stdout.write(JSON.stringify(event) + "\n");
}

export function parseEventLine(line: string): ProvisionEvent | null {
  try {
    const parsed: unknown = JSON.parse(line);
    if (
      parsed !== null &&
      typeof parsed === "object" &&
      "type" in parsed &&
      typeof (parsed as { type: unknown }).type === "string"
    ) {
      return parsed as ProvisionEvent;
    }
    return null;
  } catch {
    return null;
  }
}
