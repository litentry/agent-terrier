// Privacy toggle for the operator email — for screen-sharing / demo recordings.
// Toggled from the UI (header + onboarding), persisted in localStorage so it
// survives reloads and future sessions. Default ON (masked) so a recording never
// leaks the email by accident; flip DEFAULT_MASKED to false for a production
// deployment where users expect to see their own address.
const KEY = 'ak_mask_email';
const DEFAULT_MASKED = true;

export function getMaskEmail(): boolean {
  try {
    const v = localStorage.getItem(KEY);
    return v === null ? DEFAULT_MASKED : v === '1';
  } catch {
    return DEFAULT_MASKED;
  }
}

export function setMaskEmail(masked: boolean): void {
  try {
    localStorage.setItem(KEY, masked ? '1' : '0');
  } catch {
    /* ignore (private mode / SSR) */
  }
}

/** Render-time helper: the real email, or a fixed mask when `masked`. */
export function maskEmail(email: string | undefined, masked: boolean): string {
  if (!email) return '';
  return masked ? '••••••••' : email;
}
