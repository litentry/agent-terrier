# OpenRouter Fixture Files

These are synthetic HTML fixtures used for hermetic unit testing of the OpenRouter scraper.
They are NOT live recordings or HAR files — they are hand-crafted HTML pages that simulate
the OpenRouter signup flow without any real network calls.

## Files

### pages/signup.html
Email entry form. Contains `input[name="email"]` and `button[type="submit"]`.
Submitting navigates to `/verify`.

### pages/verify.html
OTP verification form. Contains `input[name="otp"]` and `button[type="submit"]`.
Submitting navigates to `/dashboard`.

### pages/dashboard.html
Landing page after OTP verification. Contains a link to `/keys`.

### pages/keys.html
API keys management page. Contains a "Create Key" button that reveals
`span[data-testid="new-api-key"]` with a test key value.

## Usage

Tests use Playwright's `page.route()` to intercept requests and serve these local HTML files,
providing a hermetic alternative to HAR replay. See `tests/fixtures/openrouter/mock-site.ts`.

## Notes

These are synthetic fixtures, not live recordings.
Last-updated: 2026-04-16
