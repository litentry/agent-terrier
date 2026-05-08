//! `GET /auth/email/landing` — Phase A.1, US-018.
//!
//! Broker-hosted static HTML page. Reads `window.location.hash`
//! (`#t=<token>`), POSTs the token to `/v1/auth/email/verify`, and
//! shows "Verified — return to your terminal" on success.
//!
//! Headers: `Cache-Control: no-store`, `Referrer-Policy: no-referrer`
//! per plan §3.5.3. The token NEVER appears in the server log because
//! it rides in the URL fragment (which the browser does not include
//! in the HTTP request line).

use axum::{
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};

const LANDING_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>AgentKeys — Verifying</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 30rem; margin: 4rem auto; padding: 1rem; }
  h1 { font-size: 1.5rem; }
  .ok { color: #060; }
  .err { color: #c00; }
  code { background: #f4f4f4; padding: 0.1rem 0.3rem; border-radius: 3px; }
</style>
</head>
<body>
<h1>AgentKeys email link</h1>
<p id="msg">Verifying…</p>
<script>
(async () => {
  const msg = document.getElementById('msg');
  const hash = window.location.hash || '';
  const m = hash.match(/^#t=([A-Za-z0-9_-]+)$/);
  if (!m) {
    msg.textContent = 'Magic link is malformed. Re-request from your terminal.';
    msg.className = 'err';
    return;
  }
  const token = m[1];
  // Strip the fragment from history so the token doesn't survive a refresh.
  history.replaceState(null, '', window.location.pathname);
  try {
    const r = await fetch('/v1/auth/email/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token })
    });
    if (r.ok) {
      msg.innerHTML = 'Verified — <strong>return to your terminal</strong>.';
      msg.className = 'ok';
    } else {
      const body = await r.json().catch(() => ({}));
      msg.textContent = 'Verify failed: ' + (body.message || r.status);
      msg.className = 'err';
    }
  } catch (e) {
    msg.textContent = 'Network error verifying link: ' + e.message;
    msg.className = 'err';
  }
})();
</script>
</body>
</html>"#;

pub async fn email_landing() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("text/html; charset=utf-8"));
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    (StatusCode::OK, headers, LANDING_HTML)
}
