// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
// 5xx beacon → your alert webhook (optional) → an email to you.
//
// Server errors otherwise live only in logs nobody tails. This makes any 5xx a same-minute email instead of a someday surprise.
//
// Config: ALERT_WEBHOOK_URL (wrangler.toml var) + ALERT_TOKEN (worker secret).
// Missing config = silent no-op, never breaks the request path.
//
// Throttle: max 3 beacons/minute per isolate so an error storm (or a griefing
// loop) becomes a trickle of emails, not an inbox flood. Module scope is
// per-isolate, which is exactly the blast radius we want to bound.

let sentTimes = [];

// Internal header a route can set on its own 5xx to say "this one is not worth
// waking anyone up for". Stripped before the response leaves the worker, so it is
// never visible to a client. See markNoAlert() below.
export const ALERT_SKIP_HEADER = 'x-alert-skip';

// Tag a response as test traffic / expected-failure so the beacon skips it.
export function markNoAlert(response) {
  const tagged = new Response(response.body, response);
  tagged.headers.set(ALERT_SKIP_HEADER, '1');
  return tagged;
}

// Remove the internal tag on the way out. No-op (and no response rebuild) for
// the overwhelming majority of responses, which never carry it.
export function stripAlertHeader(response) {
  if (!response || !response.headers.has(ALERT_SKIP_HEADER)) return response;
  const clean = new Response(response.body, response);
  clean.headers.delete(ALERT_SKIP_HEADER);
  return clean;
}

// Build the beacon payload for a 5xx, or null if this one should be skipped.
//
// The message matters: without one, every alert email arrives with a blank "Error:" line and you had to go look up
// which of a dozen 502 branches had fired. The body of our own error response
// already says exactly that, so read it.
//
// Reads a CLONE — the original response body is still untouched for the client.
// `detail` is the thrown error's message, handed in by the worker's catch. It used
// to ride on an X-Error-Detail response header, which also sent it to the visitor.
export async function alertPayloadFor(request, response, detail = '') {
  if (response.headers.has(ALERT_SKIP_HEADER)) return null;

  let message = '';
  try {
    const raw = (await response.clone().text()).slice(0, 2000);
    let parsed = null;
    try { parsed = JSON.parse(raw); } catch { /* not our JSON error shape */ }
    if (detail) parsed = { error: detail, detail: parsed && parsed.error ? parsed.error : '' };
    message = parsed && (parsed.error || parsed.detail)
      ? [parsed.error, parsed.detail].filter(Boolean).join(' — ')
      : raw.replace(/\s+/g, ' ').trim();
  } catch { /* unreadable body — send the alert with no message rather than none at all */ }

  const url = new URL(request.url);
  return {
    path: url.pathname,
    method: request.method,
    status: response.status,
    message: message.slice(0, 400),
  };
}

// Fires the beacon. Returns the in-flight promise so the caller can hand it to
// ctx.waitUntil() itself when it is already inside an async chain.
export function reportServerError(env, ctx, info) {
  try {
    if (!env.ALERT_WEBHOOK_URL || !env.ALERT_TOKEN) return;
    const now = Date.now();
    sentTimes = sentTimes.filter(t => now - t < 60000);
    if (sentTimes.length >= 3) return;
    sentTimes.push(now);
    const send = fetch(env.ALERT_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Alert-Token': env.ALERT_TOKEN },
      body: JSON.stringify({
        app: env.APP_NAME || 'app',
        path: String(info.path || '').slice(0, 200),
        method: String(info.method || '').slice(0, 10),
        status: info.status,
        message: String(info.message || '').slice(0, 400),
        ts: new Date().toISOString(),
      }),
    }).catch(() => {});
    if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(send);
    return send;
  } catch { /* alerting must never take down the request */ }
}
