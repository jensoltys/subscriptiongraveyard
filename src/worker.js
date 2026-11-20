// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
// worker.js — Subscription Graveyard API
// Cloudflare Worker + D1 database
// Auth: PBKDF2 password hashing + HS256 JWT (30-day sessions)

import { verifyHubPro } from './lib/verify-hub-pro.js';
import { reportServerError, alertPayloadFor, stripAlertHeader, markNoAlert } from './lib/alert.js';
import { WATCHLIST_MAX_PER_USER, PER_USER_PER_RUN, DAILY_SEND_MAX, planFairSends, claimDailySends } from './lib/send-budget.js';
import { emailLayout, emailPara, emailSmall, emailCode, emailButton, emailBigStat, emailLabel, FONT_BODY } from './lib/email-look.js';

// ── Auth-mail limits ───────────────────────────────
// Every route that mails a typed address has three limits: per-IP (existing),
// per-address (a rotating-IP script can't flood one inbox), and an app-wide
// daily ceiling so a flood can't eat the Resend quota the renewal warnings
// share. Sign-up/verification mail and reset mail have SEPARATE ceilings, so
// signup spam can't lock real users out of a password reset.
const VERIFY_MAIL_DAILY = 150;   // signup + resend-verification codes per UTC day
const RESET_MAIL_DAILY = 150;    // password reset links per UTC day
const MAIL_PER_ADDRESS = 3;      // per address per window, for each kind
const MAIL_PER_ADDRESS_WINDOW = 900; // 15 minutes

// Free plan caps. A copy with no PRO_LOOKUP_URL / HUB_JWT_SECRET puts everyone on
// the free plan, so change these numbers if you want bigger caps on your own copy.
const FREE_BURIALS = 5;
const FREE_LAST_RITES = 5;

// Where Go Pro sends people when this copy has its own Pro hub (HUB_JWT_SECRET set):
// UPGRADE_URL in wrangler.toml. Blank, or no hub, = no upgrade link anywhere.
let UPGRADE_BASE = '';
function upgradeUrl(feature) {
  if (!UPGRADE_BASE) return undefined;
  return UPGRADE_BASE + (UPGRADE_BASE.includes('?') ? '&' : '?') + 'feature=' + encodeURIComponent(feature);
}

// The hub secrets sign logins and Pro, so a short one is as bad as none. Any of
// these set to fewer than 32 characters is treated as not set, and logged once.
const HUB_SECRET_NAMES = ['HUB_JWT_SECRET', 'HUB_LOOKUP_SECRET', 'RECAP_SERVICE_SECRET'];
const MIN_SECRET_LENGTH = 32;
let warnedShortSecret = false;
function usableEnv(env) {
  const short = HUB_SECRET_NAMES.filter(n => env[n] && String(env[n]).length < MIN_SECRET_LENGTH);
  if (!short.length) return env;
  if (!warnedShortSecret) {
    warnedShortSecret = true;
    console.error(`Ignoring ${short.join(', ')}: set to fewer than ${MIN_SECRET_LENGTH} characters, so treated as not set. Make one with: openssl rand -hex 32`);
  }
  const out = Object.create(env);
  for (const n of short) Object.defineProperty(out, n, { value: '', enumerable: true });
  return out;
}

// Link previews and search engines need full addresses. The pages ship with
// site-relative ones, so this fills in the site's own address (APP_URL) and adds
// the canonical link on the way out.
function absoluteMeta(html, base) {
  const b = escapeHtml(base);
  let canonical = '';
  html = html.replace(/(<meta (?:property|name)="(og:url|og:image|twitter:image)" content=")(\/[^"]*)"/g, (m, head, name, path) => {
    if (name === 'og:url') canonical = b + path;
    return head + b + path + '"';
  });
  if (canonical && !html.includes('<link rel="canonical"')) {
    html = html.replace('</head>', () => `<link rel="canonical" href="${canonical}"/>\n</head>`);
  }
  return html;
}

// This site's own address, from APP_URL in wrangler.toml. Set on every request.
let APP_BASE = '';
function setAppBase(env) {
  APP_BASE = String(env.APP_URL || '').replace(/\/+$/, '');
  const up = String(env.UPGRADE_URL || '').trim();
  UPGRADE_BASE = env.HUB_JWT_SECRET && /^https?:\/\//i.test(up) ? up : '';
}

// Email theme ("Blood Moon" + the Keeper). Layout: lib/email-look.js.
const EMAIL_THEME = {
  name: 'Subscription Graveyard', get mascotUrl() { return APP_BASE + '/email-mascot.png'; }, mascotAlt: 'The Keeper', mascotW: 80,
  bg: '#141113', card: '#1F191B', line: '#3A2F33', pri: '#FF6B57', pri2: '#E5533F', on: '#2A0905', a2: '#6EDBA8', text: '#E9DFC9', muted: '#B4A7A6',
};

// Pro entitlement check: free-user SSO tokens carry pro_until=null. A verified
// hubPro payload alone is NOT proof of Pro — must also have a future pro_until.
function hasProAccess(hubPro) {
  return !!(hubPro?.email && hubPro?.pro_until && new Date(hubPro.pro_until) > new Date());
}
// A hub Pro token names its buyer. It counts only for the account it was bought
// for; presented by any other account it is treated as absent.
async function bindHubPro(hubPro, uid, env) {
  if (!hubPro?.email) return hubPro;
  const me = await env.DB.prepare('SELECT email FROM users WHERE id=?').bind(uid).first();
  return me && String(me.email).toLowerCase() === String(hubPro.email).toLowerCase() ? hubPro : null;
}

// A request is trusted only when its Origin is this site's own address, so a
// self-hosted copy works on any domain with nothing to configure.
function getCorsHeaders(request) {
  const allowOrigin = new URL(request.url).origin;
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Hub-Pro',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

// CSRF Origin/Referer check. The session is an HttpOnly cookie, which the
// browser attaches to every request to this host no matter which site started
// it, so every state-changing request has to prove it came from one of our own
// pages: the origin the request was sent to.
// Returns null if OK, or a 403 Response.
function checkOrigin(request, cors) {
  const own = [new URL(request.url).origin];
  const origin = request.headers.get('Origin') || '';
  const referer = request.headers.get('Referer') || '';
  if (origin) return own.includes(origin) ? null : res({ error: 'Forbidden' }, 403, cors);
  if (referer && own.some(o => referer.startsWith(o + '/'))) return null;
  return res({ error: 'Forbidden' }, 403, cors);
}

// State-changing routes that skip the Origin check, each with its reason.
// A route belongs here only if no browser ever calls it with our cookie.
// Subscription Graveyard has none: its only secret-header route
// (/api/service/recap) is a GET, the cron runs as scheduled() not fetch(),
// and there is no Stripe webhook in this app.
const CSRF_EXEMPT = new Set([]);

// ── Session cookie ──────────────────────────────────────────────────────────
// The login session is an HS256 JWT held in an HttpOnly cookie, so page
// scripts can never read it. Same 30-day life as the JWT inside it.
const SESSION_COOKIE = 'sg_session';
const SESSION_TTL = 30 * 86400;
const COOKIE_ATTRS = 'Path=/; HttpOnly; Secure; SameSite=Lax';

function sessionCookie(jwt, maxAge = SESSION_TTL) {
  return `${SESSION_COOKIE}=${jwt}; ${COOKIE_ATTRS}; Max-Age=${Math.max(0, Math.floor(maxAge))}`;
}
function clearSessionCookie() {
  return `${SESSION_COOKIE}=; ${COOKIE_ATTRS}; Max-Age=0`;
}
function readCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}
async function mintSession(uid, tokenVersion, env) {
  return makeJWT({ sub: uid, tv: tokenVersion ?? 0, exp: Math.floor(Date.now() / 1000) + SESSION_TTL }, env.JWT_SECRET);
}
// A JSON response that also starts (or replaces) the session cookie.
function resWithSession(data, jwt, cors) {
  const r = res(data, 200, cors);
  r.headers.append('Set-Cookie', sessionCookie(jwt));
  return r;
}
function hasSession(request) {
  return !!readCookie(request, SESSION_COOKIE);
}

// SHA-256 hex helper — used to store opaque tokens (reset, email-verify) as
// hashes-at-rest so a DB read can't replay them.
async function sha256Hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// Email validator — single source of truth for signup, login, reset-request, hub-sso.
function isValidEmail(s) {
  return typeof s === 'string' && s.length > 3 && s.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}

// Password length policy: min 10, max 200. Min enforces strength; max defends
// PBKDF2-100k DoS from attacker-controlled blob.
function isValidPassword(s) {
  return typeof s === 'string' && s.length >= 10 && s.length <= 200;
}

// A date field must be a string naming a real calendar day. The shape check
// alone let "2020-13-45" through (it later threw inside the daily job) and let
// an array through (D1 can't store one, so the request ended in a 500).
function isRealDate(v) {
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return false;
  const d = new Date(v + 'T00:00:00Z');
  return !isNaN(d.getTime()) && d.toISOString().slice(0, 10) === v;
}

const ALLOWED_CATEGORIES = ['streaming','software','fitness','food','news','gaming','music','audiobooks','storage','productivity','other'];
const ALLOWED_CYCLES = ['monthly','quarterly','annual','weekly'];
const ALLOWED_REMINDER_MODES = ['cancel','negotiate'];

export default {
  // Any 5xx that leaves this worker fires an email beacon (alert.js) so a
  // real visitor hitting a server error is a same-minute email, not a
  // someday discovery in the logs.
  async fetch(request, env, ctx) {
    env = usableEnv(env);
    setAppBase(env);
    // A THROW out of handle() has to become a Response before the 5xx branch
    // below can see it. Without this catch the exception escaped the worker,
    // the runtime returned its own 500, and NO alert email was sent — silent on
    // exactly the crash class the beacon exists for.
    let response;
    let errDetail = '';
    try {
      response = await this.handle(request, env, ctx);
    } catch (e) {
      console.error('unhandled route error', request.method, new URL(request.url).pathname, (e && e.stack) || e);
      response = new Response(JSON.stringify({ error: 'Server error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      });
      // The message the beacon reads comes off this body, so name the cause.
      errDetail = String((e && e.message) || e).slice(0, 200);
    }
    try {
      if (response && response.status >= 500) {
        // The message is read off a clone of the response body inside
        // waitUntil, so it never delays the client. Responses tagged by markNoAlert()
        // are skipped.
        const job = alertPayloadFor(request, response, errDetail)
          .then(info => (info ? reportServerError(env, null, info) : null))
          .catch(() => {});
        if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(job);
      }
    } catch { /* never block the response */ }
    return stripAlertHeader(response);
  },

  async handle(request, env, ctx) {
    const cors = getCorsHeaders(request);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    const url = new URL(request.url);
    const p = url.pathname;

    // Pro entitlement: if X-Hub-Pro header present, verify it.
    // Result is { email, pro_until } payload or null. Used by route handlers.
    const hubProToken = request.headers.get('X-Hub-Pro');
    let hubPro = null;
    if (hubProToken && env.HUB_JWT_SECRET) {
      hubPro = await verifyHubPro(hubProToken, env.HUB_JWT_SECRET);
    }

    if (!p.startsWith('/api/')) {
      // /reset/<token> is a virtual route: there is no asset at that path, so
      // ask ASSETS for the SPA shell instead. Without this the reset link 404s.
      const assetReq = /^\/reset\/[A-Za-z0-9._-]{16,256}\/?$/.test(p)
        ? new Request(new URL('/', request.url), request)
        : request;
      const asset = await env.ASSETS.fetch(assetReq);
      const headers = new Headers(asset.headers);
      headers.set('X-Content-Type-Options', 'nosniff');
      headers.set('X-Frame-Options', 'DENY');
      headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
      headers.set('Strict-Transport-Security', 'max-age=31536000');
      headers.set('Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self' https://static.cloudflareinsights.com; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com data:; " +
        "img-src 'self' data: blob:; " +
        "connect-src 'self' https://cloudflareinsights.com; " +
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none';");
      headers.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=(), usb=()');
      headers.set('Cache-Control', 'public, max-age=0, must-revalidate, no-cache');
      if (asset.status === 200 && request.method === 'GET' && APP_BASE && (headers.get('Content-Type') || '').includes('text/html')) {
        headers.delete('Content-Length');
        return new Response(absoluteMeta(await asset.text(), APP_BASE), { status: 200, headers });
      }
      return new Response(asset.body, { status: asset.status, headers });
    }

    // Reject oversized request bodies (64KB max)
    const contentLength = parseInt(request.headers.get('Content-Length') || '0');
    if (contentLength > 65536) {
      return res({ error: 'Request too large' }, 413, cors);
    }

    try {
      // A copy with no session secret can't log anyone in. Say so before any
      // account is written, instead of failing halfway with "Server error".
      if (p.startsWith('/api/auth/') && request.method === 'POST' && p !== '/api/auth/logout'
          && (typeof env.JWT_SECRET !== 'string' || env.JWT_SECRET.length < 32)) {
        console.error('JWT_SECRET is not set (or is shorter than 32 characters). Sign up and log in are off until it is.');
        return markNoAlert(res({ error: "This server isn't set up yet. Its owner needs to set JWT_SECRET to a random string of 32 or more characters.", code: 'setup_required' }, 503, cors));
      }

      // ── Rate-limit auth routes ──────────────────────────
      if (p.startsWith('/api/auth/') && request.method === 'POST' && p !== '/api/auth/logout') {
        const rl = await rateLimit(request, env, 'auth', 10, 300, undefined, cors);
        if (rl) return rl;
      }

      // ── CSRF: every state-changing request must come from our own pages ──
      // The session rides in a cookie the browser sends automatically, so
      // this runs on ALL POST/PUT/PATCH/DELETE, not a hand-picked list.
      if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method) && !CSRF_EXEMPT.has(p)) {
        const csrf = checkOrigin(request, cors);
        if (csrf) return csrf;
      }

      // ── Unauthenticated routes ──────────────────────────
      // Logout needs no valid session: it always clears the cookie, so a
      // stale or revoked cookie can still be removed.
      if (p === '/api/auth/logout'        && request.method === 'POST') return logout(cors);
      if (p === '/api/auth/signup'        && request.method === 'POST') return signup(request, env, cors);
      if (p === '/api/auth/login'         && request.method === 'POST') return login(request, env, cors);
      if (p === '/api/auth/hub-sso'       && request.method === 'POST') return hubSso(request, env, cors);
      if (p === '/api/auth/reset-request' && request.method === 'POST') return resetRequest(request, env, cors, ctx);
      if (p === '/api/auth/resend-verification' && request.method === 'POST') return resendVerification(request, env, cors);
      if (p === '/api/auth/reset-confirm' && request.method === 'POST') return resetConfirm(request, env, cors);
      if (p === '/api/auth/verify-code'   && request.method === 'POST') return verifyCode(request, env, cors);
      // Retired magic-link verify: answers with a page, never verifies (see verifyEmail).
      if (p === '/api/auth/verify-email'  && request.method === 'GET')  return verifyEmail(url, env);

      // ── Feedback widget relay (no login needed, same-origin POST only) ─
      if (p === '/api/feedback' && request.method === 'POST') {
        const fbLimited = await rateLimit(request, env, 'feedback', 5, 600, undefined, cors);
        if (fbLimited) return fbLimited;
        return feedback(request, env, cors);
      }

      // ── Pro token refresh proxy (no auth — the hub token IS the credential) ─
      if (p === '/api/pro-refresh' && request.method === 'POST') return proRefresh(request, env, cors);

      // ── Recap stats for the hub cron (secret-gated, never public) ─
      if (p === '/api/service/recap' && request.method === 'GET') return serviceRecap(url, request, env, cors);

      // ── Public Pro status (reads X-Hub-Pro header, no auth required) ─
      if (p === '/api/pro-status' && request.method === 'GET') {
        // With a session presented, the token only counts for that account.
        if (hubPro && hasSession(request)) {
          try { hubPro = await bindHubPro(hubPro, await requireAuth(request, env, cors), env); } catch { hubPro = null; }
        }
        return res({
          is_pro: hasProAccess(hubPro),
          // False on a copy with no Pro hub: the page then points Go Pro at the hosted version.
          pro_available: !!env.HUB_JWT_SECRET,
          // With a hub: where Go Pro goes (UPGRADE_URL, null = hide Go Pro) and an optional price line.
          upgrade_url: UPGRADE_BASE || null,
          pro_price_text: (env.HUB_JWT_SECRET && String(env.PRO_PRICE_TEXT || '').trim()) || null,
          // False when FEEDBACK_WEBHOOK_URL is blank: the page then hides the Feedback button.
          feedback_available: !!env.FEEDBACK_WEBHOOK_URL,
          email: hubPro?.email || null,
          pro_until: hubPro?.pro_until || null,
        }, 200, cors);
      }

      // ── Authenticated routes ────────────────────────────
      const uid = await requireAuth(request, env, cors);
      hubPro = await bindHubPro(hubPro, uid, env);

      // Per-user write rate limit: 120 writes per minute per user
      if (['POST','PUT','DELETE','PATCH'].includes(request.method)) {
        const userRL = await rateLimit(request, env, '', 120, 60, `user:${uid}:writes`, cors);
        if (userRL) return userRL;
      }

      // GDPR data export — authed only
      if (p === '/api/account/export' && request.method === 'GET') return exportAccount(uid, env, cors);

      // Subscriptions (graveyard)
      if (p === '/api/subscriptions' && request.method === 'GET')  return getSubs(uid, env, cors);
      if (p === '/api/subscriptions' && request.method === 'POST') return addSub(uid, request, env, hubPro, cors);

      const subMatch = p.match(/^\/api\/subscriptions\/([^/]+)$/);
      if (subMatch && request.method === 'PUT')    return updateSub(uid, subMatch[1], request, env, cors);
      if (subMatch && request.method === 'DELETE')  return deleteSub(uid, subMatch[1], env, cors);

      // Death Row
      if (p === '/api/death-row' && request.method === 'GET')  return getDeathRow(uid, env, cors);
      if (p === '/api/death-row' && request.method === 'POST') return addDeathRow(uid, request, env, hubPro, cors);

      const drMatch = p.match(/^\/api\/death-row\/([^/]+)$/);
      if (drMatch && request.method === 'DELETE') return deleteDeathRow(uid, drMatch[1], env, cors);

      const execMatch = p.match(/^\/api\/death-row\/([^/]+)\/execute$/);
      if (execMatch && request.method === 'POST') return executeDeathRow(uid, execMatch[1], request, env, hubPro, cors);

      // Renewal Watchlist (Pro-only)
      if (p === '/api/watchlist' && request.method === 'GET')    return getWatchlist(uid, env, hubPro, cors);
      if (p === '/api/watchlist' && request.method === 'POST')   return addWatchlist(uid, request, env, hubPro, cors);
      if (p === '/api/watchlist' && request.method === 'PUT')    return updateWatchlist(uid, request, env, hubPro, cors);
      if (p === '/api/watchlist' && request.method === 'DELETE') return deleteWatchlist(uid, request, env, hubPro, cors);

      // Profile & settings. /api/me is the boot check: the page can't read
      // the HttpOnly cookie, so one GET here decides "logged in?" (401 = no).
      if (p === '/api/me'            && request.method === 'GET')    return getProfile(uid, env, cors, request);
      if (p === '/api/profile'       && request.method === 'GET')    return getProfile(uid, env, cors, request);
      if (p === '/api/profile'       && request.method === 'PUT')    return updateProfile(uid, request, env, cors);
      if (p === '/api/auth/password' && request.method === 'PUT')    return changePassword(uid, request, env, cors);
      if (p === '/api/auth/account'  && request.method === 'DELETE') return deleteAccount(uid, request, env, cors);

      return res({ error: 'Not found' }, 404, cors);
    } catch (e) {
      if (e instanceof Response) return e;
      console.error(e.stack || e);
      return res({ error: 'Server error' }, 500, cors);
    }
  },

  // Scheduled: daily renewal warning emails (cron: "0 14 * * *")
  // Same daily run also purges expired rate-limit rows and dead tokens.
  async scheduled(event, env, ctx) {
    env = usableEnv(env);
    setAppBase(env);
    ctx.waitUntil(Promise.allSettled([sendRenewalWarnings(env), purgeExpired(env)]).then((results) => {
      // allSettled never rejects, so a job that threw would vanish without this.
      for (const r of results) {
        if (r.status === 'rejected') console.error('scheduled job failed', (r.reason && r.reason.stack) || r.reason);
      }
      return results;
    }));
  },
};

// ── Daily purge (retention) ─────────────────────────────────────────────────
// Expired rate-limit rows go the day they lapse. Reset and email-verification
// tokens are kept 7 days past expiry (used ones included), then deleted.
async function purgeExpired(env) {
  const now = Math.floor(Date.now() / 1000);
  const weekAgo = now - 7 * 86400;
  try {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM rate_limits WHERE expires_at < ?').bind(now),
      env.DB.prepare('DELETE FROM reset_tokens WHERE expires_at < ?').bind(new Date(weekAgo * 1000).toISOString()),
      env.DB.prepare('DELETE FROM email_verification_tokens WHERE expires_at < ?').bind(weekAgo),
      // Auth-mail ceiling rows ('verify:YYYY-MM-DD', 'reset:YYYY-MM-DD') share
      // daily_send_counts with the renewal budget. Its own cleanup compares
      // bare dates, so these prefixed rows are cleared here after 30 days.
      env.DB.prepare("DELETE FROM daily_send_counts WHERE (day LIKE 'verify:%' OR day LIKE 'reset:%') AND substr(day, instr(day, ':') + 1) < ?")
        .bind(new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10)),
    ]);
  } catch (e) {
    console.error('purgeExpired failed', e && e.message);
  }
}

// ── Response helper ─────────────────────────────────────────────────────────

// CORS headers are passed explicitly per-request to avoid module-level mutable
// state racing between concurrent requests in the same Worker isolate.
function res(data, status = 200, cors = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' },
  });
}

// Every handler that reads a JSON body goes through here. A malformed body
// used to escape a bare request.json() as a 500, which also fired the 5xx
// alert beacon (anyone could trigger an alert by POSTing garbage). Now it is a 400.
// The body is read as text and capped at 64 KB before parsing: the
// Content-Length check in handle() can't see a chunked body with no length.
// A JSON null/array/number reads as null too, so `(await readJson(r)) || {}`
// never destructures null (that TypeError was a 500 + alert email).
const MAX_BODY_CHARS = 65536;
async function readJson(request) {
  let text;
  try { text = await request.text(); } catch { return null; }
  if (typeof text !== 'string' || text.length > MAX_BODY_CHARS) return null;
  let body;
  try { body = JSON.parse(text); } catch { return null; }
  return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
}

// Security event log (Workers Logs, [observability] in wrangler.toml). One
// JSON line per auth event. Never a raw password, token, email or IP: the
// email and IP are hashed with a server-side pepper so the log can link
// events for one account or one address without holding either.
async function peppered(env, kind, value) {
  if (!value) return null;
  return (await sha256Hex(`${env.JWT_SECRET || ''}:${kind}:${value}`)).slice(0, 24);
}
async function secLog(env, request, type, { uid = null, email = null } = {}) {
  try {
    const ip = request?.headers?.get('CF-Connecting-IP') || '';
    console.log(JSON.stringify({
      evt: 'auth', type,
      ...(uid ? { uid } : {}),
      ...(email ? { email_hash: await peppered(env, 'email', String(email).toLowerCase()) } : {}),
      ip_hash: await peppered(env, 'ip', ip),
    }));
  } catch { /* logging must never break a request */ }
}
const badBody = (cors) => res({ error: 'Invalid request body.' }, 400, cors);

// ── Email footer ────────────────────────────────────────────────────────────
// Every email this Worker sends ends with the same footer. Put your own company
// name and postal address here (many countries require one in email).
const EMAIL_SENDER_LINE = 'YOUR COMPANY NAME · YOUR BUSINESS ADDRESS';
const emailPrivacyUrl = () => `${APP_BASE}/legal/privacy`;
const emailFooterText = () => `${EMAIL_SENDER_LINE} · Privacy: ${emailPrivacyUrl()}`;
function emailFooterHtml(color = '#888', rule = '#3A2F33') {
  return `<p style="font-size:12px;color:${color};margin-top:24px;text-align:center;border-top:1px solid ${rule};padding-top:12px;line-height:1.5">${EMAIL_SENDER_LINE.replace(' · ', ' &middot; ')} &middot; Privacy: <a href="${emailPrivacyUrl()}" style="color:${color}">${emailPrivacyUrl()}</a></p>`;
}

// ── Rate Limiting ───────────────────────────────────────────────────────────

// Email verification: send a 6-digit CODE, not a magic link. A long tokenized
// verify-link to a young domain reads as phishing to Gmail, which accepts then
// silently drops it (Resend shows "delivered" but it never reaches the inbox).
// A code has no clickable credential link, so it lands normally. Store only the
// SHA-256 hash so a DB read can't replay the code.
// Returns true only when Resend accepted the message, so callers can tell the
// user when nothing went out instead of promising an inbox.
async function sendVerificationEmail(userId, email, env) {
  const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
  // USER-SCOPED hash: `token` is the table's PRIMARY KEY, so a bare sha256(code)
  // collides whenever two users draw the same 6-digit code → second INSERT throws
  // a PK violation → non-JSON 500 on signup. Salting with the user id makes every
  // stored hash unique per user.
  const codeHash = await sha256Hex(userId + ':' + code);
  const now = Math.floor(Date.now() / 1000);
  // The account is already created at this point; a DB error storing the code must
  // never 500 the signup. Log and bail — the user can just resend the code.
  try {
    // One live code per user: clear any prior unused codes first.
    await env.DB.prepare('DELETE FROM email_verification_tokens WHERE user_id=? AND used=0').bind(userId).run();
    // A fresh code starts with a fresh 5-miss count. The 20-a-day miss ceiling
    // stays: resetting it here would give unlimited guesses through Resend code.
    await env.DB.prepare('DELETE FROM rate_limits WHERE key = ?').bind(`verify-miss:${userId}`).run();
    await env.DB.prepare('INSERT INTO email_verification_tokens (token, user_id, expires_at, used, created_at) VALUES (?, ?, ?, 0, ?)')
      .bind(codeHash, userId, now + 1800, now).run(); // 30-minute window
  } catch (e) {
    console.error('sendVerificationEmail: DB store failed', e.message);
    return false;
  }
  if (!env.RESEND_API_KEY) {
    // Local testing only: DEV_LOG_CODES=true prints the code when no email key is set.
    if (env.DEV_LOG_CODES === 'true') { console.log('[dev] verify code for', email, code); return true; }
    console.error('sendVerificationEmail: RESEND_API_KEY not set'); return false;
  }
  // Awaited so the send completes before the request ends (un-awaited fetches
  // get cancelled when the Worker returns). Errors logged, not thrown.
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: env.FROM_EMAIL || 'Subscription Graveyard <onboarding@resend.dev>',
        to: email,
        subject: `Your Subscription Graveyard code is ${code}`,
        text: `Your Subscription Graveyard verification code is: ${code}\n\nEnter it on the sign-in screen to finish setting up your account. It expires in 30 minutes.\n\nIf you didn't sign up for Subscription Graveyard, ignore this email.\n\n${emailFooterText()}`,
        html: emailLayout(EMAIL_THEME, {
          title: 'Your verification code',
          body: emailPara(EMAIL_THEME, 'Enter this code on the sign-in screen to finish setting up your Subscription Graveyard account:')
            + emailCode(EMAIL_THEME, code)
            + emailSmall(EMAIL_THEME, "This code expires in 30 minutes. If you didn't sign up for Subscription Graveyard, ignore this email."),
          footer: emailFooterHtml(EMAIL_THEME.muted, EMAIL_THEME.line),
        })
      })
    });
    if (!r.ok) { console.error('sendVerificationEmail: Resend FAIL', r.status, await r.text()); return false; }
    return true;
  } catch (e) { console.error('sendVerificationEmail threw', e.message); return false; }
}

const BAD_CODE_MSG = "That code is invalid or expired. Already verified? Log in instead.";

// POST /api/auth/verify-code  body: { email, code, password } — finish email
// verification with the 6-digit code. Rate-limited (codes are low-entropy) and
// single-use. Sets the session cookie on success so the user is logged straight in.
// The password is required: signup on an unverified row
// replaces its password, so without this check someone could re-sign-up on the
// owner's address right after them and the owner's code would verify an account
// whose password the other person chose.
async function verifyCode(request, env, cors) {
  const { email, code, password } = (await readJson(request)) || {};
  const cleanEmail = String(email || '').trim().toLowerCase();
  const cleanCode = String(code || '').replace(/\D/g, '');
  if (!isValidEmail(cleanEmail) || cleanCode.length !== 6) return res({ error: 'Enter the 6-digit code from your email.' }, 400, cors);
  if (typeof password !== 'string' || !password || password.length > 200) {
    return res({ error: 'Enter your password along with the code.' }, 400, cors);
  }
  // Throttle guesses: 8/min per email + 30/min per IP. 6-digit space + this = safe.
  const emailLimited = await rateLimit(request, env, 'verify-code', 8, 60, `verify-code:${cleanEmail}`, cors);
  if (emailLimited) return emailLimited;
  const ipLimited = await rateLimit(request, env, 'verify-code-ip', 30, 60, null, cors);
  if (ipLimited) return ipLimited;

  // Unknown email, already-verified email and wrong code all get this same
  // 400. A distinct "already verified" 409 told anyone which emails had
  // accounts.
  const badCode = () => res({ error: BAD_CODE_MSG }, 400, cors);
  const user = await env.DB.prepare('SELECT id, email, email_verified, newsletter_consent, token_version, password_hash FROM users WHERE email = ?').bind(cleanEmail).first();
  if (!user) return badCode();
  // Already verified → DON'T issue a session. Minting a token here just because
  // the email is verified would be a password-free login bypass. A session is
  // only issued on a real code match below.
  if (user.email_verified) return badCode();
  // Wrong-code budget, charged only on a miss against a real unverified account,
  // so junk requests naming someone's address can't use it up. 20 misses a day
  // per account stops slow guessing from many IPs. Over budget answers the same
  // generic 400, so it reveals nothing about the account.
  const nowS = Math.floor(Date.now() / 1000);
  const dayKey = `verify-miss-day:${user.id}`;
  const misses = await env.DB.prepare('SELECT COUNT(*) as c FROM rate_limits WHERE key = ? AND created_at > ?').bind(dayKey, nowS - 86400).first();
  if (Number(misses?.c || 0) >= 20) return badCode();
  // New codes are stored user-scoped (sha256(userId+':'+code)). Codes emailed
  // before this fix were hashed bare, so accept the legacy hash too during the
  // transition window.
  const codeHash = await sha256Hex(user.id + ':' + cleanCode);
  const legacyHash = await sha256Hex(cleanCode);
  const now = Math.floor(Date.now() / 1000);
  // Scope the match to THIS user (user_id AND code hash). A bare hash lookup
  // collides across users who happen to share a 6-digit code.
  const row = await env.DB.prepare('SELECT token FROM email_verification_tokens WHERE user_id=? AND token IN (?,?) AND used=0 AND expires_at > ?')
    .bind(user.id, codeHash, legacyHash, now).first();
  if (!row) {
    await hitCount(env, dayKey, 86400);
    // 5 misses burn the current code. The real owner just taps Resend code.
    if ((await hitCount(env, `verify-miss:${user.id}`, 1800)) >= 5) {
      await env.DB.prepare('UPDATE email_verification_tokens SET used=1 WHERE user_id=? AND used=0').bind(user.id).run();
    }
    return badCode();
  }
  // The code proves the inbox, the password proves this is whoever set the
  // row's credentials. Only a real code match reaches this, so it can't be
  // used to test passwords without the code. No verify, no session on mismatch.
  if (!user.password_hash || !(await checkPw(password, user.password_hash))) {
    return res({ error: "That password doesn't match this account." }, 400, cors);
  }
  // Atomic finish: verify only if the row is still exactly what was just
  // checked (still unverified, same password hash and token_version) AND the
  // matched code is still unused. A signup that swapped the password, or a
  // second request racing this one, changes 0 rows and gets the generic 400.
  const out = await env.DB.batch([
    env.DB.prepare(
      'UPDATE users SET email_verified=1, verified_at=? WHERE id=? AND email_verified=0 AND password_hash=? AND COALESCE(token_version,0)=? ' +
      'AND EXISTS (SELECT 1 FROM email_verification_tokens WHERE user_id=? AND token=? AND used=0 AND expires_at > ?)'
    ).bind(new Date().toISOString(), user.id, user.password_hash, user.token_version ?? 0, user.id, row.token, now),
    env.DB.prepare('UPDATE email_verification_tokens SET used=1 WHERE user_id=? AND used=0').bind(user.id),
  ]);
  if (!out?.[0]?.meta?.changes || !out?.[1]?.meta?.changes) return badCode();
  const token = await mintSession(user.id, user.token_version ?? 0, env);
  const hubProToken = await hubProLookup(user.email, env);
  return resWithSession({ ...(hubProToken ? { hub_pro_token: hubProToken } : {}), user: { id: user.id, email: user.email, newsletter_consent: user.newsletter_consent === 1 } }, token, cors);
}

// GET /api/auth/verify-email: the old magic-link route. Links stopped going out
// when verification switched to 6-digit codes, and every link
// expired long ago. It no longer verifies anything: a link that verified an
// unverified row without the password would reopen an account-takeover race (a
// re-signup replaces that row's password). It just points people to log in.
async function verifyEmail(url, env) {
  const base = APP_BASE || '/';
  return new Response(`<!DOCTYPE html><html><head><title>Link expired</title><meta name="viewport" content="width=device-width,initial-scale=1"/><style>body{font-family:-apple-system,sans-serif;background:#1C1719;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;padding:20px}a{color:#6EDBA8}h1{color:#FF6B57}</style></head><body><div><h1>This link has expired</h1><p>Log in with your email and password and we'll send you a fresh 6-digit code.</p><p><a href="${base}">Go to Subscription Graveyard</a></p></div></body></html>`, { headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-store' } });
}

// Record THEN count, in one D1 batch (one transaction). Counting first and
// inserting after let a burst of parallel requests all read "under the cap"
// before any of them was recorded. Returns the
// count INCLUDING this hit, so callers block on `> max`.
async function hitCount(env, key, windowSecs) {
  const now = Math.floor(Date.now() / 1000);
  const [, counted] = await env.DB.batch([
    env.DB.prepare('INSERT INTO rate_limits (key, created_at, expires_at) VALUES (?, ?, ?)').bind(key, now, now + windowSecs),
    env.DB.prepare('SELECT COUNT(*) as c FROM rate_limits WHERE key = ? AND created_at > ?').bind(key, now - windowSecs),
  ]);
  return Number(counted?.results?.[0]?.c ?? 0);
}

// A correct password hands back the try it reserved, so only wrong ones count.
async function returnTry(env, emailLower) {
  await env.DB.prepare('DELETE FROM rate_limits WHERE rowid IN (SELECT rowid FROM rate_limits WHERE key = ? ORDER BY created_at DESC LIMIT 1)').bind(`failed-login:${emailLower}`).run();
}
// Password re-checks inside the app (change password, delete account) share the
// login lockout, so a stolen session can't be used to guess the password.
async function recheckPassword(env, emailLower, password, hash) {
  if ((await hitCount(env, `failed-login:${emailLower}`, LOGIN_WINDOW)) > LOGIN_TRIES) return false;
  if (!hash || !(await checkPw(password, hash))) return false;
  await returnTry(env, emailLower);
  return true;
}

// Account lockout: 5 wrong passwords per email per 15 min. Each try is reserved
// BEFORE the password check, and a correct password hands back only its own
// reservation, so only wrong tries count.
const LOGIN_TRIES = 5;
const LOGIN_WINDOW = 900;

// Called only when an email is about to go to a real account, so junk requests
// for an unknown address never touch anyone's budget. Charges the per-address
// cap (record-then-count, one batch), then the daily ceiling (one atomic
// upsert). False = skip the send. The caller answers exactly as if it had
// sent, so a cap never reveals an account.
async function mayMail(env, kind, emailLower, max) {
  if ((await hitCount(env, `${kind}-email:${emailLower}`, MAIL_PER_ADDRESS_WINDOW)) > MAIL_PER_ADDRESS) {
    console.log(JSON.stringify({ evt: 'mail_skipped', kind, reason: 'per_address_cap' }));
    return false;
  }
  if (!(await withinMailCeiling(env, kind, max))) {
    console.log(JSON.stringify({ evt: 'mail_skipped', kind, reason: 'daily_ceiling' }));
    return false;
  }
  return true;
}

// App-wide daily ceiling for one kind of auth mail. Reuses the renewal
// budget's daily_send_counts table under a prefixed key ('verify:2026-11-02'),
// so the renewal row (bare date) is never touched. One atomic upsert: two
// requests at once can't both read the same count (the charge and the room
// check are the same statement). Returns true while today's count is within
// `max`. Only called right before a real send (mayMail). Fails OPEN on a D1 error (logged): the per-IP and
// per-address limits, which fail closed, still stand, and a missing row must
// never lock every user out of sign-up or reset.
async function withinMailCeiling(env, kind, max) {
  const day = `${kind}:${new Date().toISOString().slice(0, 10)}`;
  try {
    const row = await env.DB.prepare(
      'INSERT INTO daily_send_counts (day, count) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET count = count + 1 RETURNING count'
    ).bind(day).first();
    return Number(row?.count || 0) <= max;
  } catch (e) {
    console.error('withinMailCeiling failed (allowing send)', kind, e && e.message);
    return true;
  }
}

// Per-IP keys store a peppered hash of the address, never the raw IP. The
// swap resets in-flight per-IP counters once (old raw-IP rows expire on their
// own within 15 minutes); per-account keys are unchanged.
async function rateLimit(request, env, prefix, maxAttempts, windowSecs, customKey, cors = {}) {
  const key = customKey || `${prefix}:ip:${await peppered(env, 'ip', request.headers.get('CF-Connecting-IP') || 'unknown')}`;
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare('DELETE FROM rate_limits WHERE expires_at < ?').bind(now).run();
  if ((await hitCount(env, key, windowSecs)) > maxAttempts) {
    return res({ error: 'Too many attempts. Please try again later.' }, 429, cors);
  }
  return null;
}

// ── Crypto: PBKDF2 password hashing ─────────────────────────────────────────

async function hashPw(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = [...salt].map(b => b.toString(16).padStart(2, '0')).join('');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  const hashHex = [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
  return `pbkdf2:${saltHex}:${hashHex}`;
}

async function checkPw(pw, stored) {
  const [, saltHex, hashHex] = stored.split(':');
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('') === hashHex;
}

// ── Crypto: HS256 JWT ────────────────────────────────────────────────────────

function b64(str) { return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); }
function unb64(str) { const p = str.replace(/-/g, '+').replace(/_/g, '/'); return atob(p + '='.repeat((4 - p.length % 4) % 4)); }

function requireSecret(secret) {
  // Refuse to sign or check logins without a real secret. A missing one would turn
  // into the word 'undefined', and anyone could forge a session.
  if (typeof secret !== 'string' || secret.length < 32) throw new Error('JWT_SECRET must be set to a random string of 32+ characters.');
}

async function makeJWT(payload, secret) {
  requireSecret(secret);
  const h = b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const p = b64(JSON.stringify(payload));
  const data = `${h}.${p}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return `${data}.${b64(String.fromCharCode(...new Uint8Array(sig)))}`;
}

// A malformed token (bad base64 or JSON) is just an invalid token. It must get a
// 401, not a 500: every 500 fires the optional alert webhook.
async function verifyJWT(token, secret) {
  try { return await verifyJWTStrict(token, secret); } catch { return null; }
}

async function verifyJWTStrict(token, secret) {
  requireSecret(secret);
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify('HMAC', key,
    Uint8Array.from(unb64(s), c => c.charCodeAt(0)),
    new TextEncoder().encode(`${h}.${p}`)
  );
  if (!valid) return null;
  const payload = JSON.parse(unb64(p));
  // A missing exp compared as undefined < n is false, which would make such a
  // token immortal. Every token this worker mints has one; require it.
  if (typeof payload.exp !== 'number' || payload.exp < Date.now() / 1000) return null;
  return payload;
}

// ── Auth middleware ──────────────────────────────────────────────────────────

async function requireAuth(request, env, cors = {}) {
  // Session cookie only. The old localStorage `Authorization: Bearer` path
  // is gone, so a Bearer header alone is a 401.
  const cookieJwt = readCookie(request, SESSION_COOKIE);
  if (!cookieJwt) throw res({ error: 'Unauthorized' }, 401, cors);
  const payload = await verifyJWT(cookieJwt, env.JWT_SECRET);
  if (!payload || typeof payload.sub !== 'string') throw res({ error: 'Invalid or expired token' }, 401, cors);
  // Verify token version matches (invalidates old tokens after password change)
  if (payload.tv !== undefined) {
    const user = await env.DB.prepare('SELECT token_version FROM users WHERE id=?').bind(payload.sub).first();
    if (!user || (user.token_version ?? 0) !== payload.tv) throw res({ error: 'Token revoked' }, 401, cors);
  }
  return payload.sub;
}

// POST /api/auth/logout: clears the cookie. Subscription Graveyard keeps no
// server-side session list, so there is nothing else to revoke here; a
// password change or reset still ends every session via token_version.
function logout(cors) {
  const r = res({ ok: true }, 200, cors);
  r.headers.append('Set-Cookie', clearSessionCookie());
  return r;
}

// ── Auth routes ──────────────────────────────────────────────────────────────

async function signup(request, env, cors) {
  const reqBody = await readJson(request);
  if (!reqBody) return badBody(cors);
  const { email, password, newsletter_consent = false } = reqBody;
  const emailLower = String(email || '').trim().toLowerCase();
  if (!isValidEmail(emailLower)) {
    return res({ error: 'A valid email is required.' }, 400, cors);
  }
  if (!isValidPassword(password)) {
    return res({ error: 'Password must be 10-200 characters.' }, 400, cors);
  }
  // Mail caps (mayMail) are charged only when a code is really about to go
  // out. A capped send is skipped silently and the answer is the normal one,
  // so it never reveals an account. They can use Resend code later.
  const existing = await env.DB.prepare('SELECT id, email_verified FROM users WHERE email = ?').bind(emailLower).first();
  if (existing) {
    if (!existing.email_verified) {
      // Nobody has proved they own this address yet. The newest signer-up
      // takes over the credentials and gets a fresh code; entering it is what
      // proves ownership. Before this, a row squatted by someone else kept ITS
      // password after the real owner verified (pre-hijack account takeover).
      // The password is swapped only when a fresh code really went out. A
      // capped or failed send leaves the row alone: otherwise anyone could
      // re-submit signup for an address and quietly break the code its owner
      // is still holding (their password would stop matching).
      const hash = await hashPw(password);
      let sent = true;
      if (await mayMail(env, 'verify', emailLower, VERIFY_MAIL_DAILY)) {
        sent = await sendVerificationEmail(existing.id, emailLower, env);
        if (sent) {
          await env.DB.prepare('UPDATE users SET password_hash=?, token_version=COALESCE(token_version,0)+1 WHERE id=? AND email_verified=0').bind(hash, existing.id).run();
        }
      }
      return res({ ok: true, awaiting_verification: true, email: emailLower, email_sent: sent, message: 'Check your inbox to verify your email before logging in.' }, 200, cors);
    }
    // Don't leak account existence. Burn PBKDF2 cycles to match timing and
    // answer with the exact shape of a fresh signup.
    await hashPw(password);
    return res({ ok: true, awaiting_verification: true, email: emailLower, email_sent: true, message: 'Check your inbox to verify your email before logging in.' }, 200, cors);
  }

  const id = crypto.randomUUID();
  const hash = await hashPw(password);
  const now = new Date().toISOString();
  await env.DB.prepare(
    'INSERT INTO users (id,email,password_hash,newsletter_consent,newsletter_consent_at,currency,created_at) VALUES (?,?,?,?,?,?,?)'
  ).bind(id, emailLower, hash, newsletter_consent ? 1 : 0, newsletter_consent ? now : null, 'USD', now).run();

  const emailSent = (await mayMail(env, 'verify', emailLower, VERIFY_MAIL_DAILY))
    ? await sendVerificationEmail(id, emailLower, env) : true;
  // Optional operator ping on each signup (SIGNUP_WEBHOOK_URL). Off when unset.
  await notifySignup(env, 'subscription-graveyard', emailLower, newsletter_consent === true);

  return res({ ok: true, awaiting_verification: true, email: emailLower, email_sent: emailSent, message: 'Check your inbox to verify your email before logging in.' }, 200, cors);
}

async function resendVerification(request, env, cors) {
  const { email } = (await readJson(request)) || {};
  if (!email) return res({ ok: true }, 200, cors);
  const emailLower = String(email).trim().toLowerCase();
  if (!isValidEmail(emailLower)) return res({ ok: true }, 200, cors);
  const emailLimited = await rateLimit(request, env, 'verify-resend', 1, 60, `verify-resend:${emailLower}`, cors);
  if (emailLimited) return emailLimited;
  const ipLimited = await rateLimit(request, env, 'verify-resend-ip', 10, 60, null, cors);
  if (ipLimited) return ipLimited;
  const user = await env.DB.prepare('SELECT id, email_verified FROM users WHERE email = ?').bind(emailLower).first();
  // An unknown or already-verified email still reads as sent (no enumeration);
  // only a real send that Resend refused reports email_sent:false.
  let emailSent = true;
  // Shares the 'verify' per-address count and daily ceiling with signup. A
  // capped send is skipped and still reads as sent.
  if (user && !user.email_verified && await mayMail(env, 'verify', emailLower, VERIFY_MAIL_DAILY)) {
    emailSent = await sendVerificationEmail(user.id, emailLower, env);
  }
  return res({ ok: true, email_sent: emailSent, message: 'If that account exists and needs verification, an email has been sent.' }, 200, cors);
}

// Optional signup notification to the operator. Set SIGNUP_WEBHOOK_URL and
// SIGNUP_WEBHOOK_SECRET to get a POST on each signup (the secret rides in the
// X-Signup-Secret header). Must be awaited: an un-awaited fetch is cancelled when
// the response returns.
async function notifySignup(env, appName, email, appNewsletterConsent) {
  if (!env.SIGNUP_WEBHOOK_URL || !env.SIGNUP_WEBHOOK_SECRET) return;
  await fetch(env.SIGNUP_WEBHOOK_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Signup-Secret': env.SIGNUP_WEBHOOK_SECRET,
    },
    body: JSON.stringify({
      app_name: appName,
      email: (email || '').toLowerCase(),
      app_newsletter_consent: !!appNewsletterConsent,
      ss_newsletter_consent: false,
      timestamp: new Date().toISOString(),
    }),
  }).catch(() => {});
}

async function login(request, env, cors) {
  const reqBody = await readJson(request);
  if (!reqBody) return badBody(cors);
  const { email, password } = reqBody;
  const emailLower = String(email || '').trim().toLowerCase();
  // Length validation runs BEFORE dummy-hash so a 10MB body can't burn PBKDF2 cycles.
  if (!isValidEmail(emailLower) || !isValidPassword(password)) {
    return res({ error: 'Invalid email or password' }, 401, cors);
  }
  const DUMMY_HASH = 'pbkdf2:00000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000';
  // Account lockout: 5 tries per email in 15 min, reserved before the password
  // check so parallel guesses can't slip past. Generic error to not leak lockout state.
  if ((await hitCount(env, `failed-login:${emailLower}`, LOGIN_WINDOW)) > LOGIN_TRIES) {
    await checkPw(password, DUMMY_HASH);
    await secLog(env, request, 'login_fail', { email: emailLower });
    return res({ error: 'Invalid email or password' }, 401, cors);
  }
  // Explicit column list, not SELECT *: the login path is the last place a
  // future sensitive column should be able to ride along by accident. These
  // six are every field this function touches.
  const user = await env.DB.prepare(
    'SELECT id, email, password_hash, email_verified, token_version, newsletter_consent FROM users WHERE email = ?'
  ).bind(emailLower).first();
  // Constant-time compare: always run PBKDF2 even if user not found, so attacker can't time-enumerate emails
  const storedHash = user?.password_hash || DUMMY_HASH;
  const pwValid = await checkPw(password, storedHash);
  if (!user || !pwValid) {
    await secLog(env, request, 'login_fail', { email: emailLower });
    return res({ error: 'Invalid email or password' }, 401, cors);
  }
  // A correct password gives back only its own reserved try. Wrong tries keep
  // counting, so the owner logging in never resets someone else's guessing budget.
  await returnTry(env, emailLower);
  if (!user.email_verified) {
    return res({ error: 'Please verify your email before logging in.', code: 'email_not_verified', email: user.email }, 403, cors);
  }
  const token = await mintSession(user.id, user.token_version, env);
  await secLog(env, request, 'login_ok', { uid: user.id });
  const hubProToken = await hubProLookup(user.email, env);
  return resWithSession({ ...(hubProToken ? { hub_pro_token: hubProToken } : {}), user: { id: user.id, email: user.email, newsletter_consent: user.newsletter_consent === 1 } }, token, cors);
}

// Pro follows the account, not the browser. At login (and any other
// session-minting response), ask the hub whether this email has Pro and carry
// a fresh hub token back — otherwise a new device/cleared storage stays free
// until the user thinks to relaunch from the hub. Never blocks login: any
// failure → null.
async function hubProLookup(email, env) {
  // Optional: PRO_LOOKUP_URL + HUB_LOOKUP_SECRET connect a Pro hub. Unset = free plan for everyone.
  if (!env.PRO_LOOKUP_URL || !env.HUB_LOOKUP_SECRET) return null;
  try {
    const r = await fetch(env.PRO_LOOKUP_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': env.HUB_LOOKUP_SECRET },
      body: JSON.stringify({ email, app: 'subscription-graveyard' }),
      signal: AbortSignal.timeout(4000),
    });
    if (!r.ok) return null;
    const j = await r.json().catch(() => null);
    return j && j.pro === true && typeof j.token === 'string' ? j.token : null;
  } catch (e) {
    console.error('hubProLookup failed', e.message);
    return null;
  }
}

// Pro check for the renewal-warning cron. Three answers, so the cron can tell
// a clear "not Pro" from a lookup that just failed:
//   'pro'      the hub says this email has Pro now
//   'not_pro'  the hub answered and said no
//   'unknown'  no lookup secret, timeout, network error or a non-2xx answer
async function hubProState(email, env) {
  const secret = env.HUB_LOOKUP_SECRET;
  if (!env.PRO_LOOKUP_URL || !secret) return 'unknown';
  try {
    const r = await fetch(env.PRO_LOOKUP_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': secret },
      body: JSON.stringify({ email, app: 'subscription-graveyard' }),
      signal: AbortSignal.timeout(3000),
    });
    if (!r.ok) return 'unknown';
    const j = await r.json().catch(() => null);
    if (j && j.pro === true) return 'pro';
    if (j && j.pro === false) return 'not_pro';
    return 'unknown';
  } catch (e) {
    console.error('hubProState failed', e.message);
    return 'unknown';
  }
}

// One hub lookup per distinct account in the send plan, in plan order, at most
// PRO_LOOKUPS_PER_RUN accounts and PRO_LOOKUP_CONCURRENCY at a time. Returns
// Map(user_id -> state). Accounts past the cap get no entry.
const PRO_LOOKUPS_PER_RUN = 300;
const PRO_LOOKUP_CONCURRENCY = 10;
async function proStateForUsers(env, plan) {
  const out = new Map();
  // No Pro hub connected at all: nobody can have Pro here, so nobody gets a warning.
  if (!env.PRO_LOOKUP_URL && !env.HUB_JWT_SECRET) return out;
  const users = [];
  const seen = new Set();
  for (const row of plan) {
    if (seen.has(row.user_id)) continue;
    seen.add(row.user_id);
    users.push({ id: row.user_id, email: row.item.email });
    if (users.length >= PRO_LOOKUPS_PER_RUN) break;
  }
  for (let i = 0; i < users.length; i += PRO_LOOKUP_CONCURRENCY) {
    const batch = users.slice(i, i + PRO_LOOKUP_CONCURRENCY);
    const states = await Promise.all(batch.map(u => hubProState(u.email, env)));
    batch.forEach((u, k) => out.set(u.id, states[k]));
  }
  return out;
}

// Hub SSO: hub passes us a verified Pro JWT; we verify locally with HUB_JWT_SECRET,
// find-or-create the user, and mint a Graveyard session JWT. Auto-created users get
// a random sentinel password_hash (can never PBKDF2-match) — they enable password
// login later via the forgot-password flow.
// A password hash no password can ever match. Used for rows the hub owns:
// SSO-created users, and pre-registered rows the hub just proved belong to
// someone else. The real owner sets a password through the reset flow.
function sentinelHash() {
  const randSalt = [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, '0')).join('');
  const randHash = [...crypto.getRandomValues(new Uint8Array(32))].map(b => b.toString(16).padStart(2, '0')).join('');
  return `pbkdf2:${randSalt}:${randHash}`;
}

async function hubSso(request, env, cors) {
  const body = (await readJson(request)) || {};
  const hubJwt = body.hub_pro_jwt;
  if (!hubJwt || typeof hubJwt !== 'string' || hubJwt.length > 4096) {
    return res({ error: 'Missing hub token' }, 400, cors);
  }
  if (!env.HUB_JWT_SECRET) return res({ error: 'Hub sign-in is off on this server.' }, 404, cors);
  const payload = await verifyHubPro(hubJwt, env.HUB_JWT_SECRET);
  if (!payload || !payload.email) {
    return res({ error: 'Invalid or expired hub token' }, 401, cors);
  }
  const emailLower = String(payload.email).trim().toLowerCase();
  if (!isValidEmail(emailLower)) {
    return res({ error: 'Invalid email in hub token' }, 400, cors);
  }
  let user = await env.DB.prepare(
    'SELECT id, email, newsletter_consent, token_version, email_verified FROM users WHERE email = ?'
  ).bind(emailLower).first();

  // Hub already verified — bump any unverified existing user to verified. That
  // row's password was set by whoever signed up first, who never proved they
  // own the address, so it is replaced with a sentinel and token_version is
  // bumped to end any session they hold. Before this, a pre-registered row
  // kept the squatter's password after the real owner arrived through SSO
  // (pre-hijack account takeover).
  if (user && !user.email_verified) {
    await env.DB.prepare('UPDATE users SET email_verified=1, verified_at=COALESCE(verified_at, ?), password_hash=?, token_version=COALESCE(token_version,0)+1 WHERE id=?')
      .bind(new Date().toISOString(), sentinelHash(), user.id).run();
    user.token_version = (user.token_version ?? 0) + 1;
  }

  if (!user) {
    const id = crypto.randomUUID();
    const sentinel = sentinelHash();
    const now = new Date().toISOString();
    await env.DB.prepare(
      'INSERT INTO users (id, email, password_hash, newsletter_consent, currency, created_at, email_verified, verified_at) VALUES (?, ?, ?, 0, ?, ?, 1, ?)'
    ).bind(id, emailLower, sentinel, 'USD', now, now).run();
    // Auto-created via hub SSO: no newsletter consent yet. Webhook is consent-gated, so we skip.
    user = { id, email: emailLower, newsletter_consent: 0, token_version: 0 };
  }

  const token = await mintSession(user.id, user.token_version, env);
  return resWithSession({
    user: { id: user.id, email: user.email, newsletter_consent: user.newsletter_consent === 1 },
  }, token, cors);
}

async function resetRequest(request, env, cors, ctx) {
  const { email } = (await readJson(request)) || {};
  const emailLower = String(email || '').trim().toLowerCase();
  // Identical response shape regardless of email validity / existence — no enumeration.
  if (!isValidEmail(emailLower)) return res({ success: true }, 200, cors);
  const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(emailLower).first();
  if (!user) return res({ success: true }, 200, cors);
  // Per-address cap (3 per 15 min) and daily ceiling, charged only for a real
  // send. Every outcome is the same generic success, so none reveals an account.
  if (!(await mayMail(env, 'reset', emailLower, RESET_MAIL_DAILY))) return res({ success: true }, 200, cors);

  // Store the SHA-256 of the token at rest; mail the raw token.
  const rawToken = [...crypto.getRandomValues(new Uint8Array(32))].map(b => b.toString(16).padStart(2, '0')).join('');
  const tokenHash = await sha256Hex(rawToken);
  const expires = new Date(Date.now() + 3600000).toISOString();
  await env.DB.prepare('INSERT OR REPLACE INTO reset_tokens (token,user_id,expires_at,used) VALUES (?,?,?,0)')
    .bind(tokenHash, user.id, expires).run();

  if (!env.RESEND_API_KEY && env.DEV_LOG_CODES === 'true') console.log('[dev] reset link:', `${APP_BASE}/reset/${rawToken}`);
  if (env.RESEND_API_KEY) {
    // /reset/<token>, NOT ?reset=<token>. Mail transfer agents quoted-printable
    // encode the body, and "=" is the QP escape character: the link arrives with
    // the "=" and the next two characters replaced by a control byte, so the
    // token is corrupted and a locked-out user can never get back in. Proven on
    // a real delivered email:
    //   sent    .../?reset=1a2b00f74d...
    //   arrived ...?reset\x041a00f74d...
    // A path segment has no "=" for QP to eat.
    const resetUrl = `${APP_BASE}/reset/${rawToken}`;
    // Sent after the response (waitUntil) so a real account and an unknown
    // address answer in the same time. Timing used to tell them apart.
    const send = fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: env.FROM_EMAIL || 'Subscription Graveyard <onboarding@resend.dev>',
        to: emailLower,
        subject: 'Reset your Subscription Graveyard password',
        text: `Reset your Subscription Graveyard password\n\nOpen this link to reset your password. It expires in 1 hour.\n${resetUrl}\n\nIf you didn't request this, ignore this email.\n\n${emailFooterText()}`,
        html: emailLayout(EMAIL_THEME, {
          title: 'Reset your password',
          body: emailPara(EMAIL_THEME, 'Tap below to reset your Subscription Graveyard password. This link expires in 1 hour.')
            + emailButton(EMAIL_THEME, resetUrl, 'Reset password')
            + emailSmall(EMAIL_THEME, "If you didn't request this, ignore this email."),
          footer: emailFooterHtml(EMAIL_THEME.muted, EMAIL_THEME.line),
        })
      })
    }).catch(e => console.error('reset mail failed', e && e.message));
    if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(send); else await send;
  }
  return res({ success: true }, 200, cors);
}

async function resetConfirm(request, env, cors) {
  const reqBody = await readJson(request);
  if (!reqBody) return badBody(cors);
  const { token, password } = reqBody;
  if (!token || typeof token !== 'string' || token.length > 256) {
    return res({ error: 'Invalid or expired reset link' }, 400, cors);
  }
  if (!isValidPassword(password)) {
    return res({ error: 'Password must be 10-200 characters.' }, 400, cors);
  }
  const tokenHash = await sha256Hex(token);
  const rt = await env.DB.prepare('SELECT * FROM reset_tokens WHERE token=? AND used=0').bind(tokenHash).first();
  if (!rt || new Date(rt.expires_at) < new Date()) {
    return res({ error: 'Invalid or expired reset link' }, 400, cors);
  }
  const hash = await hashPw(password);
  // Claim the link in one statement: two requests racing with the same link
  // can't both get through. Then every other reset link for this user dies too.
  const claim = await env.DB.prepare('UPDATE reset_tokens SET used=1 WHERE token=? AND used=0').bind(tokenHash).run();
  if (!claim?.meta?.changes) return res({ error: 'Invalid or expired reset link' }, 400, cors);
  await env.DB.batch([
    // Opening the emailed link proved the inbox, so the account is verified too.
    env.DB.prepare('UPDATE users SET password_hash=?, token_version=COALESCE(token_version,0)+1, email_verified=1, verified_at=COALESCE(verified_at, ?) WHERE id=?').bind(hash, new Date().toISOString(), rt.user_id),
    env.DB.prepare('UPDATE reset_tokens SET used=1 WHERE user_id=?').bind(rt.user_id),
  ]);
  const user = await env.DB.prepare('SELECT id,email,newsletter_consent,token_version FROM users WHERE id=?').bind(rt.user_id).first();
  await secLog(env, request, 'password_reset', { uid: rt.user_id });
  const jwt = await mintSession(user.id, user.token_version, env);
  const hubProToken = await hubProLookup(user.email, env);
  return resWithSession({ ...(hubProToken ? { hub_pro_token: hubProToken } : {}), user: { id: user.id, email: user.email, newsletter_consent: user.newsletter_consent === 1 } }, jwt, cors);
}

// ── Profile routes ──────────────────────────────────────────────────────────

async function getProfile(uid, env, cors, request) {
  const u = await env.DB.prepare('SELECT id,email,currency,newsletter_consent,timezone FROM users WHERE id=?').bind(uid).first();
  if (!u) return res({ error: 'Not found' }, 404, cors);
  // Backfill the timezone the browser reports, so renewal warnings go out on
  // the user's calendar day. Only writes when it changed, and a failure here
  // must never break loading the app.
  const tz = request && request.headers ? request.headers.get('X-Timezone') : null;
  if (tz && tz !== u.timezone && isValidTimezone(tz)) {
    try {
      await env.DB.prepare('UPDATE users SET timezone=? WHERE id=?').bind(tz, uid).run();
    } catch (e) { /* non-fatal */ }
  }
  return res({ id: u.id, email: u.email, currency: u.currency, newsletter_consent: u.newsletter_consent === 1 }, 200, cors);
}

// Only accept a real IANA zone name — this string is user-controlled and is
// fed to Intl later. Anything unrecognised is dropped rather than stored.
function isValidTimezone(tz) {
  if (typeof tz !== 'string' || tz.length > 64 || !/^[A-Za-z0-9_+\-\/]+$/.test(tz)) return false;
  try { new Intl.DateTimeFormat('en-CA', { timeZone: tz }); return true; } catch (e) { return false; }
}
// "Today" on the user's wall calendar, not the server's.
function localToday(tz) {
  try { return new Intl.DateTimeFormat('en-CA', { timeZone: tz || 'UTC' }).format(new Date()); }
  catch (e) { return new Date().toISOString().slice(0, 10); }
}

async function updateProfile(uid, request, env, cors) {
  const body = await readJson(request);
  if (!body) return badBody(cors);
  const sets = [], vals = [];
  if ('currency' in body) {
    if (typeof body.currency !== 'string' || body.currency.length > 8) {
      return res({ error: 'Invalid currency' }, 400, cors);
    }
    sets.push('currency=?'); vals.push(body.currency);
  }
  if ('newsletter_consent' in body) {
    sets.push('newsletter_consent=?'); vals.push(body.newsletter_consent ? 1 : 0);
    sets.push('newsletter_consent_at=?'); vals.push(body.newsletter_consent ? new Date().toISOString() : null);
  }
  if (sets.length) await env.DB.prepare(`UPDATE users SET ${sets.join(',')} WHERE id=?`).bind(...vals, uid).run();
  return res({ success: true }, 200, cors);
}

async function changePassword(uid, request, env, cors) {
  const reqBody = await readJson(request);
  if (!reqBody) return badBody(cors);
  const { current_password, password } = reqBody;
  if (!current_password || typeof current_password !== 'string' || current_password.length > 200) {
    return res({ error: 'Current password required' }, 400, cors);
  }
  if (!isValidPassword(password)) {
    return res({ error: 'New password must be 10-200 characters.' }, 400, cors);
  }
  const user = await env.DB.prepare('SELECT email, password_hash FROM users WHERE id=?').bind(uid).first();
  if (!user || !(await recheckPassword(env, String(user.email).toLowerCase(), current_password, user.password_hash))) {
    return res({ error: 'Current password is incorrect' }, 401, cors);
  }
  // A password change also kills any reset link still sitting in an inbox.
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET password_hash=?, token_version=COALESCE(token_version,0)+1 WHERE id=?').bind(await hashPw(password), uid),
    env.DB.prepare('UPDATE reset_tokens SET used=1 WHERE user_id=?').bind(uid),
  ]);
  await secLog(env, request, 'password_change', { uid });
  // The bump revokes every old session, including this one. Hand back a fresh
  // token so the person who just changed their password stays logged in.
  const fresh = await env.DB.prepare('SELECT token_version FROM users WHERE id=?').bind(uid).first();
  const token = await mintSession(uid, fresh?.token_version, env);
  return resWithSession({ success: true }, token, cors);
}

// Account delete needs a fresh proof, so a stolen session alone can't wipe data.
// Either proof is enough:
//   - current_password, for any account that has one;
//   - hub_pro_jwt plus confirm:"DELETE", for accounts made through the App Hub
//     that never set a password (their hash is a random sentinel nobody can
//     type). The hub token is checked here with HUB_JWT_SECRET and must name
//     this account's email: the same proof hub-sso accepts to log in.
async function deleteAccount(uid, request, env, cors) {
  const body = await readJson(request);
  if (!body) return badBody(cors);
  const { current_password } = body;
  const user = await env.DB.prepare('SELECT email, password_hash FROM users WHERE id=?').bind(uid).first();
  if (!user) return res({ error: 'Not found' }, 404, cors);
  if (body.hub_pro_jwt !== undefined) {
    if (body.confirm !== 'DELETE') return res({ error: 'Type DELETE to confirm.' }, 400, cors);
    const hub = typeof body.hub_pro_jwt === 'string' && body.hub_pro_jwt.length <= 4096 && env.HUB_JWT_SECRET
      ? await verifyHubPro(body.hub_pro_jwt, env.HUB_JWT_SECRET) : null;
    if (!hub || String(hub.email || '').toLowerCase() !== String(user.email).toLowerCase()) {
      return res({ error: "We couldn't confirm your App Hub sign-in. Open the App Hub, launch Subscription Graveyard from there, then try again. Or use Forgot password to set a password first." }, 401, cors);
    }
  } else {
    if (!current_password || typeof current_password !== 'string' || current_password.length > 200) {
      return res({ error: 'Current password required to delete account' }, 400, cors);
    }
    const ok = await recheckPassword(env, String(user.email).toLowerCase(), current_password, user.password_hash);
    if (!ok) return res({ error: 'Current password is incorrect' }, 401, cors);
  }
  await env.DB.batch([
    env.DB.prepare('DELETE FROM renewal_watchlist WHERE user_id=?').bind(uid),
    env.DB.prepare('DELETE FROM death_row WHERE user_id=?').bind(uid),
    env.DB.prepare('DELETE FROM subscriptions WHERE user_id=?').bind(uid),
    env.DB.prepare('DELETE FROM reset_tokens WHERE user_id=?').bind(uid),
    env.DB.prepare('DELETE FROM email_verification_tokens WHERE user_id=?').bind(uid),
    env.DB.prepare("DELETE FROM rate_limits WHERE key = ?").bind(`failed-login:${user.email}`),
    env.DB.prepare('DELETE FROM users WHERE id=?').bind(uid),
  ]);
  await secLog(env, request, 'account_delete', { uid });
  const out = res({ success: true }, 200, cors);
  out.headers.append('Set-Cookie', clearSessionCookie());
  return out;
}

// GDPR Article 15 / 20 — data export. Returns user profile + all owned rows.
async function exportAccount(uid, env, cors) {
  const user = await env.DB.prepare(
    'SELECT id, email, currency, timezone, newsletter_consent, newsletter_consent_at, created_at FROM users WHERE id=?'
  ).bind(uid).first();
  if (!user) return res({ error: 'Not found' }, 404, cors);
  const subs = await env.DB.prepare('SELECT * FROM subscriptions WHERE user_id=?').bind(uid).all();
  const deathRow = await env.DB.prepare('SELECT * FROM death_row WHERE user_id=?').bind(uid).all();
  const watchlist = await env.DB.prepare('SELECT * FROM renewal_watchlist WHERE user_id=?').bind(uid).all();
  return res({
    exported_at: new Date().toISOString(),
    user,
    subscriptions: subs.results || [],
    death_row: deathRow.results || [],
    watchlist: watchlist.results || [],
  }, 200, cors);
}

// ── Subscription routes (graveyard) ─────────────────────────────────────────

async function getSubs(uid, env, cors) {
  const r = await env.DB.prepare(
    'SELECT * FROM subscriptions WHERE user_id=? ORDER BY cancelled_date DESC'
  ).bind(uid).all();
  return res(r.results || [], 200, cors);
}

async function addSub(uid, request, env, hubPro, cors) {
  if (!hasProAccess(hubPro)) {
    const count = await env.DB.prepare('SELECT COUNT(*) as n FROM subscriptions WHERE user_id=?').bind(uid).first();
    if (count.n >= FREE_BURIALS) {
      return res({
        error: 'Pro required',
        feature: 'unlimited-burials',
        upgrade_url: upgradeUrl('unlimited-burials'),
      }, 402, cors);
    }
  }
  const reqBody = await readJson(request);
  if (!reqBody) return badBody(cors);
  const { name, monthly_cost, category = 'other', cancelled_date, started_date, cancel_reason } = reqBody;
  if (!name || !monthly_cost || !cancelled_date) {
    return res({ error: 'Name, monthly cost, and cancellation date required' }, 400, cors);
  }
  if (typeof name !== 'string' || name.length > 200) return res({ error: 'Invalid name' }, 400, cors);
  if (typeof monthly_cost !== 'number' || !isFinite(monthly_cost) || monthly_cost <= 0 || monthly_cost > 1000000) {
    return res({ error: 'monthly_cost must be a positive number under 1,000,000' }, 400, cors);
  }
  if (!ALLOWED_CATEGORIES.includes(category)) return res({ error: 'Invalid category' }, 400, cors);
  if (cancel_reason && (typeof cancel_reason !== 'string' || cancel_reason.length > 2000)) {
    return res({ error: 'cancel_reason too long' }, 400, cors);
  }
  if (!isRealDate(cancelled_date)) {
    return res({ error: 'cancelled_date must be YYYY-MM-DD' }, 400, cors);
  }
  if (started_date && !isRealDate(started_date)) {
    return res({ error: 'started_date must be YYYY-MM-DD' }, 400, cors);
  }
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await env.DB.prepare(
    'INSERT INTO subscriptions (id,user_id,name,monthly_cost,category,cancelled_date,started_date,cancel_reason,created_at) VALUES (?,?,?,?,?,?,?,?,?)'
  ).bind(id, uid, name, monthly_cost, category, cancelled_date, started_date || null, cancel_reason || null, now).run();
  return res({ id, name, monthly_cost, category, cancelled_date, started_date, cancel_reason, created_at: now }, 200, cors);
}

async function updateSub(uid, subId, request, env, cors) {
  const existing = await env.DB.prepare('SELECT id FROM subscriptions WHERE id=? AND user_id=?').bind(subId, uid).first();
  if (!existing) return res({ error: 'Not found' }, 404, cors);
  const body = await readJson(request);
  if (!body) return badBody(cors);
  if ('monthly_cost' in body) {
    const n = body.monthly_cost;
    if (typeof n !== 'number' || !isFinite(n) || n <= 0 || n > 1000000) return res({ error: 'Invalid monthly_cost' }, 400, cors);
  }
  if ('name' in body && (typeof body.name !== 'string' || body.name.length > 200)) return res({ error: 'Invalid name' }, 400, cors);
  if ('category' in body && !ALLOWED_CATEGORIES.includes(body.category)) return res({ error: 'Invalid category' }, 400, cors);
  if ('cancelled_date' in body && !isRealDate(body.cancelled_date)) return res({ error: 'cancelled_date must be YYYY-MM-DD' }, 400, cors);
  if ('started_date' in body && body.started_date !== null && body.started_date !== '' && !isRealDate(body.started_date)) return res({ error: 'started_date must be YYYY-MM-DD' }, 400, cors);
  if ('cancel_reason' in body && body.cancel_reason !== null && (typeof body.cancel_reason !== 'string' || body.cancel_reason.length > 2000)) return res({ error: 'cancel_reason too long' }, 400, cors);
  const sets = [], vals = [];
  for (const field of ['name', 'monthly_cost', 'category', 'cancelled_date', 'started_date', 'cancel_reason']) {
    if (field in body) { sets.push(`${field}=?`); vals.push(body[field]); }
  }
  if (sets.length) await env.DB.prepare(`UPDATE subscriptions SET ${sets.join(',')} WHERE id=? AND user_id=?`).bind(...vals, subId, uid).run();
  return res({ success: true }, 200, cors);
}

async function deleteSub(uid, subId, env, cors) {
  const existing = await env.DB.prepare('SELECT id FROM subscriptions WHERE id=? AND user_id=?').bind(subId, uid).first();
  if (!existing) return res({ error: 'Not found' }, 404, cors);
  await env.DB.prepare('DELETE FROM subscriptions WHERE id=? AND user_id=?').bind(subId, uid).run();
  return res({ success: true }, 200, cors);
}

// ── Death Row routes ────────────────────────────────────────────────────────

async function getDeathRow(uid, env, cors) {
  const r = await env.DB.prepare(
    'SELECT * FROM death_row WHERE user_id=? ORDER BY created_at DESC'
  ).bind(uid).all();
  return res(r.results || [], 200, cors);
}

async function addDeathRow(uid, request, env, hubPro, cors) {
  if (!hasProAccess(hubPro)) {
    const count = await env.DB.prepare('SELECT COUNT(*) as n FROM death_row WHERE user_id=?').bind(uid).first();
    if (count.n >= FREE_LAST_RITES) {
      return res({
        error: 'Pro required',
        feature: 'unlimited-death-row',
        upgrade_url: upgradeUrl('unlimited-death-row'),
      }, 402, cors);
    }
  }
  const reqBody = await readJson(request);
  if (!reqBody) return badBody(cors);
  const { name, monthly_cost, category = 'other', notes } = reqBody;
  if (!name || !monthly_cost) {
    return res({ error: 'Name and monthly cost required' }, 400, cors);
  }
  if (typeof name !== 'string' || name.length > 200) return res({ error: 'Invalid name' }, 400, cors);
  if (typeof monthly_cost !== 'number' || !isFinite(monthly_cost) || monthly_cost <= 0 || monthly_cost > 1000000) {
    return res({ error: 'monthly_cost must be a positive number under 1,000,000' }, 400, cors);
  }
  if (!ALLOWED_CATEGORIES.includes(category)) return res({ error: 'Invalid category' }, 400, cors);
  if (notes && (typeof notes !== 'string' || notes.length > 2000)) return res({ error: 'notes too long' }, 400, cors);
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await env.DB.prepare(
    'INSERT INTO death_row (id,user_id,name,monthly_cost,category,notes,created_at) VALUES (?,?,?,?,?,?,?)'
  ).bind(id, uid, name, monthly_cost, category, notes || null, now).run();
  return res({ id, name, monthly_cost, category, notes, created_at: now }, 200, cors);
}

async function deleteDeathRow(uid, drId, env, cors) {
  const existing = await env.DB.prepare('SELECT id FROM death_row WHERE id=? AND user_id=?').bind(drId, uid).first();
  if (!existing) return res({ error: 'Not found' }, 404, cors);
  await env.DB.prepare('DELETE FROM death_row WHERE id=? AND user_id=?').bind(drId, uid).run();
  return res({ success: true }, 200, cors);
}

async function executeDeathRow(uid, drId, request, env, hubPro, cors) {
  const item = await env.DB.prepare('SELECT * FROM death_row WHERE id=? AND user_id=?').bind(drId, uid).first();
  if (!item) return res({ error: 'Not found' }, 404, cors);

  if (!hasProAccess(hubPro)) {
    const count = await env.DB.prepare('SELECT COUNT(*) as n FROM subscriptions WHERE user_id=?').bind(uid).first();
    if (count.n >= FREE_BURIALS) {
      return res({
        error: 'Pro required',
        feature: 'unlimited-burials',
        upgrade_url: upgradeUrl('unlimited-burials'),
      }, 402, cors);
    }
  }

  const { cancelled_date, cancel_reason } = (await readJson(request)) || {};
  if (cancelled_date && !isRealDate(cancelled_date)) {
    return res({ error: 'cancelled_date must be YYYY-MM-DD' }, 400, cors);
  }
  if (cancel_reason && (typeof cancel_reason !== 'string' || cancel_reason.length > 2000)) {
    return res({ error: 'cancel_reason too long' }, 400, cors);
  }
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  await env.DB.batch([
    env.DB.prepare(
      'INSERT INTO subscriptions (id,user_id,name,monthly_cost,category,cancelled_date,cancel_reason,created_at) VALUES (?,?,?,?,?,?,?,?)'
    ).bind(id, uid, item.name, item.monthly_cost, item.category, cancelled_date || now.slice(0, 10), cancel_reason || item.notes || null, now),
    env.DB.prepare('DELETE FROM death_row WHERE id=? AND user_id=?').bind(drId, uid),
  ]);

  return res({ id, name: item.name, monthly_cost: item.monthly_cost, category: item.category, cancelled_date: cancelled_date || now.slice(0, 10), created_at: now }, 200, cors);
}

// ── Pro token refresh proxy ─────────────────────────────────────────────────
// The hub JWT stored client-side expires; rather than silently dropping a Pro
// user to free, the client sends us its stored token and we relay it
// server-side to the hub's refresh endpoint, passing the JSON + status straight
// through. Client-demand only — never polled.
// Hub responses: 200 {valid:true,token,pro_until} | 200 {valid:false} | 400 | 429 (60/min/IP).
async function proRefresh(request, env, cors) {
  const body = (await readJson(request)) || {};
  const token = body.token;
  if (typeof token !== 'string' || token.length === 0 || token.length > 2048) {
    return res({ valid: false }, 400, cors);
  }
  // Optional: PRO_REFRESH_URL is the hub's token refresh endpoint. Unset = off.
  if (!env.PRO_REFRESH_URL) return res({ error: 'Pro refresh is off on this server.' }, 404, cors);
  // Light per-IP limit so this proxy can't be used to hammer the hub.
  const rl = await rateLimit(request, env, 'pro-refresh', 20, 60, undefined, cors);
  if (rl) return rl;
  try {
    const upstream = await fetch(env.PRO_REFRESH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    const data = await upstream.json().catch(() => null);
    // No `valid` field on upstream failures — the client only removes its token
    // on an explicit valid:false, so a hub outage never demotes anyone.
    if (data === null) return res({ error: 'Upstream error' }, 502, cors);
    // A hub 5xx passes through, but it's the hub's error, not ours: no alert email.
    const out = res(data, upstream.status, cors);
    return upstream.status >= 500 ? markNoAlert(out) : out;
  } catch (e) {
    console.error('pro-refresh upstream failed', e.message);
    return res({ error: 'Upstream unreachable' }, 502, cors);
  }
}

// ── Pro-only Renewal Watchlist ──────────────────────────────────────────────

function requirePro(hubPro, featureId, cors) {
  if (hasProAccess(hubPro)) return null;
  return res({
    error: 'Pro required',
    feature: featureId,
    upgrade_url: upgradeUrl(featureId),
  }, 402, cors);
}

// Validate user-supplied URL: must be http(s), reasonable length. Defends
// against javascript: schemes embedded in renewal warning emails.
function isValidUrl(s) {
  if (typeof s !== 'string') return false;
  if (s.length === 0 || s.length > 500) return false;
  return /^https?:\/\//i.test(s);
}

async function getWatchlist(uid, env, hubPro, cors) {
  const blocked = requirePro(hubPro, 'renewal-watchlist', cors);
  if (blocked) return blocked;
  const items = await env.DB.prepare(
    'SELECT id, name, monthly_cost, category, next_renewal_date, warning_days, cancel_url, notes, last_warned_at, billing_cycle, reminder_mode, created_at FROM renewal_watchlist WHERE user_id=? ORDER BY next_renewal_date ASC'
  ).bind(uid).all();
  return res({ items: items.results || [] }, 200, cors);
}

async function addWatchlist(uid, request, env, hubPro, cors) {
  const blocked = requirePro(hubPro, 'renewal-watchlist', cors);
  if (blocked) return blocked;
  const body = (await readJson(request)) || {};
  const { name, monthly_cost, category = 'other', next_renewal_date, warning_days = '7,1', cancel_url = null, notes = null, billing_cycle = 'monthly', reminder_mode = 'cancel' } = body;
  if (!ALLOWED_CYCLES.includes(billing_cycle)) return res({ error: 'billing_cycle must be monthly, quarterly, annual, or weekly' }, 400, cors);
  if (!ALLOWED_REMINDER_MODES.includes(reminder_mode)) return res({ error: 'reminder_mode must be cancel or negotiate' }, 400, cors);
  if (!name || typeof monthly_cost !== 'number' || !next_renewal_date) {
    return res({ error: 'name, monthly_cost (number), next_renewal_date required' }, 400, cors);
  }
  if (typeof name !== 'string' || name.length > 200) return res({ error: 'Invalid name' }, 400, cors);
  if (!isFinite(monthly_cost) || monthly_cost <= 0 || monthly_cost > 1000000) {
    return res({ error: 'monthly_cost must be a positive number under 1,000,000' }, 400, cors);
  }
  if (!ALLOWED_CATEGORIES.includes(category)) return res({ error: 'Invalid category' }, 400, cors);
  if (!isRealDate(next_renewal_date)) {
    return res({ error: 'next_renewal_date must be YYYY-MM-DD' }, 400, cors);
  }
  if (typeof warning_days !== 'string' || warning_days.length > 64 || !/^[\d,\s]+$/.test(warning_days)) {
    return res({ error: 'warning_days must be comma-separated digits' }, 400, cors);
  }
  if (cancel_url !== null && cancel_url !== undefined && cancel_url !== '' && !isValidUrl(cancel_url)) {
    return res({ error: 'cancel_url must be a https URL under 500 chars' }, 400, cors);
  }
  if (notes && (typeof notes !== 'string' || notes.length > 2000)) {
    return res({ error: 'notes too long' }, 400, cors);
  }
  const have = await env.DB.prepare('SELECT COUNT(*) AS c FROM renewal_watchlist WHERE user_id=?').bind(uid).first();
  if (Number(have?.c || 0) >= WATCHLIST_MAX_PER_USER) {
    return res({ error: `Your watchlist is full. It holds up to ${WATCHLIST_MAX_PER_USER} subscriptions, so remove one you're not watching anymore to add this one.` }, 409, cors);
  }
  const id = crypto.randomUUID();
  const created_at = new Date().toISOString();
  await env.DB.prepare(
    'INSERT INTO renewal_watchlist (id, user_id, name, monthly_cost, category, next_renewal_date, warning_days, cancel_url, notes, billing_cycle, reminder_mode, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)'
  ).bind(id, uid, name, monthly_cost, category, next_renewal_date, warning_days, cancel_url || null, notes, billing_cycle, reminder_mode, created_at).run();
  return res({ id, name, monthly_cost, category, next_renewal_date, warning_days, cancel_url, notes, billing_cycle, reminder_mode, created_at }, 200, cors);
}

async function updateWatchlist(uid, request, env, hubPro, cors) {
  const blocked = requirePro(hubPro, 'renewal-watchlist', cors);
  if (blocked) return blocked;
  const { id, name, monthly_cost, category, next_renewal_date, warning_days, cancel_url, notes, billing_cycle, reminder_mode } = (await readJson(request)) || {};
  if (!id || typeof id !== 'string' || id.length > 64) return res({ error: 'id required' }, 400, cors);
  const updates = [];
  const binds = [];
  if (name !== undefined) {
    if (typeof name !== 'string' || name.length > 200) return res({ error: 'Invalid name' }, 400, cors);
    updates.push('name=?'); binds.push(name);
  }
  if (monthly_cost !== undefined) {
    if (typeof monthly_cost !== 'number' || !isFinite(monthly_cost) || monthly_cost <= 0 || monthly_cost > 1000000) {
      return res({ error: 'Invalid monthly_cost' }, 400, cors);
    }
    updates.push('monthly_cost=?'); binds.push(monthly_cost);
  }
  if (category !== undefined) {
    if (!ALLOWED_CATEGORIES.includes(category)) return res({ error: 'Invalid category' }, 400, cors);
    updates.push('category=?'); binds.push(category);
  }
  if (next_renewal_date !== undefined) {
    if (!isRealDate(next_renewal_date)) return res({ error: 'next_renewal_date must be YYYY-MM-DD' }, 400, cors);
    updates.push('next_renewal_date=?'); binds.push(next_renewal_date);
  }
  if (warning_days !== undefined) {
    if (typeof warning_days !== 'string' || warning_days.length > 64 || !/^[\d,\s]+$/.test(warning_days)) {
      return res({ error: 'warning_days must be comma-separated digits' }, 400, cors);
    }
    updates.push('warning_days=?'); binds.push(warning_days);
  }
  if (cancel_url !== undefined) {
    if (cancel_url !== null && cancel_url !== '' && !isValidUrl(cancel_url)) {
      return res({ error: 'cancel_url must be a https URL under 500 chars' }, 400, cors);
    }
    updates.push('cancel_url=?'); binds.push(cancel_url || null);
  }
  if (notes !== undefined) {
    if (notes !== null && (typeof notes !== 'string' || notes.length > 2000)) return res({ error: 'notes too long' }, 400, cors);
    updates.push('notes=?'); binds.push(notes);
  }
  if (billing_cycle !== undefined) {
    if (!ALLOWED_CYCLES.includes(billing_cycle)) return res({ error: 'Invalid billing_cycle' }, 400, cors);
    updates.push('billing_cycle=?'); binds.push(billing_cycle);
  }
  if (reminder_mode !== undefined) {
    if (!ALLOWED_REMINDER_MODES.includes(reminder_mode)) return res({ error: 'Invalid reminder_mode' }, 400, cors);
    updates.push('reminder_mode=?'); binds.push(reminder_mode);
  }
  if (!updates.length) return res({ error: 'no fields to update' }, 400, cors);
  binds.push(id, uid);
  await env.DB.prepare(
    `UPDATE renewal_watchlist SET ${updates.join(',')} WHERE id=? AND user_id=?`
  ).bind(...binds).run();
  return res({ id, updated: true }, 200, cors);
}

async function deleteWatchlist(uid, request, env, hubPro, cors) {
  const blocked = requirePro(hubPro, 'renewal-watchlist', cors);
  if (blocked) return blocked;
  const { id } = (await readJson(request)) || {};
  if (!id || typeof id !== 'string' || id.length > 64) return res({ error: 'id required' }, 400, cors);
  await env.DB.prepare('DELETE FROM renewal_watchlist WHERE id=? AND user_id=?').bind(id, uid).run();
  return res({ deleted: true }, 200, cors);
}

// ── Recap stats endpoint ───────────────────────────────────
// Called by a connected Pro hub's recap job with the shared RECAP_SERVICE_SECRET.
// The hub decides who is Pro; this endpoint only reports a user's month.

function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Same thresholds as TIERS in public/app.js — keep in sync.
function tierForMonthlyRate(rate) {
  if (rate >= 500) return 'Grim Reaper';
  if (rate >= 200) return 'Undertaker';
  if (rate >= 100) return 'Gravedigger';
  if (rate >= 50) return 'Mourner';
  return 'Ghost';
}

async function serviceRecap(url, request, env, cors) {
  const provided = request.headers.get('X-Internal-Secret') || '';
  if (!env.RECAP_SERVICE_SECRET || !timingSafeEqualStr(provided, env.RECAP_SERVICE_SECRET)) {
    return res({ error: 'Unauthorized' }, 401, cors);
  }
  const email = (url.searchParams.get('email') || '').trim().toLowerCase();
  const start = url.searchParams.get('start') || '';
  const end = url.searchParams.get('end') || '';
  if (!email || !isRealDate(start) || !isRealDate(end)) {
    return res({ error: 'email, start, end required' }, 400, cors);
  }
  const user = await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first();
  if (!user) return res({ found: false }, 200, cors);

  const subs = await env.DB.prepare(
    'SELECT name, monthly_cost, cancelled_date FROM subscriptions WHERE user_id=?'
  ).bind(user.id).all();
  const all = subs.results || [];
  const periodDays = Math.max(1, Math.round((new Date(end) - new Date(start)) / 86400000) + 1);
  // Savings realized inside the window: full monthly_cost for subs buried
  // before it, prorated by day for subs buried mid-window.
  let savedInPeriod = 0;
  const newBurials = [];
  for (const s of all) {
    const c = s.cancelled_date || '';
    if (c > end) continue;
    if (c >= start) {
      newBurials.push({ name: s.name, monthly_cost: s.monthly_cost });
      const daysSaved = Math.round((new Date(end) - new Date(c)) / 86400000) + 1;
      savedInPeriod += s.monthly_cost * (daysSaved / periodDays);
    } else {
      savedInPeriod += s.monthly_cost;
    }
  }
  const monthlyRate = all.reduce((t, s) => t + (s.monthly_cost || 0), 0);
  const dr = await env.DB.prepare('SELECT COUNT(*) AS n FROM death_row WHERE user_id=?').bind(user.id).first();
  const today = new Date().toISOString().slice(0, 10);
  const thirtyOut = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
  const upcoming = await env.DB.prepare(
    'SELECT name, next_renewal_date, reminder_mode FROM renewal_watchlist WHERE user_id=? AND next_renewal_date BETWEEN ? AND ? ORDER BY next_renewal_date ASC LIMIT 10'
  ).bind(user.id, today, thirtyOut).all();

  return res({
    found: true,
    stats: {
      buried_total: all.length,
      monthly_rate: Math.round(monthlyRate * 100) / 100,
      saved_in_period: Math.round(savedInPeriod * 100) / 100,
      new_burials: newBurials.slice(0, 10),
      tier: tierForMonthlyRate(monthlyRate),
      death_row_count: dr?.n || 0,
      upcoming_renewals: upcoming.results || [],
      // Never send a "$0 stayed in your pocket" month: skip unless the period
      // had real savings or a fresh burial.
      skip: savedInPeriod === 0 && newBurials.length === 0,
    },
  }, 200, cors);
}

// ── Scheduled: daily renewal warning emails ─────────────────────────────────

async function sendRenewalWarnings(env) {
  if (!env.RESEND_API_KEY) {
    console.error('Renewal warnings: RESEND_API_KEY not set, aborting');
    return;
  }
  const today = new Date().toISOString().slice(0, 10);  // YYYY-MM-DD
  const todayMs = new Date(today).getTime();

  // Find items renewing within next 14 days (broader filter; narrowed below)
  const fourteenDaysOut = new Date(todayMs + 14 * 86400000).toISOString().slice(0, 10);
  const rows = await env.DB.prepare(
    'SELECT w.*, u.email, u.timezone FROM renewal_watchlist w JOIN users u ON u.id = w.user_id WHERE w.next_renewal_date BETWEEN ? AND ? ORDER BY w.next_renewal_date ASC'
  ).bind(today, fourteenDaysOut).all();

  // Pick out what's actually due today first, then spend the budget fairly.
  const due = [];
  for (const item of rows.results || []) {
    // Count days from the USER's calendar day. This cron fires at 14:00 UTC,
    // still today in the Americas/Europe/Asia but already tomorrow at UTC+10
    // and east — so a Sydney or Auckland user was warned a day late, and a
    // "1 day before" setting could land on the renewal day itself.
    const userToday = localToday(item.timezone);
    const userTodayMs = new Date(userToday).getTime();
    const renewalMs = new Date(item.next_renewal_date).getTime();
    const daysOut = Math.round((renewalMs - userTodayMs) / 86400000);
    const warningDays = (item.warning_days || '7,1').split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
    if (!warningDays.includes(daysOut)) continue;
    // Skip if already warned today
    if (item.last_warned_at && item.last_warned_at.slice(0, 10) === userToday) continue;
    due.push({ item, daysOut });
  }

  // At most PER_USER_PER_RUN per account, round-robin across accounts, and no
  // more than DAILY_SEND_MAX per UTC day in total (counted in D1). Anything
  // left over keeps its old last_warned_at, so it's still due on the next run.
  const fair = planFairSends(due.map(d => ({ ...d, user_id: d.item.user_id, next_renewal_date: d.item.next_renewal_date })), PER_USER_PER_RUN);
  // Renewal Alerts are Pro-only, and Pro can end after rows were added. Ask
  // the hub once per account. A clear "not Pro" skips that account (its rows
  // keep their last_warned_at, so renewing Pro picks them right back up). A
  // lookup that fails still sends, so a hub hiccup never costs a paying user
  // a warning. Accounts with no answer at all (past the lookup cap) wait.
  const proState = await proStateForUsers(env, fair);
  const plan = fair.filter(r => proState.get(r.user_id) === 'pro' || proState.get(r.user_id) === 'unknown');
  const skipped = fair.length - plan.length;
  if (skipped) console.log(`Renewal warnings: ${skipped} skipped (no current Pro, or past the lookup cap)`);
  let granted = 0;
  try {
    granted = await claimDailySends(env, plan.length, DAILY_SEND_MAX);
  } catch (err) {
    console.error('Renewal warnings: daily send budget unavailable, sending nothing:', err);
    granted = 0;
  }
  if (granted < plan.length) {
    console.warn(`Renewal warnings: ${plan.length} due, sending ${granted}, ${plan.length - granted} held for the next run`);
  }
  for (const { item, daysOut } of plan.slice(0, granted)) {
    await sendWarningEmail(env, item, daysOut);
    await env.DB.prepare('UPDATE renewal_watchlist SET last_warned_at=? WHERE id=?')
      .bind(new Date().toISOString(), item.id).run();
  }

  // Bump items past their renewal date forward one full billing cycle. Loop
  // until the date is in the future so long-dormant rows (e.g. an annual sub
  // that lapsed two cycles ago) land on the NEXT real renewal, not a past one.
  const past = await env.DB.prepare(
    'SELECT id, next_renewal_date, billing_cycle FROM renewal_watchlist WHERE next_renewal_date < ?'
  ).bind(today).all();
  let rollFailed = 0;
  for (const row of past.results || []) {
    // Each row on its own: one bad row must never stop the rows after it.
    try {
      if (!isRealDate(row.next_renewal_date)) { rollFailed++; continue; }
      let next = row.next_renewal_date;
      for (let i = 0; i < 60 && next < today; i++) next = advanceByCycle(next, row.billing_cycle);
      await env.DB.prepare('UPDATE renewal_watchlist SET next_renewal_date=? WHERE id=?')
        .bind(next, row.id).run();
    } catch (err) {
      rollFailed++;
      console.error('Renewal rollover: row skipped', row.id, err && err.message);
    }
  }
  if (rollFailed) console.error(`Renewal rollover: ${rollFailed} row(s) could not be rolled forward`);
}

// One billing cycle forward, in UTC, returning YYYY-MM-DD.
function advanceByCycle(dateStr, cycle) {
  const d = new Date(dateStr + 'T00:00:00Z');
  if (cycle === 'weekly') d.setUTCDate(d.getUTCDate() + 7);
  else if (cycle === 'quarterly') d.setUTCMonth(d.getUTCMonth() + 3);
  else if (cycle === 'annual') d.setUTCFullYear(d.getUTCFullYear() + 1);
  else d.setUTCMonth(d.getUTCMonth() + 1);
  return d.toISOString().slice(0, 10);
}

async function sendWarningEmail(env, item, daysOut) {
  // Re-validate cancel_url at send time — even though addWatchlist filters, defense in depth.
  const safeCancelUrl = isValidUrl(item.cancel_url) ? item.cancel_url : null;
  const t = EMAIL_THEME;
  const dayWord = daysOut === 1 ? 'day' : 'days';
  const safeName = escapeHtml(item.name);
  const safeDate = escapeHtml(item.next_renewal_date);
  const negotiate = item.reminder_mode === 'negotiate';
  const subject = negotiate
    ? `${item.name} renews in ${daysOut} ${dayWord}. Time to make them beg.`
    : `${item.name} renews in ${daysOut} ${dayWord}`;
  // Negotiation mode: the renewal window is leverage. Give a short script
  // instead of a cancel link so the call actually happens.
  const negotiateBlock = `
      <div style="background:${t.bg};border:1px solid ${t.line};border-radius:14px;padding:14px 16px;margin:16px 0">
        <p style="margin:0 0 8px;font-family:${FONT_BODY};font-weight:bold;color:${t.a2}">Your negotiation script:</p>
        <ol style="margin:0;padding-left:20px;font-family:${FONT_BODY};color:${t.text};font-size:14px;line-height:1.7">
          <li>Call or chat with ${safeName} support and ask for the <strong>retention or cancellation department</strong>.</li>
          <li>Say: "My renewal is coming up on ${safeDate} and I'm planning to cancel. Are there any offers that would change my mind?"</li>
          <li>Mention any new-customer promo they advertise and ask for it as a loyal customer.</li>
          <li>Silence is fine. Let them fill it with a better offer.</li>
          <li>No deal? Follow through. The graveyard has room.</li>
        </ol>
      </div>`;
  const cost = `$${Number(item.monthly_cost).toFixed(2)}`;
  const html = emailLayout(t, {
    title: negotiate ? `Time to negotiate: ${safeName} renews in ${daysOut} ${dayWord}` : `${safeName} renews in ${daysOut} ${dayWord}`,
    body: emailPara(t, `It'll charge <strong>${cost}</strong> on <strong>${safeDate}</strong>.`)
      + emailBigStat(t, cost, `Charges on ${safeDate}`)
      + (negotiate ? negotiateBlock : '')
      + (safeCancelUrl ? emailButton(t, escapeHtml(safeCancelUrl), 'Cancel here') : '')
      + emailSmall(t, `Manage your watchlist at <a href="${escapeHtml(APP_BASE || '/')}" style="color:${t.pri}">Subscription Graveyard</a>.`),
    footer: emailFooterHtml(t.muted, t.line),
  });
  const negotiateText = `Your negotiation script:
1. Call or chat with ${item.name} support and ask for the retention or cancellation department.
2. Say: "My renewal is coming up on ${item.next_renewal_date} and I'm planning to cancel. Are there any offers that would change my mind?"
3. Mention any new-customer promo they advertise and ask for it as a loyal customer.
4. Silence is fine. Let them fill it with a better offer.
5. No deal? Follow through. The graveyard has room.`;
  const text = [
    negotiate ? `Time to negotiate: ${item.name} renews in ${daysOut} ${dayWord}` : `${item.name} renews in ${daysOut} ${dayWord}`,
    `It'll charge $${Number(item.monthly_cost).toFixed(2)} on ${item.next_renewal_date}.`,
    negotiate ? negotiateText : '',
    safeCancelUrl ? `Cancel here: ${safeCancelUrl}` : '',
    `Manage your watchlist at ${APP_BASE}`,
    emailFooterText(),
  ].filter(Boolean).join('\n\n');
  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: env.FROM_EMAIL || 'Subscription Graveyard <onboarding@resend.dev>',
      to: item.email,
      subject,
      text,
      html,
    }),
  }).catch(err => console.error('Resend error:', err));
}

// POST /api/feedback: the feedback widget's relay. Rate-limited per
// IP in handle() (5 per 10 min, D1), then honeypot, type allowlist and length
// caps here, then forwarded to your feedback webhook with the payload shape the widget
// used to send itself. Set FEEDBACK_WEBHOOK_URL to turn it on. Unset = off.
async function feedback(request, env, cors) {
  const body = await readJson(request);
  if (!body || typeof body !== 'object' || Array.isArray(body)) return badBody(cors);
  // Honeypot: a hidden field people never see. Bots fill it. Answer as if sent.
  if (body.website) return res({ ok: true }, 200, cors);
  if (!env.FEEDBACK_WEBHOOK_URL) return markNoAlert(res({ error: "Feedback isn't set up on this server." }, 503, cors));
  const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
  const message = str(body.message, 2000);
  if (message.length < 3) return res({ error: 'Please write a bit more so I know what you mean.' }, 400, cors);
  const email = str(body.email, 200);
  if (email && !isValidEmail(email.toLowerCase())) return res({ error: "That email doesn't look right. Fix it or leave it blank." }, 400, cors);
  const type = ['bug', 'feature', 'other'].includes(body.type) ? body.type : 'other';
  const r = await fetch(env.FEEDBACK_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      app: env.APP_NAME || 'Subscription Graveyard',
      type,
      message,
      email,
      url: str(body.url, 500),
      user_agent: (request.headers.get('User-Agent') || '').slice(0, 500),
    }),
    signal: AbortSignal.timeout(8000),
  }).catch(() => null);
  // markNoAlert keeps a webhook outage out of the error beacon.
  if (!r || !r.ok) return markNoAlert(res({ error: 'Could not send. Try again in a minute.' }, 502, cors));
  return res({ ok: true }, 200, cors);
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
