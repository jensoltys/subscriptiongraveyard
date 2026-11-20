// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
// Session cookie switch: the login JWT moved from localStorage
// (sent as Authorization: Bearer) to the HttpOnly sg_session cookie.
// Covers: cookie set on login, cookie auth, a Bearer header alone is refused
// (the old Bearer path is gone), logout clears it, cross-origin writes refused (403),
// garbage cookies get a 401 (never a 500, every 500 fires the alert webhook).
// Run: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';

const ORIGIN = 'https://subscriptiongraveyard.app';
const SECRET = 'test-secret-test-secret-test-secret-1234';
const PW = 'correct-horse-1';
const COOKIE = 'sg_session';

function b64(s) { return Buffer.from(s).toString('base64url'); }
async function hs256(payload, secret = SECRET) {
  const data = `${b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${b64(JSON.stringify(payload))}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return `${data}.${Buffer.from(sig).toString('base64url')}`;
}
async function pbkdf2(pw) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: new Uint8Array(16), iterations: 100000, hash: 'SHA-256' }, key, 256);
  return `pbkdf2:${'00'.repeat(16)}:${Buffer.from(bits).toString('hex')}`;
}

// One verified user, token_version 0. Everything else answers empty.
async function makeEnv() {
  const user = { id: 'u1', email: 'a@example.com', password_hash: await pbkdf2(PW), email_verified: 1, token_version: 0, newsletter_consent: 0, currency: 'USD', timezone: null };
  const DB = {
    prepare(sql) {
      let args = [];
      const stmt = {
        bind(...a) { args = a; return stmt; },
        async first() {
          if (/COUNT\(\*\)/.test(sql)) return { c: 0, n: 0 };
          if (/FROM users WHERE (email|id)\s*=\s*\?/.test(sql)) return (args[0] === user.email || args[0] === user.id) ? user : null;
          return null;
        },
        async all() { return { results: [] }; },
        async run() { return { meta: { changes: 1 } }; },
      };
      return stmt;
    },
    async batch(stmts) { return Promise.all(stmts.map(s => s.run())); },
  };
  return { JWT_SECRET: SECRET, DB, user };
}

function req(path, { method = 'GET', body, headers = {} } = {}) {
  const h = { 'CF-Connecting-IP': '203.0.113.9', ...headers };
  if (body !== undefined) h['Content-Type'] = 'application/json';
  return new Request(ORIGIN + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
}
async function call(r, env) {
  const resp = await worker.fetch(r, env, { waitUntil() {} });
  return { status: resp.status, setCookie: resp.headers.get('Set-Cookie') || '', body: await resp.json().catch(() => null) };
}
const cookieValue = (setCookie) => (new RegExp(`${COOKIE}=([^;]*)`).exec(setCookie) || [])[1];
const validJwt = (tv = 0) => hs256({ sub: 'u1', tv, exp: Math.floor(Date.now() / 1000) + 3600 });

test('login sets the HttpOnly session cookie and no longer returns the token', async () => {
  const env = await makeEnv();
  const r = await call(req('/api/auth/login', { method: 'POST', body: { email: 'a@example.com', password: PW }, headers: { Origin: ORIGIN } }), env);
  assert.equal(r.status, 200);
  assert.equal(r.body.token, undefined);
  assert.equal(r.body.user.email, 'a@example.com');
  assert.match(r.setCookie, /^sg_session=[\w-]+\.[\w-]+\.[\w-]+; /);
  for (const attr of ['Path=/', 'HttpOnly', 'Secure', 'SameSite=Lax', 'Max-Age=2592000']) assert.ok(r.setCookie.includes(attr), attr);
});

test('the cookie alone authenticates, and GET /api/me answers who it is', async () => {
  const env = await makeEnv();
  const r = await call(req('/api/me', { headers: { Cookie: `other=1; ${COOKIE}=${await validJwt()}` } }), env);
  assert.equal(r.status, 200);
  assert.equal(r.body.email, 'a@example.com');
  assert.equal(r.setCookie, '', 'a cookie session is not re-set on every request');
});

test('a valid Bearer token alone is refused: 401 and no cookie', async () => {
  const env = await makeEnv();
  const jwt = await validJwt();
  const r = await call(req('/api/me', { headers: { Authorization: `Bearer ${jwt}` } }), env);
  assert.equal(r.status, 401);
  assert.equal(r.setCookie, '', 'a Bearer token is never turned into a cookie');
});

test('a garbage cookie with a valid Bearer is still 401 and sets no cookie', async () => {
  const env = await makeEnv();
  const jwt = await validJwt();
  const r = await call(req('/api/me', { headers: { Cookie: `${COOKIE}=garbage`, Authorization: `Bearer ${jwt}` } }), env);
  assert.equal(r.status, 401);
  assert.equal(r.setCookie, '');
});

test('logout clears the cookie with the same attributes', async () => {
  const env = await makeEnv();
  const r = await call(req('/api/auth/logout', { method: 'POST', headers: { Origin: ORIGIN, Cookie: `${COOKIE}=${await validJwt()}` } }), env);
  assert.equal(r.status, 200);
  assert.match(r.setCookie, /^sg_session=; /);
  for (const attr of ['Path=/', 'HttpOnly', 'Secure', 'SameSite=Lax', 'Max-Age=0']) assert.ok(r.setCookie.includes(attr), attr);
});

test('logout with a revoked or garbage cookie still clears it', async () => {
  const env = await makeEnv();
  const r = await call(req('/api/auth/logout', { method: 'POST', headers: { Origin: ORIGIN, Cookie: `${COOKIE}=nope` } }), env);
  assert.equal(r.status, 200);
  assert.ok(r.setCookie.includes('Max-Age=0'));
});

test('cross-origin POST/PUT/DELETE carrying the cookie is refused with 403', async () => {
  const env = await makeEnv();
  const Cookie = `${COOKIE}=${await validJwt()}`;
  const body = { name: 'Netflix', monthly_cost: 15, cancelled_date: '2026-10-01' };
  for (const [method, path] of [['POST', '/api/subscriptions'], ['PUT', '/api/profile'], ['DELETE', '/api/subscriptions/x'], ['POST', '/api/auth/logout'], ['PUT', '/api/auth/password']]) {
    const evil = await call(req(path, { method, body, headers: { Cookie, Origin: 'https://evil.example' } }), env);
    assert.equal(evil.status, 403, `${method} ${path} from another origin`);
    const none = await call(req(path, { method, body, headers: { Cookie } }), env);
    assert.equal(none.status, 403, `${method} ${path} with no Origin or Referer`);
    const badRef = await call(req(path, { method, body, headers: { Cookie, Referer: 'https://subscriptiongraveyard.app.evil.example/' } }), env);
    assert.equal(badRef.status, 403, `${method} ${path} with a look-alike Referer`);
  }
});

test('same-origin POST with the cookie goes through (Origin or Referer)', async () => {
  const env = await makeEnv();
  const Cookie = `${COOKIE}=${await validJwt()}`;
  const body = { name: 'Netflix', monthly_cost: 15, cancelled_date: '2026-10-01' };
  const a = await call(req('/api/subscriptions', { method: 'POST', body, headers: { Cookie, Origin: ORIGIN } }), env);
  assert.equal(a.status, 200);
  const b = await call(req('/api/subscriptions', { method: 'POST', body, headers: { Cookie, Referer: ORIGIN + '/' } }), env);
  assert.equal(b.status, 200);
});

test('garbage, tampered, expired and revoked cookies get 401, never 500', async () => {
  const env = await makeEnv();
  const expired = await hs256({ sub: 'u1', tv: 0, exp: Math.floor(Date.now() / 1000) - 10 });
  const revoked = await validJwt(7);
  const forged = await hs256({ sub: 'u1', tv: 0, exp: Math.floor(Date.now() / 1000) + 3600 }, 'wrong-secret');
  const noSub = await hs256({ tv: 0, exp: Math.floor(Date.now() / 1000) + 3600 });
  const values = ['garbage', 'a.b.c', '...', '%%%', 'eyJ.eyJ.sig', '!!.@@.##', 'x'.repeat(5000), expired, revoked, forged, noSub, ''];
  for (const v of values) {
    const r = await call(req('/api/me', { headers: { Cookie: `${COOKIE}=${v}` } }), env);
    assert.equal(r.status, 401, `cookie ${String(v).slice(0, 20)} -> ${r.status}`);
  }
  const bearer = await call(req('/api/me', { headers: { Authorization: 'Bearer %%%.@@.!!' } }), env);
  assert.equal(bearer.status, 401);
  assert.equal(bearer.setCookie, '', 'a refused Bearer never sets a cookie');
});
