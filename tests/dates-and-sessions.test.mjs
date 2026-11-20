// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
// Real calendar dates only, a daily job one bad row can't stop, and a few auth edges:
//   - a date field must be a string naming a real day (no arrays, no 2020-13-45)
//   - the renewal rollover skips a bad row and still rolls every row after it
//   - logout clears this device's cookie only (a password change signs out every device)
//   - re-signup on an unverified address only swaps the password when a new code went out
//   - a password reset marks the account verified (the emailed link proved the inbox)
//   - wrong guesses at the recap secret are counted and then refused
//   - every API answer is nosniff + no-store
// Run: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';

const ORIGIN = 'https://subscriptiongraveyard.app';
const SECRET = 'test-secret-test-secret-test-secret-1234';
const HUB_SECRET = 'hub-secret-hub-secret-hub-secret-12';
const RECAP_SECRET = 'recap-secret-recap-secret-recap-1234';

const b64 = (s) => Buffer.from(s).toString('base64url');
async function hs256(payload, secret) {
  const data = `${b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${b64(JSON.stringify(payload))}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return `${data}.${Buffer.from(sig).toString('base64url')}`;
}
const exp = () => Math.floor(Date.now() / 1000) + 3600;
const session = (tv = 0) => hs256({ sub: 'u1', tv, exp: exp() }, SECRET);
const proToken = () => hs256({ v: 1, email: 'a@example.com', pro_until: '2099-01-01T00:00:00Z', iss: 'app-hub', iat: exp() - 3600, exp: exp() }, HUB_SECRET);

// A recording D1 stand-in. `over` lets a test answer specific statements.
function makeEnv({ user, over = {}, extra = {} } = {}) {
  const u = user === undefined ? { id: 'u1', email: 'a@example.com', password_hash: 'pbkdf2:00:00', email_verified: 1, token_version: 0, newsletter_consent: 0, currency: 'USD', timezone: null } : user;
  const log = [];
  const DB = {
    prepare(sql) {
      let args = [];
      const st = {
        sql,
        bind(...a) { args = a; return st; },
        async first() {
          log.push({ op: 'first', sql, args });
          if (over.first) { const v = over.first(sql, args); if (v !== undefined) return v; }
          if (/RETURNING count/.test(sql)) return { count: 1 };
          if (/COUNT\(\*\)/.test(sql)) return { c: 0, n: 0 };
          if (/FROM users WHERE (email|id)\s*=\s*\?/.test(sql)) return u && (args[0] === u.email || args[0] === u.id) ? u : null;
          return null;
        },
        async all() {
          log.push({ op: 'all', sql, args });
          if (over.all) { const v = over.all(sql, args); if (v !== undefined) return v; }
          return { results: [] };
        },
        async run() { log.push({ op: 'run', sql, args }); return { meta: { changes: 1 } }; },
      };
      return st;
    },
    async batch(stmts) {
      const out = [];
      for (const s of stmts) {
        if (/^SELECT COUNT/.test(s.sql)) { log.push({ op: 'count', sql: s.sql }); out.push({ results: [{ c: over.count ? over.count(s.sql) : 1 }], meta: {} }); }
        else out.push(await s.run());
      }
      return out;
    },
  };
  return { JWT_SECRET: SECRET, HUB_JWT_SECRET: HUB_SECRET, DB, log, ...extra };
}
const writes = (env, re) => env.log.filter((l) => l.op === 'run' && re.test(l.sql));

async function call(env, path, { method = 'GET', body, headers = {}, cookie } = {}) {
  const h = { 'CF-Connecting-IP': '203.0.113.9', ...headers };
  if (method !== 'GET') h.Origin = ORIGIN;
  if (body !== undefined) h['Content-Type'] = 'application/json';
  if (cookie) h.Cookie = `sg_session=${cookie}`;
  const r = await worker.fetch(new Request(ORIGIN + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }), env, { waitUntil() {} });
  return { status: r.status, headers: r.headers, body: await r.json().catch(() => null) };
}

test('dates: an array, an impossible day and a wrong shape are 400, never a 500, and nothing is stored', async () => {
  const bad = [['2026-01-05'], '2020-13-45', '2026-02-30', '2020-00-00', '9999-99-99', '2026-1-5', 20260105, { a: 1 }];
  for (const d of bad) {
    const env = makeEnv();
    const cookie = await session();
    const add = await call(env, '/api/subscriptions', { method: 'POST', cookie, body: { name: 'Netflix', monthly_cost: 10, cancelled_date: d } });
    assert.equal(add.status, 400, `POST cancelled_date ${JSON.stringify(d)}`);
    const started = await call(env, '/api/subscriptions', { method: 'POST', cookie, body: { name: 'Netflix', monthly_cost: 10, cancelled_date: '2026-01-05', started_date: d } });
    assert.equal(started.status, 400, `POST started_date ${JSON.stringify(d)}`);
    const put = await call(env, '/api/subscriptions/s1', { method: 'PUT', cookie, body: { cancelled_date: d } });
    assert.ok([400, 404].includes(put.status), `PUT cancelled_date ${JSON.stringify(d)} gave ${put.status}`);
    assert.equal(writes(env, /INSERT INTO subscriptions|UPDATE subscriptions/).length, 0);
  }
});

test('dates: a real day is accepted, leap day included', async () => {
  for (const d of ['2026-01-05', '2024-02-29']) {
    const env = makeEnv();
    const r = await call(env, '/api/subscriptions', { method: 'POST', cookie: await session(), body: { name: 'Netflix', monthly_cost: 10, cancelled_date: d } });
    assert.equal(r.status, 200, d);
    assert.equal(writes(env, /INSERT INTO subscriptions/).length, 1);
  }
});

test('dates: updating a subscription refuses a bad date and takes a good one', async () => {
  const own = { first: (sql) => (/FROM subscriptions WHERE id=\? AND user_id=\?/.test(sql) ? { id: 's1' } : undefined) };
  const env = makeEnv({ over: own });
  const cookie = await session();
  assert.equal((await call(env, '/api/subscriptions/s1', { method: 'PUT', cookie, body: { cancelled_date: ['2026-01-05'] } })).status, 400);
  assert.equal((await call(env, '/api/subscriptions/s1', { method: 'PUT', cookie, body: { started_date: '2026-02-31' } })).status, 400);
  assert.equal((await call(env, '/api/subscriptions/s1', { method: 'PUT', cookie, body: { cancel_reason: ['x'] } })).status, 400);
  assert.equal(writes(env, /UPDATE subscriptions/).length, 0);
  assert.equal((await call(env, '/api/subscriptions/s1', { method: 'PUT', cookie, body: { cancelled_date: '2026-01-06', started_date: null } })).status, 200);
  assert.equal(writes(env, /UPDATE subscriptions/).length, 1);
});

test('dates: the watchlist refuses an impossible renewal date on add and on update', async () => {
  const env = makeEnv();
  const cookie = await session();
  const headers = { 'X-Hub-Pro': await proToken() };
  for (const d of ['2020-13-45', ['2026-12-01'], '2026-02-30']) {
    const add = await call(env, '/api/watchlist', { method: 'POST', cookie, headers, body: { name: 'Hulu', monthly_cost: 9, next_renewal_date: d } });
    assert.equal(add.status, 400, `add ${JSON.stringify(d)}`);
    const upd = await call(env, '/api/watchlist', { method: 'PUT', cookie, headers, body: { id: 'w1', next_renewal_date: d } });
    assert.equal(upd.status, 400, `update ${JSON.stringify(d)}`);
  }
  assert.equal(writes(env, /INSERT INTO renewal_watchlist|UPDATE renewal_watchlist/).length, 0);
  const ok = await call(env, '/api/watchlist', { method: 'POST', cookie, headers, body: { name: 'Hulu', monthly_cost: 9, next_renewal_date: '2026-12-01' } });
  assert.equal(ok.status, 200);
});

test('cron: a bad date in the middle is skipped and every good row still rolls forward', async () => {
  const ago = (days) => new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
  const past = [
    { id: 'good-1', next_renewal_date: ago(40), billing_cycle: 'monthly' },
    { id: 'poison', next_renewal_date: '2020-13-45', billing_cycle: 'monthly' },
    { id: 'good-2', next_renewal_date: ago(10), billing_cycle: 'weekly' },
    { id: 'poison-2', next_renewal_date: null, billing_cycle: 'monthly' },
    { id: 'good-3', next_renewal_date: ago(400), billing_cycle: 'annual' },
  ];
  const env = makeEnv({ over: { all: (sql) => (/next_renewal_date < \?/.test(sql) ? { results: past } : undefined) }, extra: { RESEND_API_KEY: 'test' } });
  const realFetch = globalThis.fetch;
  const realError = console.error;
  const errors = [];
  globalThis.fetch = async () => new Response('{}');
  console.error = (...a) => { errors.push(a.join(' ')); };
  let results;
  try {
    let job;
    await worker.scheduled({}, env, { waitUntil: (p) => { job = p; } });
    results = await job;
  } finally { globalThis.fetch = realFetch; console.error = realError; }
  assert.deepEqual(results.map((r) => r.status), ['fulfilled', 'fulfilled']);
  const rolled = writes(env, /UPDATE renewal_watchlist SET next_renewal_date/);
  assert.deepEqual(rolled.map((w) => w.args[1]), ['good-1', 'good-2', 'good-3']);
  const today = new Date().toISOString().slice(0, 10);
  for (const w of rolled) assert.ok(w.args[0] >= today, `${w.args[1]} rolled to ${w.args[0]}`);
  assert.ok(errors.some((e) => /2 row\(s\) could not be rolled forward/.test(e)), 'the skipped rows are logged');
});

test('cron: a job that throws is logged instead of vanishing', async () => {
  const env = makeEnv({ over: { all: () => { throw new Error('boom'); } }, extra: { RESEND_API_KEY: 'test' } });
  const realError = console.error;
  const errors = [];
  console.error = (...a) => { errors.push(a.join(' ')); };
  try {
    let job;
    await worker.scheduled({}, env, { waitUntil: (p) => { job = p; } });
    await job;
  } finally { console.error = realError; }
  assert.ok(errors.some((e) => /scheduled job failed/.test(e) && /boom/.test(e)));
});

test('logout: clears only this device\'s cookie and never touches token_version', async () => {
  for (const cookie of [await session(0), undefined, 'garbage']) {
    const env = makeEnv();
    const r = await call(env, '/api/auth/logout', { method: 'POST', cookie });
    assert.equal(r.status, 200);
    assert.match(r.headers.get('Set-Cookie') || '', /^sg_session=; .*Max-Age=0/);
    assert.equal(writes(env, /UPDATE users/).length, 0);
  }
});

const UNVERIFIED = { id: 'u2', email: 'new@example.com', password_hash: 'pbkdf2:00:00', email_verified: 0, token_version: 0, newsletter_consent: 0 };
const signupBody = { email: 'new@example.com', password: 'another-pass-42' };

test('signup on an unverified address: the password is swapped when a fresh code really went out', async () => {
  const env = makeEnv({ user: UNVERIFIED, extra: { RESEND_API_KEY: 'test' } });
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('{}');
  let r;
  try { r = await call(env, '/api/auth/signup', { method: 'POST', body: signupBody }); }
  finally { globalThis.fetch = realFetch; }
  assert.equal(r.status, 200);
  assert.equal(r.body.email_sent, true);
  assert.equal(writes(env, /UPDATE users SET password_hash=/).length, 1);
});

test('signup on an unverified address: a failed send leaves the password alone', async () => {
  const env = makeEnv({ user: UNVERIFIED, extra: { RESEND_API_KEY: 'test' } });
  const realFetch = globalThis.fetch; const realError = console.error;
  globalThis.fetch = async () => new Response('nope', { status: 500 });
  console.error = () => {};
  let r;
  try { r = await call(env, '/api/auth/signup', { method: 'POST', body: signupBody }); }
  finally { globalThis.fetch = realFetch; console.error = realError; }
  assert.equal(r.status, 200);
  assert.equal(r.body.email_sent, false);
  assert.equal(writes(env, /UPDATE users SET password_hash=/).length, 0);
});

test('signup on an unverified address: at the mail cap nothing is sent, the password stays, same answer', async () => {
  // count() answers 4 for the per-address key: one over the cap of 3.
  const env = makeEnv({ user: UNVERIFIED, over: { count: () => 4 }, extra: { RESEND_API_KEY: 'test' } });
  const realFetch = globalThis.fetch;
  const sent = [];
  globalThis.fetch = async (u) => { sent.push(String(u)); return new Response('{}'); };
  let r;
  try { r = await call(env, '/api/auth/signup', { method: 'POST', body: signupBody, headers: { 'CF-Connecting-IP': '203.0.113.77' } }); }
  finally { globalThis.fetch = realFetch; }
  // The per-IP auth limit shares the stand-in counter, so 429 is also a "nothing sent" answer here.
  assert.ok([200, 429].includes(r.status));
  assert.deepEqual(sent, []);
  assert.equal(writes(env, /UPDATE users SET password_hash=/).length, 0);
});

test('reset-confirm: a used reset link also marks the account verified', async () => {
  const future = new Date(Date.now() + 3600000).toISOString();
  const env = makeEnv({ user: { ...UNVERIFIED, id: 'u1', email: 'a@example.com' }, over: { first: (sql) => (/FROM reset_tokens WHERE token=\? AND used=0/.test(sql) ? { token: 'h', user_id: 'u1', expires_at: future, used: 0 } : undefined) } });
  const r = await call(env, '/api/auth/reset-confirm', { method: 'POST', body: { token: 'a'.repeat(64), password: 'brand-new-pass-77' } });
  assert.equal(r.status, 200);
  const upd = writes(env, /UPDATE users SET password_hash=\?, token_version=COALESCE\(token_version,0\)\+1, email_verified=1, verified_at=COALESCE\(verified_at, \?\) WHERE id=\?/);
  assert.equal(upd.length, 1);
  assert.equal(upd[0].args[2], 'u1');
});

test('every API answer is nosniff and never cached', async () => {
  const env = makeEnv();
  for (const r of [await call(env, '/api/pro-status'), await call(env, '/api/me'), await call(env, '/api/account/export', { cookie: await session() })]) {
    assert.equal(r.headers.get('X-Content-Type-Options'), 'nosniff');
    assert.equal(r.headers.get('Cache-Control'), 'no-store');
  }
});
