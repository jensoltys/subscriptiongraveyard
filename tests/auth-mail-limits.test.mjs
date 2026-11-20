// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
// Auth mail limits: verify-code needs the password, per-address and daily caps
// on auth mail, and the feedback relay. Run: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';

const ORIGIN = 'https://subscriptiongraveyard.app';
let ipN = 0;
function post(path, body, ip) {
  return new Request(ORIGIN + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN, 'CF-Connecting-IP': ip || `198.51.100.${++ipN % 250}` },
    body: JSON.stringify(body),
  });
}
async function call(req, env) {
  const r = await worker.fetch(req, env, { waitUntil() {} });
  return { status: r.status, body: await r.json().catch(() => null) };
}
async function sha256Hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function hashPw(pw) {
  const salt = new Uint8Array(16).fill(7);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return `pbkdf2:${'07'.repeat(16)}:${[...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('')}`;
}

// Small in-memory D1 stand-in covering only the statements these routes run.
function memDB(state) {
  const log = [];
  return {
    log,
    prepare(sql) {
      let a = [];
      const st = {
        sql,
        bind(...x) { a = x; return st; },
        async first() { log.push(sql); return exec(sql, a, state); },
        async run() { log.push(sql); const r = exec(sql, a, state); return { meta: { changes: r && r.changes !== undefined ? r.changes : 1 } }; },
        async all() { log.push(sql); return { results: [] }; },
      };
      return st;
    },
    // Like D1: one transaction, statements in order, a SELECT answers with results.
    async batch(sts) { const out = []; for (const s of sts) out.push(/^\s*SELECT/i.test(s.sql) ? { results: [await s.first()] } : await s.run()); return out; },
  };
}
function exec(sql, a, st) {
  st.rl ||= []; st.daily ||= {};
  if (/^DELETE FROM rate_limits/.test(sql)) return null;
  if (/SELECT COUNT\(\*\) as c FROM rate_limits/.test(sql)) return { c: st.rl.filter(r => r.key === a[0] && r.t > a[1]).length };
  if (/INSERT INTO rate_limits/.test(sql)) { st.rl.push({ key: a[0], t: a[1] }); return null; }
  if (/INSERT INTO daily_send_counts/.test(sql)) { st.daily[a[0]] = (st.daily[a[0]] || 0) + 1; return { count: st.daily[a[0]] }; }
  if (/FROM users WHERE email/.test(sql)) return st.user && st.user.email === a[0] ? st.user : null;
  if (/^SELECT token FROM email_verification_tokens/.test(sql)) return st.codeHash && a.includes(st.codeHash) ? { token: st.codeHash } : null;
  if (/UPDATE users SET email_verified/.test(sql)) {
    // Mirrors the conditional WHERE: still unverified + same hash + same tv.
    const u = st.user;
    if (st.raceLost || !u || u.email_verified || a[2] !== u.password_hash || a[3] !== (u.token_version ?? 0)) return { changes: 0 };
    st.verified = true; return { changes: 1 };
  }
  return null;
}

test('verify-code: missing password 400, wrong password 400 (no verify, no session), right password 200', async () => {
  const user = { id: 'u1', email: 'v@example.com', email_verified: 0, token_version: 0, newsletter_consent: 0, password_hash: await hashPw('right-password-1') };
  const state = { user, codeHash: await sha256Hex('u1:123456') };
  const env = { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB: memDB(state) };

  const none = await call(post('/api/auth/verify-code', { email: 'v@example.com', code: '123456' }), env);
  assert.equal(none.status, 400);
  assert.equal(none.body.error, 'Enter your password along with the code.');

  const wrong = await call(post('/api/auth/verify-code', { email: 'v@example.com', code: '123456', password: 'attacker-pw-99' }), env);
  assert.equal(wrong.status, 400);
  assert.match(wrong.body.error, /password doesn't match/);
  assert.equal(state.verified, undefined);

  const r = await worker.fetch(post('/api/auth/verify-code', { email: 'v@example.com', code: '123456', password: 'right-password-1' }), env, { waitUntil() {} });
  assert.equal(r.status, 200);
  assert.ok(state.verified);
  assert.match(r.headers.get('Set-Cookie') || '', /sg_session=/);
});

test('verify-code: losing the race (row changed after the check) is the generic 400, no session', async () => {
  const user = { id: 'u1', email: 'v@example.com', email_verified: 0, token_version: 0, newsletter_consent: 0, password_hash: await hashPw('right-password-1') };
  const state = { user, codeHash: await sha256Hex('u1:123456'), raceLost: true };
  const r = await worker.fetch(post('/api/auth/verify-code', { email: 'v@example.com', code: '123456', password: 'right-password-1' }), { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB: memDB(state) }, { waitUntil() {} });
  assert.equal(r.status, 400);
  assert.match((await r.json()).error, /code is invalid/);
  assert.equal(r.headers.get('Set-Cookie'), null);
  assert.equal(state.verified, undefined);
});

test('verify-code: a wrong code never reaches the password check', async () => {
  const state = { user: { id: 'u1', email: 'v@example.com', email_verified: 0, token_version: 0, password_hash: await hashPw('right-password-1') }, codeHash: await sha256Hex('u1:123456') };
  const r = await call(post('/api/auth/verify-code', { email: 'v@example.com', code: '654321', password: 'right-password-1' }), { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB: memDB(state) });
  assert.equal(r.status, 400);
  assert.match(r.body.error, /code is invalid/);
});

test('legacy verify-email link no longer verifies anything', async () => {
  const env = { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB: memDB({}) };
  const r = await worker.fetch(new Request(ORIGIN + '/api/auth/verify-email?token=abc'), env, { waitUntil() {} });
  assert.equal(r.status, 200);
  assert.match(await r.text(), /expired/);
  assert.equal(env.DB.log.length, 0);
});

test('reset-request: 4th mail to one address in 15 min sends nothing, same generic answer', async () => {
  const state = { user: { id: 'u1', email: 'r@example.com' } };
  const env = { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB: memDB(state) };
  for (let i = 0; i < 4; i++) {
    const r = await call(post('/api/auth/reset-request', { email: 'r@example.com' }), env);
    assert.equal(r.status, 200);
    assert.deepEqual(r.body, { success: true });
  }
  const tokenWrites = env.DB.log.filter(s => /INTO reset_tokens/.test(s)).length;
  assert.equal(tokenWrites, 3);
});

test('junk requests for unknown addresses charge neither the per-address cap nor the ceiling', async () => {
  const st = {};
  const env = { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB: memDB(st) };
  for (let i = 0; i < 5; i++) await call(post('/api/auth/reset-request', { email: 'nobody@example.com' }), env);
  assert.deepEqual(st.daily || {}, {});
  assert.equal((st.rl || []).filter(r => /-email:/.test(r.key)).length, 0);
});

test('reset-request: daily ceiling stops sends and reads the same as an unknown email', async () => {
  const day = new Date().toISOString().slice(0, 10);
  const state = { user: { id: 'u1', email: 'r@example.com' }, daily: { [`reset:${day}`]: 150 } };
  const env = { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB: memDB(state) };
  const r = await call(post('/api/auth/reset-request', { email: 'r@example.com' }), env);
  assert.deepEqual(r.body, { success: true });
  assert.equal(env.DB.log.filter(s => /INTO reset_tokens/.test(s)).length, 0);
  assert.equal(state.daily[day], undefined, 'renewal budget row untouched');
});

test('signup at the per-address cap: normal 200 answer, no code stored, same for known and unknown', async () => {
  const bodies = [];
  for (const user of [null, { id: 'u1', email: 's@example.com', email_verified: 0 }, { id: 'u1', email: 's@example.com', email_verified: 1 }]) {
    const now = Math.floor(Date.now() / 1000);
    const st = { user, rl: [1, 2, 3].map(() => ({ key: 'verify-email:s@example.com', t: now })) };
    const env = { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB: memDB(st) };
    const r = await call(post('/api/auth/signup', { email: 's@example.com', password: 'long-enough-pw' }), env);
    assert.equal(r.status, 200);
    bodies.push(r.body);
    assert.equal(env.DB.log.filter(q => /INTO email_verification_tokens/.test(q)).length, 0);
  }
  assert.deepEqual(bodies[0], bodies[1]);
  assert.deepEqual(bodies[1], bodies[2]);
  assert.equal(bodies[0].email_sent, true);
});

test('resend at the verify ceiling: normal 200 answer, nothing sent', async () => {
  const day = new Date().toISOString().slice(0, 10);
  const st = { user: { id: 'u1', email: 'x@example.com', email_verified: 0 }, daily: { [`verify:${day}`]: 150 } };
  const env = { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB: memDB(st) };
  const r = await call(post('/api/auth/resend-verification', { email: 'x@example.com' }), env);
  assert.equal(r.status, 200);
  assert.equal(r.body.email_sent, true);
  assert.equal(env.DB.log.filter(q => /INTO email_verification_tokens/.test(q)).length, 0);
});

test('feedback relay: forwards the widget payload shape, honeypot skips, 6th call is 429', async () => {
  const sent = [];
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => { sent.push({ url, body: JSON.parse(init.body) }); return new Response('{}', { status: 200 }); };
  try {
    const env = { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', APP_NAME: 'Subscription Graveyard', FEEDBACK_WEBHOOK_URL: 'https://example.invalid/hook', DB: memDB({}) };
    const ip = '192.0.2.9';
    const hp = await call(post('/api/feedback', { message: 'bot text', website: 'x' }, ip), env);
    assert.equal(hp.status, 200);
    assert.equal(sent.length, 0);
    for (let i = 0; i < 4; i++) {
      const r = await call(post('/api/feedback', { type: 'bug', message: 'The button is broken', email: '', url: ORIGIN + '/' }, ip), env);
      assert.equal(r.status, 200);
    }
    assert.deepEqual(Object.keys(sent[0].body).sort(), ['app', 'email', 'message', 'type', 'url', 'user_agent']);
    assert.equal(sent[0].body.app, 'Subscription Graveyard');
    const sixth = await call(post('/api/feedback', { type: 'bug', message: 'again' }, ip), env);
    assert.equal(sixth.status, 429);
  } finally { globalThis.fetch = origFetch; }
});

test('feedback relay: cross-origin POST is refused', async () => {
  const env = { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB: memDB({}) };
  const req = new Request(ORIGIN + '/api/feedback', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' }, body: '{"message":"hello"}' });
  const r = await worker.fetch(req, env, { waitUntil() {} });
  assert.equal(r.status, 403);
});
