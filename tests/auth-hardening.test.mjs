// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
// Auth hardening: no account oracle on verify-code, bad bodies
// answer 4xx (never a 500 + alert email), hashed IPs in rate-limit rows,
// security event log lines, password change keeps you logged in, daily purge.
// Run: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';

function fakeDB(handler) {
  const log = [];
  return {
    log,
    prepare(sql) {
      let args = [];
      const stmt = {
        sql, get args() { return args; },
        bind(...a) { args = a; return stmt; },
        async first() { log.push({ sql, args }); return handler(sql, args, 'first') ?? null; },
        async all() { log.push({ sql, args }); return handler(sql, args, 'all') ?? { results: [] }; },
        async run() { log.push({ sql, args }); return handler(sql, args, 'run') ?? { meta: { changes: 1 } }; },
      };
      return stmt;
    },
    async batch(stmts) { return Promise.all(stmts.map(s => s.run())); },
  };
}
function b64(s) { return Buffer.from(s).toString('base64url'); }
async function hs256(payload, secret) {
  const data = `${b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${b64(JSON.stringify(payload))}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return `${data}.${Buffer.from(sig).toString('base64url')}`;
}
const ORIGIN = 'https://subscriptiongraveyard.app';
const IP = '203.0.113.77';
function post(path, body, headers = {}) {
  return new Request(ORIGIN + path, {
    method: headers.method || 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN, 'CF-Connecting-IP': IP, ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}
async function call(req, env) {
  const r = await worker.fetch(req, env, { waitUntil() {} });
  return { status: r.status, headers: r.headers, body: await r.json().catch(() => null) };
}
async function captureLogs(fn) {
  const lines = [];
  const orig = console.log;
  console.log = (...a) => lines.push(a.join(' '));
  try { await fn(); } finally { console.log = orig; }
  return lines;
}

test('verify-code: unknown email and already-verified email get the same 400', async () => {
  const mk = (user) => ({ JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB: fakeDB((sql) => /FROM users WHERE email/.test(sql) ? user : undefined) });
  const a = await call(post('/api/auth/verify-code', { email: 'nobody@example.com', code: '123456', password: 'whatever-pw-1' }), mk(null));
  const b = await call(post('/api/auth/verify-code', { email: 'real@example.com', code: '123456', password: 'whatever-pw-1' }), mk({ id: 'u1', email: 'real@example.com', email_verified: 1, token_version: 0 }));
  assert.equal(a.status, 400);
  assert.equal(b.status, 400);
  assert.deepEqual(a.body, b.body);
  assert.doesNotMatch(a.body.error, /[—;]/);
});

test('a JSON null / array / oversized body is a 4xx, never a 500', async () => {
  const env = { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB: fakeDB(() => undefined) };
  for (const path of ['/api/auth/verify-code', '/api/auth/resend-verification', '/api/auth/reset-request', '/api/auth/hub-sso']) {
    for (const body of ['null', '[]', '7', '{bad']) {
      const r = await call(post(path, body), env);
      assert.ok(r.status < 500, `${path} ${body} -> ${r.status}`);
    }
  }
  // Chunked body over 64 KB with no Content-Length: readJson refuses it.
  const big = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode(JSON.stringify({ email: 'a@b.co', password: 'x'.repeat(70000) }))); c.close(); } });
  const req = new Request(ORIGIN + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: ORIGIN }, body: big, duplex: 'half' });
  const r = await call(req, env);
  assert.equal(r.status, 400);
});

test('per-IP rate-limit rows never store the raw IP', async () => {
  const env = { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB: fakeDB(() => undefined) };
  await call(post('/api/auth/reset-request', { email: 'x@example.com' }), env);
  const inserts = env.DB.log.filter(l => /INSERT INTO rate_limits/.test(l.sql));
  assert.ok(inserts.length > 0);
  for (const l of inserts) assert.ok(!String(l.args[0]).includes(IP), `raw IP in key ${l.args[0]}`);
});

test('failed login writes one hashed auth log line, no raw email or IP', async () => {
  const env = { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB: fakeDB(() => undefined) };
  const lines = await captureLogs(() => call(post('/api/auth/login', { email: 'who@example.com', password: 'wrong-password-123' }), env));
  const evts = lines.filter(l => l.includes('"evt":"auth"')).map(l => JSON.parse(l));
  assert.equal(evts.length, 1);
  assert.equal(evts[0].type, 'login_fail');
  assert.ok(evts[0].email_hash && evts[0].ip_hash);
  assert.ok(!lines.join('\n').includes('who@example.com'));
  assert.ok(!lines.join('\n').includes(IP));
});

test('password change sets a fresh session cookie for the new token_version and logs it', async () => {
  // Password "correct-horse-1" hashed with the worker's own PBKDF2 scheme.
  const salt = new Uint8Array(16);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode('correct-horse-1'), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  const stored = `pbkdf2:${'00'.repeat(16)}:${Buffer.from(bits).toString('hex')}`;
  let tv = 0;
  const env = {
    JWT_SECRET: 'test-secret-test-secret-test-secret-1234',
    DB: fakeDB((sql) => {
      if (/SELECT token_version FROM users/.test(sql)) return { token_version: tv };
      if (/SELECT (email, )?password_hash FROM users/.test(sql)) return { email: 'a@example.com', password_hash: stored };
      if (/UPDATE users SET password_hash/.test(sql)) { tv += 1; return { meta: { changes: 1 } }; }
      return undefined;
    }),
  };
  const token = await hs256({ sub: 'u1', tv: 0, exp: Math.floor(Date.now() / 1000) + 3600 }, env.JWT_SECRET);
  let r;
  const lines = await captureLogs(async () => {
    r = await call(post('/api/auth/password', { current_password: 'correct-horse-1', password: 'new-password-22' }, { method: 'PUT', Cookie: `sg_session=${token}` }), env);
  });
  assert.equal(r.status, 200);
  assert.equal(r.body.token, undefined);
  const cookie = /sg_session=([^;]+)/.exec(r.headers.get('Set-Cookie') || '');
  assert.ok(cookie, 'Set-Cookie carries the new session');
  const payload = JSON.parse(Buffer.from(cookie[1].split('.')[1], 'base64url').toString());
  assert.equal(payload.tv, 1);
  assert.ok(lines.some(l => l.includes('"type":"password_change"')));
});

test('daily cron purges expired rate limits and week-old tokens', async () => {
  const env = { DB: fakeDB((sql) => /renewal_watchlist/.test(sql) ? { results: [] } : undefined) };
  let job;
  await worker.scheduled({}, env, { waitUntil: (p) => { job = p; } });
  await job;
  const sqls = env.DB.log.map(l => l.sql).join('\n');
  assert.match(sqls, /DELETE FROM rate_limits WHERE expires_at < \?/);
  assert.match(sqls, /DELETE FROM reset_tokens WHERE expires_at < \?/);
  assert.match(sqls, /DELETE FROM email_verification_tokens WHERE expires_at < \?/);
});

test('account delete: App Hub accounts with no password can delete with the hub token + DELETE', async () => {
  const deleted = [];
  const env = {
    JWT_SECRET: 'test-secret-test-secret-test-secret-1234', HUB_JWT_SECRET: 'hub-secret-hub-secret-hub-secret-12',
    DB: fakeDB((sql, args) => {
      if (/SELECT token_version FROM users/.test(sql)) return { token_version: 0 };
      if (/SELECT email, password_hash FROM users/.test(sql)) return { email: 'Hub@Example.com', password_hash: 'sentinel:never-matches' };
      if (/^DELETE FROM (users|subscriptions|death_row|renewal_watchlist) /.test(sql)) deleted.push(sql);
      return undefined;
    }),
  };
  const session = await hs256({ sub: 'u1', tv: 0, exp: Math.floor(Date.now() / 1000) + 3600 }, env.JWT_SECRET);
  const now = Math.floor(Date.now() / 1000);
  const hubFor = (email) => hs256({ v: 1, email, pro_until: null, iss: 'app-hub', iat: now, exp: now + 3600 }, env.HUB_JWT_SECRET);
  const del = (body) => call(post('/api/auth/account', body, { method: 'DELETE', Cookie: `sg_session=${session}` }), env);

  let r = await del({ hub_pro_jwt: await hubFor('hub@example.com') });
  assert.equal(r.status, 400, 'missing DELETE confirm');
  r = await del({ hub_pro_jwt: await hubFor('someone-else@example.com'), confirm: 'DELETE' });
  assert.equal(r.status, 401, 'hub token for another email');
  r = await del({ hub_pro_jwt: 'not.a.jwt', confirm: 'DELETE' });
  assert.equal(r.status, 401, 'forged hub token');
  r = await del({ current_password: 'wrong-password-1' });
  assert.equal(r.status, 401, 'password path still checks the password');
  assert.equal(deleted.length, 0);

  r = await del({ hub_pro_jwt: await hubFor('hub@example.com'), confirm: 'DELETE' });
  assert.equal(r.status, 200);
  assert.ok(deleted.some(s => /DELETE FROM users WHERE id=\?/.test(s)));
  assert.match(r.headers.get('Set-Cookie') || '', /sg_session=;|Max-Age=0/);
});
