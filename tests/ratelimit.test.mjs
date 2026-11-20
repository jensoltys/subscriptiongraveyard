// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
// Rate limits under a parallel burst. The old
// limiter counted, then inserted, as separate statements, so 20 requests at
// once all read "under the cap". Now each hit is recorded and counted in one
// D1 batch. This fake lets single statements interleave (each waits a tick,
// like a network round trip) but runs a batch as one unit, like D1.
// Run: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';

const ORIGIN = 'https://subscriptiongraveyard.app';
const tick = () => new Promise(r => setImmediate(r));

function burstDB(state) {
  state.rl ||= [];
  function exec(sql, a) {
    if (/^DELETE FROM rate_limits WHERE expires_at/.test(sql)) { state.rl = state.rl.filter(r => r.exp >= a[0]); return { changes: 0 }; }
    if (/^DELETE FROM rate_limits WHERE key/.test(sql)) { state.rl = state.rl.filter(r => r.key !== a[0]); return { changes: 1 }; }
    if (/^INSERT INTO rate_limits/.test(sql)) { state.rl.push({ key: a[0], t: a[1], exp: a[2] }); return { changes: 1 }; }
    if (/^SELECT COUNT\(\*\) as c FROM rate_limits/.test(sql)) return { c: state.rl.filter(r => r.key === a[0] && r.t > a[1]).length };
    if (/^UPDATE reset_tokens SET used=1 WHERE token=\? AND used=0/.test(sql)) {
      const t = state.tokens.find(t => t.token === a[0] && !t.used); if (t) t.used = 1; return { changes: t ? 1 : 0 };
    }
    if (/^UPDATE reset_tokens SET used=1 WHERE user_id/.test(sql)) {
      let n = 0; for (const t of state.tokens) if (t.user_id === a[0] && !t.used) { t.used = 1; n++; } return { changes: n };
    }
    if (/^SELECT \* FROM reset_tokens/.test(sql)) return state.tokens.find(t => t.token === a[0] && !t.used) || null;
    if (/FROM users WHERE id=/.test(sql)) return state.user || null;
    if (/FROM users WHERE email/.test(sql)) return state.user && state.user.email === a[0] ? state.user : null;
    if (/^SELECT token FROM email_verification_tokens/.test(sql)) return !state.burned && state.codeHash && a.includes(state.codeHash) ? { token: state.codeHash } : null;
    if (/^UPDATE email_verification_tokens SET used=1 WHERE user_id/.test(sql)) { state.burned = true; return { changes: 1 }; }
    return null;
  }
  return {
    prepare(sql) {
      let a = [];
      const st = {
        sql,
        bind(...x) { a = x; return st; },
        async first() { await tick(); return exec(sql, a); },
        async run() { await tick(); const r = exec(sql, a); return { meta: { changes: r?.changes ?? 1 } }; },
        async all() { await tick(); return { results: [] }; },
        _now() { return exec(sql, a); },
      };
      return st;
    },
    async batch(sts) {
      await tick();
      return sts.map(s => /^\s*SELECT/i.test(s.sql) ? { results: [s._now()] } : { meta: { changes: s._now()?.changes ?? 1 } });
    },
  };
}
const post = (path, body, i) => new Request(ORIGIN + path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Origin: ORIGIN, 'CF-Connecting-IP': `203.0.113.${i}` },
  body: JSON.stringify(body),
});
const env = (state) => ({ JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB: burstDB(state) });
const ctx = { waitUntil() {} };

test('burst: 20 parallel resend-code requests for one address, exactly 1 gets through', async () => {
  const e = env({});
  const out = await Promise.all(Array.from({ length: 20 }, (_, i) =>
    worker.fetch(post('/api/auth/resend-verification', { email: 'burst@example.com' }, i), e, ctx).then(r => r.status)));
  assert.equal(out.filter(s => s === 200).length, 1, `statuses: ${out.join(',')}`);
  assert.equal(out.filter(s => s === 429).length, 19);
});

test('burst: 20 parallel code guesses for one address, exactly 8 checked, 12 refused, no 500', async () => {
  const e = env({});
  const out = await Promise.all(Array.from({ length: 20 }, (_, i) =>
    worker.fetch(post('/api/auth/verify-code', { email: 'guess@example.com', code: '000000', password: 'whatever-password' }, i), e, ctx).then(r => r.status)));
  assert.equal(out.filter(s => s === 400).length, 8, `statuses: ${out.join(',')}`);
  assert.equal(out.filter(s => s === 429).length, 12);
  assert.ok(!out.some(s => s >= 500));
});

test('reset: one used link kills every other reset link for that user', async () => {
  const sha = async (s) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map(b => b.toString(16).padStart(2, '0')).join('');
  const exp = new Date(Date.now() + 3600000).toISOString();
  const state = {
    user: { id: 'u1', email: 'r@example.com', newsletter_consent: 0, token_version: 1 },
    tokens: [{ token: await sha('a'.repeat(64)), user_id: 'u1', expires_at: exp, used: 0 },
             { token: await sha('b'.repeat(64)), user_id: 'u1', expires_at: exp, used: 0 }],
  };
  const r = await worker.fetch(post('/api/auth/reset-confirm', { token: 'a'.repeat(64), password: 'new-password-123' }, 1), env(state), ctx);
  assert.equal(r.status, 200);
  assert.ok(state.tokens.every(t => t.used === 1), 'second link still live');
  const again = await worker.fetch(post('/api/auth/reset-confirm', { token: 'b'.repeat(64), password: 'other-password-123' }, 2), env(state), ctx);
  assert.equal(again.status, 400);
});

test('verify-code: 5 wrong guesses burn the code, junk for unknown addresses costs nothing', async () => {
  const sha = async (s) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map(b => b.toString(16).padStart(2, '0')).join('');
  const state = { user: { id: 'u9', email: 'new@example.com', email_verified: 0, token_version: 0, password_hash: 'pbkdf2:00:00' }, codeHash: await sha('u9:123456') };
  const e = env(state);
  for (let i = 0; i < 3; i++) await worker.fetch(post('/api/auth/verify-code', { email: 'other@example.com', code: '111111', password: 'x-password-1' }, 40 + i), e, ctx);
  assert.equal(state.rl.filter(r => r.key.startsWith('verify-miss')).length, 0, 'unknown address charged a budget');
  for (let i = 0; i < 4; i++) await worker.fetch(post('/api/auth/verify-code', { email: 'new@example.com', code: '000000', password: 'x-password-1' }, 50 + i), e, ctx);
  assert.equal(state.burned, undefined, 'burned after only 4 misses');
  await worker.fetch(post('/api/auth/verify-code', { email: 'new@example.com', code: '000000', password: 'x-password-1' }, 60), e, ctx);
  assert.equal(state.burned, true, 'code still live after 5 misses');
});
