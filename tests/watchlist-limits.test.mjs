// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
// Watchlist row cap + renewal-warning send budget.
// Run: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';
import { planFairSends, claimDailySends, WATCHLIST_MAX_PER_USER, DAILY_SEND_MAX } from '../src/lib/send-budget.js';

// Tiny D1 stand-in: every statement goes through `handler(sql, args, kind)`.
function fakeDB(handler) {
  const log = [];
  return {
    log,
    prepare(sql) {
      let args = [];
      const stmt = {
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

// In-memory daily_send_counts table.
function counterTable(start = {}) {
  const rows = { ...start };
  return {
    rows,
    handle(sql, args) {
      if (/INSERT OR IGNORE INTO daily_send_counts/.test(sql)) { if (!(args[0] in rows)) rows[args[0]] = 0; return { meta: { changes: 1 } }; }
      if (/SELECT count FROM daily_send_counts/.test(sql)) return args[0] in rows ? { count: rows[args[0]] } : null;
      if (/UPDATE daily_send_counts/.test(sql)) {
        const [n, day, n2, max] = args;
        if (rows[day] + n2 <= max) { rows[day] += n; return { meta: { changes: 1 } }; }
        return { meta: { changes: 0 } };
      }
      if (/DELETE FROM daily_send_counts/.test(sql)) return { meta: { changes: 0 } };
      return undefined;
    },
  };
}

const today = () => new Date().toISOString().slice(0, 10);
const inDays = (n) => new Date(Date.parse(today()) + n * 86400000).toISOString().slice(0, 10);

test('claimDailySends grants up to the ceiling and survives a "restart"', async () => {
  const t = counterTable();
  const env = { DB: fakeDB((s, a) => t.handle(s, a)) };
  assert.equal(await claimDailySends(env, 250, 300), 250);
  // A fresh run (new isolate) reads the same D1 counter.
  assert.equal(await claimDailySends(env, 250, 300), 50);
  assert.equal(await claimDailySends(env, 10, 300), 0);
  assert.equal(t.rows[today()], 300);
});

test('planFairSends caps each user and interleaves users', () => {
  const rows = [];
  for (let i = 0; i < 50; i++) rows.push({ user_id: 'heavy', next_renewal_date: inDays(1), id: 'h' + i });
  rows.push({ user_id: 'light', next_renewal_date: inDays(7), id: 'l1' });
  const plan = planFairSends(rows, 20);
  assert.equal(plan.filter(r => r.user_id === 'heavy').length, 20);
  assert.ok(plan.slice(0, 2).some(r => r.user_id === 'light'), 'light user is served in round one');
});

test('cron: heavy account cannot starve others, budget holds, skipped rows stay due', async () => {
  const due = [];
  for (let i = 0; i < 500; i++) due.push({ id: 'h' + i, user_id: 'heavy', email: 'h@example.com', name: 'Sub' + i, monthly_cost: 5, next_renewal_date: inDays(1), warning_days: '7,1', reminder_mode: 'cancel', timezone: 'UTC', last_warned_at: null });
  for (let u = 0; u < 20; u++) due.push({ id: 'u' + u, user_id: 'user' + u, email: `u${u}@example.com`, name: 'Netflix', monthly_cost: 10, next_renewal_date: inDays(7), warning_days: '7,1', reminder_mode: 'cancel', timezone: 'UTC', last_warned_at: null });

  const t = counterTable({ [today()]: DAILY_SEND_MAX - 25 });  // only 25 left today
  const warned = [];
  const env = {
    RESEND_API_KEY: 'test', HUB_JWT_SECRET: 'hub-secret-hub-secret-hub-secret-12',
    DB: fakeDB((sql, args) => {
      const c = t.handle(sql, args); if (c !== undefined) return c;
      if (/FROM renewal_watchlist w JOIN users/.test(sql)) return { results: due };
      if (/UPDATE renewal_watchlist SET last_warned_at/.test(sql)) { warned.push(args[1]); return { meta: { changes: 1 } }; }
      return undefined;
    }),
  };
  const sent = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => { sent.push(JSON.parse(opts.body).to); return new Response('{}'); };
  try {
    let job;
    await worker.scheduled({}, env, { waitUntil: (p) => { job = p; } });
    await job;
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(sent.length, 25, 'stops at the daily ceiling');
  assert.equal(warned.length, 25, 'only sent rows are marked warned');
  assert.equal(t.rows[today()], DAILY_SEND_MAX);
  // 21 users due; round one gives each user one email before heavy gets a second.
  const users = new Set(sent);
  assert.equal(users.size, 21, 'every account got its first warning');
  assert.ok(sent.filter(e => e === 'h@example.com').length <= 5);
});

// ── cron only warns accounts that still have Pro ───────────────────────────
// lookup(email) returns a Response for the hub's pro-lookup, or throws.
async function runCron(due, lookup) {
  const t = counterTable();
  const warned = [];
  const env = {
    RESEND_API_KEY: 'test', HUB_JWT_SECRET: 'hub-secret-hub-secret-hub-secret-12', HUB_LOOKUP_SECRET: 'lookup-secret-lookup-secret-lookup-1',
    PRO_LOOKUP_URL: 'https://hub.example.com/api/internal/pro-lookup',
    DB: fakeDB((sql, args) => {
      const c = t.handle(sql, args); if (c !== undefined) return c;
      if (/FROM renewal_watchlist w JOIN users/.test(sql)) return { results: due };
      if (/UPDATE renewal_watchlist SET last_warned_at/.test(sql)) { warned.push(args[1]); return { meta: { changes: 1 } }; }
      return undefined;
    }),
  };
  const sent = [];
  const lookups = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    const body = JSON.parse(opts.body);
    if (String(url).includes('pro-lookup')) { lookups.push(body.email); return lookup(body.email); }
    sent.push(body.to); return new Response('{}');
  };
  try {
    let job;
    await worker.scheduled({}, env, { waitUntil: (p) => { job = p; } });
    await job;
  } finally {
    globalThis.fetch = realFetch;
  }
  return { sent, warned, lookups };
}
const dueRow = (id, user, email) => ({ id, user_id: user, email, name: 'Netflix', monthly_cost: 10, next_renewal_date: inDays(7), warning_days: '7,1', reminder_mode: 'cancel', timezone: 'UTC', last_warned_at: null });
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json' } });

test('cron: a Pro account gets its warning', async () => {
  const r = await runCron([dueRow('w1', 'u1', 'pro@example.com')], () => json({ pro: true, token: 'x' }));
  assert.deepEqual(r.sent, ['pro@example.com']);
  assert.deepEqual(r.warned, ['w1']);
});

test('cron: an account whose Pro ended is skipped and its row stays due', async () => {
  const r = await runCron([dueRow('w1', 'u1', 'lapsed@example.com'), dueRow('w2', 'u2', 'pro@example.com')],
    (email) => json({ pro: email === 'pro@example.com' }));
  assert.deepEqual(r.sent, ['pro@example.com']);
  assert.deepEqual(r.warned, ['w2'], 'last_warned_at untouched for the lapsed account');
});

test('cron: a failed hub lookup still sends (timeout, 5xx or junk)', async () => {
  const due = [dueRow('w1', 'u1', 'a@example.com'), dueRow('w2', 'u2', 'b@example.com'), dueRow('w3', 'u3', 'c@example.com')];
  const r = await runCron(due, (email) => {
    if (email === 'a@example.com') throw new Error('network down');
    if (email === 'b@example.com') return json({ error: 'boom' }, 503);
    return new Response('not json', { status: 200 });
  });
  assert.deepEqual(r.sent.sort(), ['a@example.com', 'b@example.com', 'c@example.com']);
});

test('cron: one hub lookup per account, not per row', async () => {
  const due = [dueRow('w1', 'u1', 'pro@example.com'), dueRow('w2', 'u1', 'pro@example.com'), dueRow('w3', 'u1', 'pro@example.com')];
  const r = await runCron(due, () => json({ pro: true }));
  assert.equal(r.lookups.length, 1);
  assert.equal(r.sent.length, 3);
});

// ── per-user row cap on create ──────────────────────────────────────────────
function b64(s) { return Buffer.from(s).toString('base64url'); }
async function hs256(payload, secret) {
  const data = `${b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${b64(JSON.stringify(payload))}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return `${data}.${Buffer.from(sig).toString('base64url')}`;
}

async function postWatchlist(existingRows) {
  const inserts = [];
  const env = {
    JWT_SECRET: 'test-secret-test-secret-test-secret-1234', HUB_JWT_SECRET: 'hub-secret-hub-secret-hub-secret-12',
    DB: fakeDB((sql, args) => {
      if (/SELECT token_version FROM users/.test(sql)) return { token_version: 0 };
      if (/SELECT email FROM users WHERE id/.test(sql)) return { email: 'pro@example.com' };
      if (/SELECT COUNT\(\*\) AS c FROM renewal_watchlist/.test(sql)) return { c: existingRows };
      if (/INSERT INTO renewal_watchlist/.test(sql)) { inserts.push(args); return { meta: { changes: 1 } }; }
      return undefined;
    }),
  };
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const token = await hs256({ sub: 'u1', tv: 0, exp }, env.JWT_SECRET);
  const pro = await hs256({ v: 1, iss: 'app-hub', email: 'pro@example.com', pro_until: new Date(Date.now() + 86400000).toISOString(), exp }, env.HUB_JWT_SECRET);
  const req = new Request('https://subscriptiongraveyard.app/api/watchlist', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: `sg_session=${token}`, 'X-Hub-Pro': pro, Origin: 'https://subscriptiongraveyard.app' },
    body: JSON.stringify({ name: 'Netflix', monthly_cost: 15.49, next_renewal_date: inDays(10) }),
  });
  const res = await worker.fetch(req, env, { waitUntil() {} });
  return { res, body: await res.json(), inserts };
}

test('POST /api/watchlist works under the cap', async () => {
  const { res, inserts } = await postWatchlist(WATCHLIST_MAX_PER_USER - 1);
  assert.equal(res.status, 200);
  assert.equal(inserts.length, 1);
});

test('POST /api/watchlist refuses at the cap with a friendly message', async () => {
  const { res, body, inserts } = await postWatchlist(WATCHLIST_MAX_PER_USER);
  assert.equal(res.status, 409);
  assert.equal(inserts.length, 0);
  assert.match(body.error, /watchlist is full/);
  assert.doesNotMatch(body.error, /[—;]/);
});
