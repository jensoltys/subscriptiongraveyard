// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
// A copy with no Pro hub must say so, so the page never sells Pro that can't unlock here.
// Run: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import worker from '../src/worker.js';

const DB = { prepare() { const st = { bind() { return st; }, async first() { return null; }, async run() { return { meta: {} }; }, async all() { return { results: [] }; } }; return st; }, async batch(s) { return s.map(() => ({ results: [] })); } };
const get = (env) => worker.fetch(new Request('https://copy.example.com/api/pro-status'), { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', DB, ...env }, { waitUntil() {} }).then(r => r.json());

test('pro-status: no hub connected = pro_available false, everyone on the free plan', async () => {
  const d = await get({});
  assert.equal(d.pro_available, false);
  assert.equal(d.is_pro, false);
});

const HUB = 'hub-secret-hub-secret-hub-secret-12';

test('pro-status: hub connected = pro_available true', async () => {
  assert.equal((await get({ HUB_JWT_SECRET: HUB })).pro_available, true);
});

test('pro-status: no hub = no upgrade link or price, even if UPGRADE_URL is set', async () => {
  const d = await get({ UPGRADE_URL: 'https://pay.example.com/pro', PRO_PRICE_TEXT: '$5/mo' });
  assert.equal(d.upgrade_url, null);
  assert.equal(d.pro_price_text, null);
});

test('pro-status: hub + UPGRADE_URL + PRO_PRICE_TEXT come back as set', async () => {
  const d = await get({ HUB_JWT_SECRET: HUB, UPGRADE_URL: 'https://pay.example.com/pro', PRO_PRICE_TEXT: '$5/mo for every feature' });
  assert.equal(d.upgrade_url, 'https://pay.example.com/pro');
  assert.equal(d.pro_price_text, '$5/mo for every feature');
});

test('pro-status: hub with blank UPGRADE_URL = no upgrade link (Go Pro hidden)', async () => {
  const d = await get({ HUB_JWT_SECRET: HUB, UPGRADE_URL: '' });
  assert.equal(d.pro_available, true);
  assert.equal(d.upgrade_url, null);
  assert.equal(d.pro_price_text, null);
});

test('pro-status: a non-http UPGRADE_URL is ignored', async () => {
  assert.equal((await get({ HUB_JWT_SECRET: HUB, UPGRADE_URL: 'javascript:alert(1)' })).upgrade_url, null);
});

test('pro-status: feedback_available follows FEEDBACK_WEBHOOK_URL', async () => {
  assert.equal((await get({})).feedback_available, false);
  assert.equal((await get({ FEEDBACK_WEBHOOK_URL: 'https://hooks.example.com/fb' })).feedback_available, true);
});

test('static page fails closed: no paid upgrade link until the server says Pro is available', () => {
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.doesNotMatch(html, /href="https:\/\/jenbuiltit\.com\/app-hub\/upgrade/);
  assert.match(html, /class="pro-required-price" id="pro-required-price" hidden><\/p>/);
  assert.doesNotMatch(html, /\$7\/mo|all five Jen Built It apps/);
  const js = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.match(js, /let proAvailable=false;/);
  assert.doesNotMatch(js, /jenbuiltit\.com\/app-hub\/upgrade/);
});

test('402 upgrade_url follows UPGRADE_URL, and is left out when blank', async () => {
  const src = readFileSync(new URL('../src/worker.js', import.meta.url), 'utf8');
  assert.doesNotMatch(src, /jenbuiltit\.com\/app-hub\/upgrade/);
  assert.equal((src.match(/upgrade_url: upgradeUrl\(/g) || []).length, 4);
});

test('cron: a copy with no Pro hub sends no renewal warnings', async () => {
  const today = new Date().toISOString().slice(0, 10);
  const in7 = new Date(Date.parse(today) + 7 * 86400000).toISOString().slice(0, 10);
  const row = { id: 'w1', user_id: 'u1', email: 'a@example.com', name: 'Netflix', monthly_cost: 10, next_renewal_date: in7, warning_days: '7,1', reminder_mode: 'cancel', timezone: 'UTC', last_warned_at: null };
  const cronDB = { prepare(sql) { const st = { bind() { return st; }, async first() { return /SELECT count FROM daily_send_counts/.test(sql) ? { count: 0 } : null; }, async run() { return { meta: { changes: 1 } }; }, async all() { return /FROM renewal_watchlist w JOIN users/.test(sql) ? { results: [row] } : { results: [] }; } }; return st; } };
  const sent = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => { sent.push(String(url)); return new Response('{}'); };
  try {
    let job;
    await worker.scheduled({}, { RESEND_API_KEY: 'test', DB: cronDB }, { waitUntil: (p) => { job = p; } });
    await job;
  } finally { globalThis.fetch = realFetch; }
  assert.deepEqual(sent, []);
});

test('hub secrets shorter than 32 characters count as not set', async () => {
  const realError = console.error; console.error = () => {};
  try {
    const d = await get({ HUB_JWT_SECRET: 'abc', UPGRADE_URL: 'https://pay.example.com/pro' });
    assert.equal(d.pro_available, false);
    assert.equal(d.upgrade_url, null);
    const sso = await worker.fetch(new Request('https://copy.example.com/api/auth/hub-sso', { method: 'POST', headers: { Origin: 'https://copy.example.com', 'Content-Type': 'application/json' }, body: JSON.stringify({ hub_pro_jwt: 'a.b.c' }) }),
      { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', HUB_JWT_SECRET: 'abc', DB }, { waitUntil() {} });
    assert.equal(sso.status, 404);
    const recap = await worker.fetch(new Request('https://copy.example.com/api/service/recap?email=a@example.com&start=2026-01-01&end=2026-01-31', { headers: { 'X-Internal-Secret': 'short' } }),
      { JWT_SECRET: 'test-secret-test-secret-test-secret-1234', RECAP_SERVICE_SECRET: 'short', DB }, { waitUntil() {} });
    assert.equal(recap.status, 401);
  } finally { console.error = realError; }
});

test('no session secret: sign up, verify and log in answer with a setup message and write nothing', async () => {
  const realError = console.error; console.error = () => {};
  const wrote = [];
  const spyDB = { prepare(sql) { const st = { bind() { return st; }, async first() { return null; }, async run() { wrote.push(sql); return { meta: {} }; }, async all() { return { results: [] }; } }; return st; }, async batch(s) { wrote.push('batch'); return s.map(() => ({ results: [] })); } };
  try {
    for (const secret of [undefined, '', 'too-short']) {
      for (const [path, body] of [['signup', { email: 'a@example.com', password: 'correct horse 99' }], ['login', { email: 'a@example.com', password: 'correct horse 99' }], ['verify-code', { email: 'a@example.com', code: '123456', password: 'correct horse 99' }]]) {
        const r = await worker.fetch(new Request('https://copy.example.com/api/auth/' + path, { method: 'POST', headers: { Origin: 'https://copy.example.com', 'Content-Type': 'application/json' }, body: JSON.stringify(body) }), { JWT_SECRET: secret, DB: spyDB }, { waitUntil() {} });
        assert.equal(r.status, 503, path);
        const j = await r.json();
        assert.equal(j.code, 'setup_required');
        assert.match(j.error, /JWT_SECRET/);
      }
    }
    assert.deepEqual(wrote, []);
  } finally { console.error = realError; }
});

test('pages get this site address in og:url, og:image and the canonical link', async () => {
  const page = '<html><head><meta property="og:url" content="/guide"><meta property="og:image" content="/og.png"><meta name="twitter:image" content="/og.png"/></head><body></body></html>';
  const ASSETS = { async fetch() { return new Response(page, { headers: { 'Content-Type': 'text/html; charset=utf-8' } }); } };
  const html = await worker.fetch(new Request('https://copy.example.com/guide'), { APP_URL: 'https://copy.example.com/', ASSETS, DB }, { waitUntil() {} }).then(r => r.text());
  assert.match(html, /<meta property="og:url" content="https:\/\/copy\.example\.com\/guide">/);
  assert.match(html, /<meta property="og:image" content="https:\/\/copy\.example\.com\/og\.png">/);
  assert.match(html, /<meta name="twitter:image" content="https:\/\/copy\.example\.com\/og\.png"\/>/);
  assert.match(html, /<link rel="canonical" href="https:\/\/copy\.example\.com\/guide"\/>/);
  const real = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.match(real, /<meta property="og:url" content="\/"/);
  assert.doesNotMatch(real, /subscriptiongraveyard\.app\/og\.png/);
});

test('delete dialog: the App Hub option stays hidden unless a hub is connected', () => {
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /id="delete-use-hub-btn" data-pro-on hidden>/);
});
