// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
// Limits on how much the daily renewal-warning cron can spend.
//
// One Pro account with thousands of watchlist rows used to mean thousands of
// Resend calls + D1 writes in a single cron run, burning the email quota and
// the run's subrequest budget before anyone else got their warning. Three
// limits now stand in the way:
//   1. WATCHLIST_MAX_PER_USER rows per account, enforced on create.
//   2. PER_USER_PER_RUN warnings per account per cron run, handed out
//      round-robin so a heavy account can't starve the others.
//   3. DAILY_SEND_MAX emails per UTC day across everyone, counted in D1
//      (daily_send_counts) so a restart or a second run can't reset it.
// Rows that miss out stay due (last_warned_at untouched) for the next run.

export const WATCHLIST_MAX_PER_USER = 200;
export const PER_USER_PER_RUN = 20;
export const DAILY_SEND_MAX = 300;

// Order due rows fairly: each user's rows soonest-renewal first, then one row
// per user per round, capped at perUser rows each.
export function planFairSends(dueRows, perUser = PER_USER_PER_RUN) {
  const byUser = new Map();
  for (const row of dueRows) {
    if (!byUser.has(row.user_id)) byUser.set(row.user_id, []);
    byUser.get(row.user_id).push(row);
  }
  const queues = [...byUser.values()].map((list) =>
    list
      .slice()
      .sort((a, b) => String(a.next_renewal_date).localeCompare(String(b.next_renewal_date)))
      .slice(0, perUser)
  );
  // Users whose soonest renewal is nearest go first in every round.
  queues.sort((a, b) => String(a[0].next_renewal_date).localeCompare(String(b[0].next_renewal_date)));
  const out = [];
  for (let round = 0; round < perUser; round++) {
    for (const q of queues) if (round < q.length) out.push(q[round]);
  }
  return out;
}

// Reserve up to `n` sends from today's global budget of `max`. Returns how
// many were granted (0..n). The count lives in D1 keyed by the UTC date, so it
// survives restarts and repeated runs. The UPDATE re-checks the ceiling in SQL
// so two overlapping runs can't both spend the same headroom.
export async function claimDailySends(env, n, max = DAILY_SEND_MAX) {
  if (!(n > 0)) return 0;
  const day = new Date().toISOString().slice(0, 10);
  await env.DB.prepare('INSERT OR IGNORE INTO daily_send_counts (day, count) VALUES (?, 0)').bind(day).run();
  const row = await env.DB.prepare('SELECT count FROM daily_send_counts WHERE day = ?').bind(day).first();
  const used = Number(row?.count || 0);
  const grant = Math.max(0, Math.min(n, max - used));
  if (grant === 0) return 0;
  const r = await env.DB.prepare('UPDATE daily_send_counts SET count = count + ? WHERE day = ? AND count + ? <= ?')
    .bind(grant, day, grant, max).run();
  if (!r?.meta?.changes) return 0;  // lost a race with another run: send nothing this time
  // Housekeeping: old days are never read again.
  await env.DB.prepare('DELETE FROM daily_send_counts WHERE day < ?')
    .bind(new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10)).run();
  return grant;
}
