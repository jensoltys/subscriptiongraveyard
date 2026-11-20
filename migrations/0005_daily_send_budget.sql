-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
-- Global daily ceiling on renewal-warning emails.
--
-- The daily cron used to send one Resend email + one D1 write per due
-- watchlist row with no limit, so a single account with thousands of rows
-- could burn the Resend quota and the run's subrequest budget, and nobody
-- else got their warning. The Worker (src/lib/send-budget.js) now reserves
-- sends from this counter before it emails anyone. One row per UTC day.
--
-- Apply BEFORE deploying the Worker that reads it. Without the table the
-- cron fails closed and sends nothing.
CREATE TABLE IF NOT EXISTS daily_send_counts (
  day TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0
);
