-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
-- Renewal watchlist: Pro-only feature.
-- Pro users add active subscriptions with renewal dates; daily cron sends
-- warning emails before each renewal so they can cancel in time.

CREATE TABLE IF NOT EXISTS renewal_watchlist (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  monthly_cost REAL NOT NULL,
  category TEXT DEFAULT 'other',
  next_renewal_date TEXT NOT NULL,  -- ISO date YYYY-MM-DD
  warning_days TEXT DEFAULT '7,1',   -- comma-separated days before renewal
  cancel_url TEXT,
  last_warned_at TEXT,
  notes TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_watchlist_user ON renewal_watchlist(user_id);
CREATE INDEX IF NOT EXISTS idx_watchlist_renewal ON renewal_watchlist(next_renewal_date);
