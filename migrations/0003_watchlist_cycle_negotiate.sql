-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
-- Watchlist items know their real billing cadence (the first cron
-- assumed monthly and bumped annual subs a month at a time), and each item can
-- be a cancel reminder OR a negotiation reminder ("call and ask for a deal").
ALTER TABLE renewal_watchlist ADD COLUMN billing_cycle TEXT NOT NULL DEFAULT 'monthly';
ALTER TABLE renewal_watchlist ADD COLUMN reminder_mode TEXT NOT NULL DEFAULT 'cancel';
