-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
-- Subscription Graveyard — D1 Schema (full schema for fresh deploys).
-- For changes to a database that already exists, use the migrations/ folder.

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  newsletter_consent INTEGER DEFAULT 0,
  newsletter_consent_at TEXT,
  reset_token TEXT,
  reset_token_expires TEXT,
  currency TEXT DEFAULT 'USD',
  token_version INTEGER DEFAULT 0,
  email_verified INTEGER DEFAULT 0,
  verified_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reset_tokens (
  token TEXT PRIMARY KEY,        -- SHA-256(raw token), hex
  user_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS email_verification_tokens (
  token TEXT PRIMARY KEY,        -- SHA-256(raw token), hex
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,   -- unix seconds
  used INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  monthly_cost REAL NOT NULL,
  category TEXT DEFAULT 'other',
  cancelled_date TEXT NOT NULL,
  started_date TEXT,
  cancel_reason TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS death_row (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  monthly_cost REAL NOT NULL,
  category TEXT DEFAULT 'other',
  notes TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_death_row_user ON death_row(user_id);
CREATE INDEX IF NOT EXISTS idx_reset_tokens_user ON reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_email_verification_user ON email_verification_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_rate_limits_key ON rate_limits(key, created_at);
CREATE INDEX IF NOT EXISTS idx_rate_limits_expires ON rate_limits(expires_at);
