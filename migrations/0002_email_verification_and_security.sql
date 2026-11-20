-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2026 the Subscription Graveyard authors. See LICENSE.
-- Tokens are stored hashed, plus two indexes.
--   1. Wipe reset_tokens + email_verification_tokens rows, because the worker
--      stores SHA-256(token) instead of the raw token. On a new database both
--      tables are already empty, so this changes nothing.
--   2. Index rate_limits.expires_at so the janitor DELETE sweep stops
--      doing a full table scan.

DELETE FROM reset_tokens;
DELETE FROM email_verification_tokens;

CREATE INDEX IF NOT EXISTS idx_rate_limits_expires ON rate_limits(expires_at);
CREATE INDEX IF NOT EXISTS idx_email_verification_user ON email_verification_tokens(user_id);
