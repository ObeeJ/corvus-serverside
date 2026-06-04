-- Fix payments.currency abuse: add proper network column
ALTER TABLE payments ADD COLUMN IF NOT EXISTS network TEXT;

-- Backfill network from currency field where currency contains '/'
UPDATE payments
SET network = split_part(currency, '/', 2),
    currency = split_part(currency, '/', 1)
WHERE currency LIKE '%/%';

-- Add updated_at to users for audit trail
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Add updated_at to payments
ALTER TABLE payments ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Add created_at to subscriptions for history
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Covering index for VerifyCrypto query pattern
CREATE INDEX IF NOT EXISTS idx_payments_user_reference
ON payments(user_id, reference);

-- Index for webhook lookup by reference
CREATE INDEX IF NOT EXISTS idx_payments_reference
ON payments(reference);

-- Add metadata to usage_logs for abuse detection
ALTER TABLE usage_logs ADD COLUMN IF NOT EXISTS metadata JSONB;
