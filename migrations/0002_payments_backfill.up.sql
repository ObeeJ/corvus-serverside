-- Backfill migration: creates billing tables on installs where 0001 ran before these tables existed.
-- All statements are idempotent (IF NOT EXISTS), so this is safe to re-apply.

CREATE TABLE IF NOT EXISTS subscriptions (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL DEFAULT 'paystack',
  provider_customer_id TEXT,
  provider_subscription_id TEXT,
  status TEXT,
  current_period_end TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS payments (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  reference TEXT UNIQUE NOT NULL,
  amount_usd NUMERIC(10,2),
  currency TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id, status);

CREATE TABLE IF NOT EXISTS usage_logs (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  feature TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_usage_logs_user_feature_time
  ON usage_logs(user_id, feature, created_at);
