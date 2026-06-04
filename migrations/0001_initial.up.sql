-- Users and auth
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'free',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Payment subscriptions (Paystack or crypto)
CREATE TABLE IF NOT EXISTS subscriptions (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL DEFAULT 'paystack', -- 'paystack' | 'crypto'
  provider_customer_id TEXT,
  provider_subscription_id TEXT,
  status TEXT,
  current_period_end TIMESTAMPTZ
);

-- One-time and recurring payment records
CREATE TABLE IF NOT EXISTS payments (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,         -- 'paystack' | 'crypto'
  reference TEXT UNIQUE NOT NULL, -- Paystack reference or tx hash
  amount_usd NUMERIC(10,2),
  currency TEXT,                  -- 'NGN', 'USDC', 'USDT', etc.
  status TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'success' | 'failed'
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Rolling 30-day usage tracking
CREATE TABLE IF NOT EXISTS usage_logs (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  feature TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_usage_logs_user_feature_time
ON usage_logs(user_id, feature, created_at);

CREATE INDEX IF NOT EXISTS idx_payments_user
ON payments(user_id, status);
