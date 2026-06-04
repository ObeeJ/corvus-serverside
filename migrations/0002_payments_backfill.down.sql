-- Reverse 0002 backfill. The original tables are also defined in 0001, so dropping them
-- here only makes sense if you're rolling back to a pre-billing state.
DROP INDEX IF EXISTS idx_usage_logs_user_feature_time;
DROP TABLE IF EXISTS usage_logs;
DROP INDEX IF EXISTS idx_payments_user;
DROP TABLE IF EXISTS payments;
DROP TABLE IF EXISTS subscriptions;
