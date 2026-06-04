-- Reverse 0003_schema_fixes
DROP INDEX IF EXISTS idx_payments_user_reference;
DROP INDEX IF EXISTS idx_payments_reference;
ALTER TABLE payments DROP COLUMN IF EXISTS network;
ALTER TABLE payments DROP COLUMN IF EXISTS updated_at;
ALTER TABLE users DROP COLUMN IF EXISTS updated_at;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS created_at;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS updated_at;
ALTER TABLE usage_logs DROP COLUMN IF EXISTS metadata;
