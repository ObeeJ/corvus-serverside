-- API keys let the CLI authenticate for centralized/remote scans without a
-- short-lived JWT. Only the SHA-256 hash of the key is stored.
CREATE TABLE IF NOT EXISTS api_keys (
  id           UUID PRIMARY KEY,
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_hash     TEXT NOT NULL UNIQUE,
  label        TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ,
  revoked      BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
