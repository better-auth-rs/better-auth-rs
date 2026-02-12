-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT,
    start TEXT,
    prefix TEXT,
    key TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refill_interval INTEGER,
    refill_amount INTEGER,
    last_refill_at TIMESTAMPTZ,
    enabled BOOLEAN NOT NULL DEFAULT true,
    rate_limit_enabled BOOLEAN NOT NULL DEFAULT false,
    rate_limit_time_window INTEGER,
    rate_limit_max INTEGER,
    request_count INTEGER DEFAULT 0,
    remaining INTEGER,
    last_request TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    permissions TEXT,
    metadata TEXT
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
