-- Two-factor authentication table
CREATE TABLE IF NOT EXISTS two_factor (
    id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    backup_codes TEXT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id)
);

CREATE INDEX IF NOT EXISTS idx_two_factor_user_id ON two_factor(user_id);
