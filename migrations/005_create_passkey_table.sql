-- Passkey table for WebAuthn/Passkey authentication
CREATE TABLE IF NOT EXISTS passkeys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    counter BIGINT NOT NULL DEFAULT 0,
    device_type TEXT NOT NULL DEFAULT 'singleDevice',
    backed_up BOOLEAN NOT NULL DEFAULT FALSE,
    transports TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkeys(user_id);
CREATE INDEX IF NOT EXISTS idx_passkeys_credential_id ON passkeys(credential_id);
