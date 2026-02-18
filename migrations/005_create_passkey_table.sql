-- Passkey table for WebAuthn/Passkey authentication
CREATE TABLE IF NOT EXISTS passkey (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "userId" TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    "credentialId" TEXT NOT NULL UNIQUE,
    counter BIGINT NOT NULL DEFAULT 0,
    "deviceType" TEXT NOT NULL DEFAULT 'singleDevice',
    "backedUp" BOOLEAN NOT NULL DEFAULT FALSE,
    transports TEXT,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_passkey_user_id ON passkey("userId");
CREATE INDEX IF NOT EXISTS idx_passkey_credential_id ON passkey("credentialId");
