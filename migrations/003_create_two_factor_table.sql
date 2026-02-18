-- Two-factor authentication table
CREATE TABLE IF NOT EXISTS "twoFactor" (
    id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    "backupCodes" TEXT,
    "userId" TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE("userId")
);

CREATE INDEX IF NOT EXISTS idx_two_factor_user_id ON "twoFactor"("userId");
