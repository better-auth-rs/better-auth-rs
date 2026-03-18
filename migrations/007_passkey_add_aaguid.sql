-- Add aaguid column for passkey authentication (better-auth 1.5.5)
ALTER TABLE passkeys ADD COLUMN IF NOT EXISTS aaguid TEXT;
