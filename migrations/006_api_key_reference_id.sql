-- Rename user_id to reference_id and add config_id for better-auth 1.5.5
ALTER TABLE api_keys RENAME COLUMN user_id TO reference_id;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS config_id TEXT NOT NULL DEFAULT 'default';

DROP INDEX IF EXISTS idx_api_keys_user_id;
CREATE INDEX IF NOT EXISTS idx_api_keys_reference_id ON api_keys(reference_id);
