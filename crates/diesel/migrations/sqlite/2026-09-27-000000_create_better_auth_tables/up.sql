-- SQLite stores timestamps as fixed-width UTC text (see
-- `better_auth_diesel::sql_types::UtcTimestamp`) and JSON as text.
-- Foreign keys need `PRAGMA foreign_keys = ON` on every connection.

CREATE TABLE users (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT,
    email TEXT UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    image TEXT,
    username TEXT UNIQUE,
    display_username TEXT,
    two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    role TEXT,
    banned BOOLEAN NOT NULL DEFAULT FALSE,
    ban_reason TEXT,
    ban_expires TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE sessions (
    id TEXT NOT NULL PRIMARY KEY,
    expires_at TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    ip_address TEXT,
    user_agent TEXT,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    impersonated_by TEXT,
    active_organization_id TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_sessions_user_id ON sessions (user_id);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

CREATE TABLE accounts (
    id TEXT NOT NULL PRIMARY KEY,
    account_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    access_token TEXT,
    refresh_token TEXT,
    id_token TEXT,
    access_token_expires_at TEXT,
    refresh_token_expires_at TEXT,
    scope TEXT,
    password TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_accounts_user_id ON accounts (user_id);
CREATE UNIQUE INDEX idx_accounts_provider_account ON accounts (provider_id, account_id);

CREATE TABLE verifications (
    id TEXT NOT NULL PRIMARY KEY,
    identifier TEXT NOT NULL,
    value TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_verifications_identifier ON verifications (identifier);

CREATE TABLE organization (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    logo TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE member (
    id TEXT NOT NULL PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_member_user_id ON member (user_id);
CREATE UNIQUE INDEX idx_member_org_user_unique ON member (organization_id, user_id);

CREATE TABLE invitation (
    id TEXT NOT NULL PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL,
    inviter_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_invitation_organization_id ON invitation (organization_id);
CREATE INDEX idx_invitation_email ON invitation (email);
CREATE INDEX idx_invitation_status ON invitation (status);

CREATE TABLE two_factor (
    id TEXT NOT NULL PRIMARY KEY,
    secret TEXT NOT NULL,
    backup_codes TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    verified BOOLEAN NOT NULL DEFAULT TRUE,
    failed_verification_count BIGINT NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_two_factor_user_id ON two_factor (user_id);

-- No foreign key on reference_id: it holds a user id or an organization id
-- depending on the key's configuration, which is why upstream declares the
-- field as a plain indexed string.
CREATE TABLE api_keys (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT,
    start TEXT,
    prefix TEXT,
    key TEXT NOT NULL UNIQUE,
    reference_id TEXT NOT NULL,
    config_id TEXT NOT NULL DEFAULT 'default',
    refill_interval REAL,
    refill_amount REAL,
    last_refill_at TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_time_window REAL,
    rate_limit_max REAL,
    request_count REAL,
    remaining REAL,
    last_request TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    permissions TEXT,
    metadata TEXT
);
CREATE INDEX idx_api_keys_reference_id ON api_keys (reference_id);
CREATE INDEX idx_api_keys_config_id ON api_keys (config_id);

CREATE TABLE passkeys (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT,
    public_key TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    counter BIGINT NOT NULL DEFAULT 0,
    device_type TEXT NOT NULL,
    backed_up BOOLEAN NOT NULL DEFAULT FALSE,
    transports TEXT,
    credential TEXT NOT NULL,
    aaguid TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_passkeys_user_id ON passkeys (user_id);

CREATE TABLE device_code (
    id TEXT NOT NULL PRIMARY KEY,
    device_code TEXT NOT NULL UNIQUE,
    user_code TEXT NOT NULL UNIQUE,
    user_id TEXT REFERENCES users (id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL,
    last_polled_at TEXT,
    polling_interval BIGINT,
    client_id TEXT,
    scope TEXT
);
CREATE INDEX idx_device_code_user_id ON device_code (user_id);
CREATE INDEX idx_device_code_expires_at ON device_code (expires_at);
