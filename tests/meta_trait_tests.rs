#![cfg(feature = "derive")]

//! Tests for Auth*Meta traits — verifying that derive macros correctly generate
//! column/table name mappings for both default and custom entity structs.

// Import meta traits
use better_auth_core::entity::{
    AuthAccountMeta, AuthApiKeyMeta, AuthInvitationMeta, AuthMemberMeta, AuthOrganizationMeta,
    AuthPasskeyMeta, AuthSessionMeta, AuthTwoFactorMeta, AuthUserMeta, AuthVerificationMeta,
};

// Import derive macros
use better_auth_core::{
    AuthAccount, AuthMember, AuthPasskey, AuthSession, AuthTwoFactor, AuthUser, AuthVerification,
};

// Import built-in types to test their default impls
use better_auth_core::types::{Account, ApiKey, Passkey, Session, TwoFactor, User, Verification};
use better_auth_core::types_org::{Invitation, Member, Organization};

use chrono::{DateTime, Utc};
use serde::Serialize;

// ═══════════════════════════════════════════════════════════════════════════
// 1. Built-in types return standard default column/table names
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_builtin_user_meta_defaults() {
    assert_eq!(User::table(), "users");
    assert_eq!(User::col_id(), "id");
    assert_eq!(User::col_email(), "email");
    assert_eq!(User::col_name(), "name");
    assert_eq!(User::col_image(), "image");
    assert_eq!(User::col_email_verified(), "email_verified");
    assert_eq!(User::col_created_at(), "created_at");
    assert_eq!(User::col_updated_at(), "updated_at");
    assert_eq!(User::col_metadata(), "metadata");
    assert_eq!(User::col_username(), "username");
    assert_eq!(User::col_display_username(), "display_username");
    assert_eq!(User::col_two_factor_enabled(), "two_factor_enabled");
    assert_eq!(User::col_role(), "role");
    assert_eq!(User::col_banned(), "banned");
    assert_eq!(User::col_ban_reason(), "ban_reason");
    assert_eq!(User::col_ban_expires(), "ban_expires");
}

#[test]
fn test_builtin_session_meta_defaults() {
    assert_eq!(Session::table(), "sessions");
    assert_eq!(Session::col_id(), "id");
    assert_eq!(Session::col_expires_at(), "expires_at");
    assert_eq!(Session::col_token(), "token");
    assert_eq!(Session::col_created_at(), "created_at");
    assert_eq!(Session::col_updated_at(), "updated_at");
    assert_eq!(Session::col_ip_address(), "ip_address");
    assert_eq!(Session::col_user_agent(), "user_agent");
    assert_eq!(Session::col_user_id(), "user_id");
    assert_eq!(Session::col_impersonated_by(), "impersonated_by");
    assert_eq!(
        Session::col_active_organization_id(),
        "active_organization_id"
    );
    assert_eq!(Session::col_active(), "active");
}

#[test]
fn test_builtin_account_meta_defaults() {
    assert_eq!(Account::table(), "accounts");
    assert_eq!(Account::col_id(), "id");
    assert_eq!(Account::col_account_id(), "account_id");
    assert_eq!(Account::col_provider_id(), "provider_id");
    assert_eq!(Account::col_user_id(), "user_id");
    assert_eq!(Account::col_access_token(), "access_token");
    assert_eq!(Account::col_refresh_token(), "refresh_token");
    assert_eq!(Account::col_id_token(), "id_token");
    assert_eq!(
        Account::col_access_token_expires_at(),
        "access_token_expires_at"
    );
    assert_eq!(
        Account::col_refresh_token_expires_at(),
        "refresh_token_expires_at"
    );
    assert_eq!(Account::col_scope(), "scope");
    assert_eq!(Account::col_password(), "password");
    assert_eq!(Account::col_created_at(), "created_at");
    assert_eq!(Account::col_updated_at(), "updated_at");
}

#[test]
fn test_builtin_organization_meta_defaults() {
    assert_eq!(Organization::table(), "organization");
    assert_eq!(Organization::col_id(), "id");
    assert_eq!(Organization::col_name(), "name");
    assert_eq!(Organization::col_slug(), "slug");
    assert_eq!(Organization::col_logo(), "logo");
    assert_eq!(Organization::col_metadata(), "metadata");
    assert_eq!(Organization::col_created_at(), "created_at");
    assert_eq!(Organization::col_updated_at(), "updated_at");
}

#[test]
fn test_builtin_member_meta_defaults() {
    assert_eq!(Member::table(), "member");
    assert_eq!(Member::col_id(), "id");
    assert_eq!(Member::col_organization_id(), "organization_id");
    assert_eq!(Member::col_user_id(), "user_id");
    assert_eq!(Member::col_role(), "role");
    assert_eq!(Member::col_created_at(), "created_at");
}

#[test]
fn test_builtin_invitation_meta_defaults() {
    assert_eq!(Invitation::table(), "invitation");
    assert_eq!(Invitation::col_id(), "id");
    assert_eq!(Invitation::col_organization_id(), "organization_id");
    assert_eq!(Invitation::col_email(), "email");
    assert_eq!(Invitation::col_role(), "role");
    assert_eq!(Invitation::col_status(), "status");
    assert_eq!(Invitation::col_inviter_id(), "inviter_id");
    assert_eq!(Invitation::col_expires_at(), "expires_at");
    assert_eq!(Invitation::col_created_at(), "created_at");
}

#[test]
fn test_builtin_verification_meta_defaults() {
    assert_eq!(Verification::table(), "verifications");
    assert_eq!(Verification::col_id(), "id");
    assert_eq!(Verification::col_identifier(), "identifier");
    assert_eq!(Verification::col_value(), "value");
    assert_eq!(Verification::col_expires_at(), "expires_at");
    assert_eq!(Verification::col_created_at(), "created_at");
    assert_eq!(Verification::col_updated_at(), "updated_at");
}

#[test]
fn test_builtin_two_factor_meta_defaults() {
    assert_eq!(TwoFactor::table(), "two_factor");
    assert_eq!(TwoFactor::col_id(), "id");
    assert_eq!(TwoFactor::col_secret(), "secret");
    assert_eq!(TwoFactor::col_backup_codes(), "backup_codes");
    assert_eq!(TwoFactor::col_user_id(), "user_id");
    assert_eq!(TwoFactor::col_created_at(), "created_at");
    assert_eq!(TwoFactor::col_updated_at(), "updated_at");
}

#[test]
fn test_builtin_api_key_meta_defaults() {
    assert_eq!(ApiKey::table(), "api_keys");
    assert_eq!(ApiKey::col_id(), "id");
    assert_eq!(ApiKey::col_name(), "name");
    assert_eq!(ApiKey::col_start(), "start");
    assert_eq!(ApiKey::col_prefix(), "prefix");
    assert_eq!(ApiKey::col_key_hash(), "key");
    assert_eq!(ApiKey::col_user_id(), "user_id");
    assert_eq!(ApiKey::col_refill_interval(), "refill_interval");
    assert_eq!(ApiKey::col_refill_amount(), "refill_amount");
    assert_eq!(ApiKey::col_enabled(), "enabled");
    assert_eq!(ApiKey::col_rate_limit_enabled(), "rate_limit_enabled");
    assert_eq!(
        ApiKey::col_rate_limit_time_window(),
        "rate_limit_time_window"
    );
    assert_eq!(ApiKey::col_rate_limit_max(), "rate_limit_max");
    assert_eq!(ApiKey::col_remaining(), "remaining");
    assert_eq!(ApiKey::col_expires_at(), "expires_at");
    assert_eq!(ApiKey::col_created_at(), "created_at");
    assert_eq!(ApiKey::col_updated_at(), "updated_at");
    assert_eq!(ApiKey::col_permissions(), "permissions");
    assert_eq!(ApiKey::col_metadata(), "metadata");
}

#[test]
fn test_builtin_passkey_meta_defaults() {
    assert_eq!(Passkey::table(), "passkeys");
    assert_eq!(Passkey::col_id(), "id");
    assert_eq!(Passkey::col_name(), "name");
    assert_eq!(Passkey::col_public_key(), "public_key");
    assert_eq!(Passkey::col_user_id(), "user_id");
    assert_eq!(Passkey::col_credential_id(), "credential_id");
    assert_eq!(Passkey::col_counter(), "counter");
    assert_eq!(Passkey::col_device_type(), "device_type");
    assert_eq!(Passkey::col_backed_up(), "backed_up");
    assert_eq!(Passkey::col_transports(), "transports");
    assert_eq!(Passkey::col_created_at(), "created_at");
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Derive macro generates correct column names from struct field idents
// ═══════════════════════════════════════════════════════════════════════════

/// A user struct with standard field names — derive should produce
/// column names matching the field identifiers (same as defaults).
#[derive(Clone, Debug, Serialize, AuthUser)]
struct StandardUser {
    id: String,
    email: Option<String>,
    name: Option<String>,
    email_verified: bool,
    image: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    username: Option<String>,
    display_username: Option<String>,
    two_factor_enabled: bool,
    role: Option<String>,
    banned: bool,
    ban_reason: Option<String>,
    ban_expires: Option<DateTime<Utc>>,
    metadata: serde_json::Value,
}

#[test]
fn test_derive_standard_user_meta() {
    // Standard field names should produce default column names
    assert_eq!(StandardUser::table(), "users");
    assert_eq!(StandardUser::col_id(), "id");
    assert_eq!(StandardUser::col_email(), "email");
    assert_eq!(StandardUser::col_name(), "name");
    assert_eq!(StandardUser::col_role(), "role");
    assert_eq!(StandardUser::col_banned(), "banned");
    assert_eq!(StandardUser::col_created_at(), "created_at");
}

/// A user struct with `#[auth(field = "name")]` on a differently-named field.
/// The column name should follow the struct field ident (= DB column),
/// NOT the getter name.
#[derive(Clone, Debug, Serialize, AuthUser)]
struct RenamedFieldUser {
    id: String,
    email: Option<String>,
    #[auth(field = "name")]
    display_name: Option<String>,
    email_verified: bool,
    image: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    username: Option<String>,
    display_username: Option<String>,
    two_factor_enabled: bool,
    role: Option<String>,
    banned: bool,
    ban_reason: Option<String>,
    ban_expires: Option<DateTime<Utc>>,
    metadata: serde_json::Value,
}

#[test]
fn test_derive_renamed_field_user_meta() {
    // The `name` getter maps to `display_name` field, so col_name() should
    // return "display_name" (the actual DB column name).
    assert_eq!(RenamedFieldUser::table(), "users"); // default table
    assert_eq!(RenamedFieldUser::col_id(), "id");
    assert_eq!(RenamedFieldUser::col_name(), "display_name"); // KEY: follows field ident
    assert_eq!(RenamedFieldUser::col_email(), "email");
    assert_eq!(RenamedFieldUser::col_role(), "role");
}

/// A user struct with `#[auth(table = "...")]` to override the table name.
#[derive(Clone, Debug, Serialize, AuthUser)]
#[auth(table = "custom_users")]
struct CustomTableUser {
    id: String,
    email: Option<String>,
    name: Option<String>,
    email_verified: bool,
    image: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    username: Option<String>,
    display_username: Option<String>,
    two_factor_enabled: bool,
    role: Option<String>,
    banned: bool,
    ban_reason: Option<String>,
    ban_expires: Option<DateTime<Utc>>,
    metadata: serde_json::Value,
}

#[test]
fn test_derive_custom_table_user_meta() {
    assert_eq!(CustomTableUser::table(), "custom_users"); // overridden
    assert_eq!(CustomTableUser::col_id(), "id");
    assert_eq!(CustomTableUser::col_email(), "email");
}

/// A user struct with BOTH table override AND field rename.
#[derive(Clone, Debug, Serialize, AuthUser)]
#[auth(table = "app_users")]
struct FullyCustomUser {
    id: String,
    email: Option<String>,
    #[auth(field = "name")]
    full_name: Option<String>,
    email_verified: bool,
    image: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    username: Option<String>,
    display_username: Option<String>,
    two_factor_enabled: bool,
    #[auth(field = "role")]
    user_role: Option<String>,
    banned: bool,
    ban_reason: Option<String>,
    ban_expires: Option<DateTime<Utc>>,
    metadata: serde_json::Value,
}

#[test]
fn test_derive_fully_custom_user_meta() {
    assert_eq!(FullyCustomUser::table(), "app_users");
    assert_eq!(FullyCustomUser::col_name(), "full_name");
    assert_eq!(FullyCustomUser::col_role(), "user_role");
    assert_eq!(FullyCustomUser::col_id(), "id"); // unchanged
    assert_eq!(FullyCustomUser::col_email(), "email"); // unchanged
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Derive meta for other entity types
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug, Serialize, AuthSession)]
#[auth(table = "custom_sessions")]
struct CustomSession {
    id: String,
    expires_at: DateTime<Utc>,
    token: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    user_id: String,
    impersonated_by: Option<String>,
    active_organization_id: Option<String>,
    active: bool,
}

#[test]
fn test_derive_custom_session_meta() {
    assert_eq!(CustomSession::table(), "custom_sessions");
    assert_eq!(CustomSession::col_id(), "id");
    assert_eq!(CustomSession::col_token(), "token");
    assert_eq!(CustomSession::col_user_id(), "user_id");
}

#[derive(Clone, Debug, Serialize, AuthAccount)]
#[auth(table = "oauth_accounts")]
struct CustomAccount {
    id: String,
    account_id: String,
    provider_id: String,
    user_id: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    access_token_expires_at: Option<DateTime<Utc>>,
    refresh_token_expires_at: Option<DateTime<Utc>>,
    scope: Option<String>,
    password: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[test]
fn test_derive_custom_account_meta() {
    assert_eq!(CustomAccount::table(), "oauth_accounts");
    assert_eq!(CustomAccount::col_provider_id(), "provider_id");
    assert_eq!(CustomAccount::col_user_id(), "user_id");
}

#[derive(Clone, Debug, Serialize, AuthMember)]
#[auth(table = "org_members")]
struct CustomMember {
    id: String,
    organization_id: String,
    user_id: String,
    #[auth(field = "role")]
    member_role: String,
    created_at: DateTime<Utc>,
}

#[test]
fn test_derive_custom_member_meta() {
    assert_eq!(CustomMember::table(), "org_members");
    assert_eq!(CustomMember::col_role(), "member_role"); // renamed field
    assert_eq!(CustomMember::col_organization_id(), "organization_id");
}

#[derive(Clone, Debug, Serialize, AuthVerification)]
struct CustomVerification {
    id: String,
    identifier: String,
    value: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[test]
fn test_derive_verification_meta_no_table_override() {
    // No #[auth(table = "...")] => falls through to default
    assert_eq!(CustomVerification::table(), "verifications");
    assert_eq!(CustomVerification::col_identifier(), "identifier");
    assert_eq!(CustomVerification::col_value(), "value");
}

#[derive(Clone, Debug, Serialize, AuthTwoFactor)]
#[auth(table = "totp_secrets")]
struct CustomTwoFactor {
    id: String,
    secret: String,
    backup_codes: Option<String>,
    user_id: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[test]
fn test_derive_custom_two_factor_meta() {
    assert_eq!(CustomTwoFactor::table(), "totp_secrets");
    assert_eq!(CustomTwoFactor::col_secret(), "secret");
    assert_eq!(CustomTwoFactor::col_user_id(), "user_id");
    assert_eq!(CustomTwoFactor::col_created_at(), "created_at");
    assert_eq!(CustomTwoFactor::col_updated_at(), "updated_at");
}

#[derive(Clone, Debug, Serialize, AuthPasskey)]
#[auth(table = "webauthn_credentials")]
struct CustomPasskey {
    id: String,
    name: String,
    public_key: String,
    user_id: String,
    credential_id: String,
    counter: u64,
    device_type: String,
    backed_up: bool,
    transports: Option<String>,
    created_at: DateTime<Utc>,
}

#[test]
fn test_derive_custom_passkey_meta() {
    assert_eq!(CustomPasskey::table(), "webauthn_credentials");
    assert_eq!(CustomPasskey::col_credential_id(), "credential_id");
    assert_eq!(CustomPasskey::col_counter(), "counter");
    assert_eq!(CustomPasskey::col_public_key(), "public_key");
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Exhaustive: every col_* method on every built-in type is callable
// ═══════════════════════════════════════════════════════════════════════════

/// Smoke test to ensure all Auth*Meta traits are correctly implemented for
/// all built-in types. This catches any missing `impl AuthXMeta for X {}`.
#[test]
fn test_all_builtin_meta_traits_callable() {
    // User
    let _ = User::table();
    let _ = User::col_id();
    let _ = User::col_email();
    let _ = User::col_name();
    let _ = User::col_image();
    let _ = User::col_email_verified();
    let _ = User::col_created_at();
    let _ = User::col_updated_at();
    let _ = User::col_metadata();
    let _ = User::col_username();
    let _ = User::col_display_username();
    let _ = User::col_two_factor_enabled();
    let _ = User::col_role();
    let _ = User::col_banned();
    let _ = User::col_ban_reason();
    let _ = User::col_ban_expires();

    // Session
    let _ = Session::table();
    let _ = Session::col_id();
    let _ = Session::col_expires_at();
    let _ = Session::col_token();
    let _ = Session::col_created_at();
    let _ = Session::col_updated_at();
    let _ = Session::col_ip_address();
    let _ = Session::col_user_agent();
    let _ = Session::col_user_id();
    let _ = Session::col_impersonated_by();
    let _ = Session::col_active_organization_id();
    let _ = Session::col_active();

    // Account
    let _ = Account::table();
    let _ = Account::col_id();
    let _ = Account::col_account_id();
    let _ = Account::col_provider_id();
    let _ = Account::col_user_id();
    let _ = Account::col_access_token();
    let _ = Account::col_refresh_token();
    let _ = Account::col_id_token();
    let _ = Account::col_access_token_expires_at();
    let _ = Account::col_refresh_token_expires_at();
    let _ = Account::col_scope();
    let _ = Account::col_password();
    let _ = Account::col_created_at();
    let _ = Account::col_updated_at();

    // Organization
    let _ = Organization::table();
    let _ = Organization::col_id();
    let _ = Organization::col_name();
    let _ = Organization::col_slug();
    let _ = Organization::col_logo();
    let _ = Organization::col_metadata();
    let _ = Organization::col_created_at();
    let _ = Organization::col_updated_at();

    // Member
    let _ = Member::table();
    let _ = Member::col_id();
    let _ = Member::col_organization_id();
    let _ = Member::col_user_id();
    let _ = Member::col_role();
    let _ = Member::col_created_at();

    // Invitation
    let _ = Invitation::table();
    let _ = Invitation::col_id();
    let _ = Invitation::col_organization_id();
    let _ = Invitation::col_email();
    let _ = Invitation::col_role();
    let _ = Invitation::col_status();
    let _ = Invitation::col_inviter_id();
    let _ = Invitation::col_expires_at();
    let _ = Invitation::col_created_at();

    // Verification
    let _ = Verification::table();
    let _ = Verification::col_id();
    let _ = Verification::col_identifier();
    let _ = Verification::col_value();
    let _ = Verification::col_expires_at();
    let _ = Verification::col_created_at();
    let _ = Verification::col_updated_at();

    // TwoFactor
    let _ = TwoFactor::table();
    let _ = TwoFactor::col_id();
    let _ = TwoFactor::col_secret();
    let _ = TwoFactor::col_backup_codes();
    let _ = TwoFactor::col_user_id();
    let _ = TwoFactor::col_created_at();
    let _ = TwoFactor::col_updated_at();

    // ApiKey
    let _ = ApiKey::table();
    let _ = ApiKey::col_id();
    let _ = ApiKey::col_name();
    let _ = ApiKey::col_start();
    let _ = ApiKey::col_prefix();
    let _ = ApiKey::col_key_hash();
    let _ = ApiKey::col_user_id();
    let _ = ApiKey::col_refill_interval();
    let _ = ApiKey::col_refill_amount();
    let _ = ApiKey::col_enabled();
    let _ = ApiKey::col_rate_limit_enabled();
    let _ = ApiKey::col_rate_limit_time_window();
    let _ = ApiKey::col_rate_limit_max();
    let _ = ApiKey::col_remaining();
    let _ = ApiKey::col_expires_at();
    let _ = ApiKey::col_created_at();
    let _ = ApiKey::col_updated_at();
    let _ = ApiKey::col_permissions();
    let _ = ApiKey::col_metadata();

    // Passkey
    let _ = Passkey::table();
    let _ = Passkey::col_id();
    let _ = Passkey::col_name();
    let _ = Passkey::col_public_key();
    let _ = Passkey::col_user_id();
    let _ = Passkey::col_credential_id();
    let _ = Passkey::col_counter();
    let _ = Passkey::col_device_type();
    let _ = Passkey::col_backed_up();
    let _ = Passkey::col_transports();
    let _ = Passkey::col_created_at();
}
