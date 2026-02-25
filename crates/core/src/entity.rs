//! Entity traits for the Better Auth framework.
//!
//! These traits define the interface that entity types must implement.
//! The framework accesses entity fields through these trait methods,
//! allowing users to define their own entity structs with custom field names
//! and extra fields.
//!
//! Use `#[derive(AuthUser)]` etc. from `better-auth-derive` to auto-implement
//! these traits, or implement them manually.
//!
//! ## Meta traits
//!
//! Each entity trait has a corresponding `Auth*Meta` trait (e.g., `AuthUserMeta`)
//! that provides table and column name mappings for SQL generation. The derive
//! macros automatically implement both the entity trait and the meta trait.
//!
//! If you implement entity traits **manually** (without derive macros), you must
//! also implement the corresponding `Auth*Meta` trait. An empty `impl` block is
//! sufficient to get the default column/table names:
//!
//! ```rust,ignore
//! impl AuthUserMeta for MyUser {}   // uses default column names
//! impl AuthSessionMeta for MySession {}
//! ```

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::types::InvitationStatus;

/// Trait representing a user entity.
///
/// The framework reads user fields through these getters. Custom types
/// must provide all framework fields and may have additional fields.
pub trait AuthUser: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> &str;
    fn email(&self) -> Option<&str>;
    fn name(&self) -> Option<&str>;
    fn email_verified(&self) -> bool;
    fn image(&self) -> Option<&str>;
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;
    fn username(&self) -> Option<&str>;
    fn display_username(&self) -> Option<&str>;
    fn two_factor_enabled(&self) -> bool;
    fn role(&self) -> Option<&str>;
    fn banned(&self) -> bool;
    fn ban_reason(&self) -> Option<&str>;
    fn ban_expires(&self) -> Option<DateTime<Utc>>;
    fn metadata(&self) -> &serde_json::Value;
}

/// Trait representing a session entity.
pub trait AuthSession: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> &str;
    fn expires_at(&self) -> DateTime<Utc>;
    fn token(&self) -> &str;
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;
    fn ip_address(&self) -> Option<&str>;
    fn user_agent(&self) -> Option<&str>;
    fn user_id(&self) -> &str;
    fn impersonated_by(&self) -> Option<&str>;
    fn active_organization_id(&self) -> Option<&str>;
    fn active(&self) -> bool;
}

/// Trait representing an account entity (OAuth provider linking).
pub trait AuthAccount: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> &str;
    fn account_id(&self) -> &str;
    fn provider_id(&self) -> &str;
    fn user_id(&self) -> &str;
    fn access_token(&self) -> Option<&str>;
    fn refresh_token(&self) -> Option<&str>;
    fn id_token(&self) -> Option<&str>;
    fn access_token_expires_at(&self) -> Option<DateTime<Utc>>;
    fn refresh_token_expires_at(&self) -> Option<DateTime<Utc>>;
    fn scope(&self) -> Option<&str>;
    fn password(&self) -> Option<&str>;
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;
}

/// Trait representing an organization entity.
pub trait AuthOrganization: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn slug(&self) -> &str;
    fn logo(&self) -> Option<&str>;
    fn metadata(&self) -> Option<&serde_json::Value>;
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;
}

/// Trait representing an organization member entity.
pub trait AuthMember: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> &str;
    fn organization_id(&self) -> &str;
    fn user_id(&self) -> &str;
    fn role(&self) -> &str;
    fn created_at(&self) -> DateTime<Utc>;
}

/// Trait representing an invitation entity.
pub trait AuthInvitation: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> &str;
    fn organization_id(&self) -> &str;
    fn email(&self) -> &str;
    fn role(&self) -> &str;
    fn status(&self) -> &InvitationStatus;
    fn inviter_id(&self) -> &str;
    fn expires_at(&self) -> DateTime<Utc>;
    fn created_at(&self) -> DateTime<Utc>;

    /// Check if the invitation is still pending.
    fn is_pending(&self) -> bool {
        *self.status() == InvitationStatus::Pending
    }

    /// Check if the invitation has expired.
    fn is_expired(&self) -> bool {
        self.expires_at() < Utc::now()
    }
}

/// Trait representing a verification token entity.
pub trait AuthVerification: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> &str;
    fn identifier(&self) -> &str;
    fn value(&self) -> &str;
    fn expires_at(&self) -> DateTime<Utc>;
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;
}

/// Trait representing a two-factor authentication entity.
pub trait AuthTwoFactor: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> &str;
    fn secret(&self) -> &str;
    fn backup_codes(&self) -> Option<&str>;
    fn user_id(&self) -> &str;
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;
}

/// Trait representing an API key entity.
pub trait AuthApiKey: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> &str;
    fn name(&self) -> Option<&str>;
    fn start(&self) -> Option<&str>;
    fn prefix(&self) -> Option<&str>;
    fn key_hash(&self) -> &str;
    fn user_id(&self) -> &str;
    fn refill_interval(&self) -> Option<i64>;
    fn refill_amount(&self) -> Option<i64>;
    fn last_refill_at(&self) -> Option<&str>;
    fn enabled(&self) -> bool;
    fn rate_limit_enabled(&self) -> bool;
    fn rate_limit_time_window(&self) -> Option<i64>;
    fn rate_limit_max(&self) -> Option<i64>;
    fn request_count(&self) -> Option<i64>;
    fn remaining(&self) -> Option<i64>;
    fn last_request(&self) -> Option<&str>;
    fn expires_at(&self) -> Option<&str>;
    fn created_at(&self) -> &str;
    fn updated_at(&self) -> &str;
    fn permissions(&self) -> Option<&str>;
    fn metadata(&self) -> Option<&str>;
}

/// Trait representing a passkey entity.
pub trait AuthPasskey: Clone + Send + Sync + Serialize + std::fmt::Debug + 'static {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn public_key(&self) -> &str;
    fn user_id(&self) -> &str;
    fn credential_id(&self) -> &str;
    fn counter(&self) -> u64;
    fn device_type(&self) -> &str;
    fn backed_up(&self) -> bool;
    fn transports(&self) -> Option<&str>;
    fn created_at(&self) -> DateTime<Utc>;
}

// ── Column / table meta traits ─────────────────────────────────────────────
//
// These traits provide SQL column and table name mappings for each entity.
// The default implementations return the standard names used by the built-in
// types. When a user defines custom entity structs with different field names,
// the `#[derive(AuthUser)]` (etc.) macros generate overrides so that
// SqlxAdapter writes to the correct columns.
//
// Users can also override the table name with `#[auth(table = "my_users")]`
// at the struct level.

/// SQL column/table metadata for [`AuthUser`] entities.
///
/// These `Auth*Meta` traits are used by the `SqlxAdapter` to build SQL
/// statements (INSERT/UPDATE/DELETE/SELECT) using the *correct* table and column
/// names for your entity types.
///
/// # Customizing mappings
///
/// When using the derive macros (`#[derive(AuthUser)]`, etc.), you can customize
/// the names used by the generated `Auth*Meta` impls:
///
/// - Struct-level: override the table name with `#[auth(table = "...")]`
/// - Field-level: override the SQL column name with `#[auth(column = "...")]`
///
/// # `FromRow` consistency
///
/// If you implement `sqlx::FromRow` manually, ensure the column names you read
/// match the names returned by the corresponding `Auth*Meta` trait. Alternatively,
/// you can use `#[auth(from_row)]` to generate a `FromRow` implementation that
/// stays in sync with the `Auth*Meta` mappings.
pub trait AuthUserMeta {
    fn table() -> &'static str {
        "users"
    }
    fn col_id() -> &'static str {
        "id"
    }
    fn col_email() -> &'static str {
        "email"
    }
    fn col_name() -> &'static str {
        "name"
    }
    fn col_image() -> &'static str {
        "image"
    }
    fn col_email_verified() -> &'static str {
        "email_verified"
    }
    fn col_created_at() -> &'static str {
        "created_at"
    }
    fn col_updated_at() -> &'static str {
        "updated_at"
    }
    fn col_metadata() -> &'static str {
        "metadata"
    }
    fn col_username() -> &'static str {
        "username"
    }
    fn col_display_username() -> &'static str {
        "display_username"
    }
    fn col_two_factor_enabled() -> &'static str {
        "two_factor_enabled"
    }
    fn col_role() -> &'static str {
        "role"
    }
    fn col_banned() -> &'static str {
        "banned"
    }
    fn col_ban_reason() -> &'static str {
        "ban_reason"
    }
    fn col_ban_expires() -> &'static str {
        "ban_expires"
    }
}

/// SQL column/table metadata for [`AuthSession`] entities.
pub trait AuthSessionMeta {
    fn table() -> &'static str {
        "sessions"
    }
    fn col_id() -> &'static str {
        "id"
    }
    fn col_expires_at() -> &'static str {
        "expires_at"
    }
    fn col_token() -> &'static str {
        "token"
    }
    fn col_created_at() -> &'static str {
        "created_at"
    }
    fn col_updated_at() -> &'static str {
        "updated_at"
    }
    fn col_ip_address() -> &'static str {
        "ip_address"
    }
    fn col_user_agent() -> &'static str {
        "user_agent"
    }
    fn col_user_id() -> &'static str {
        "user_id"
    }
    fn col_impersonated_by() -> &'static str {
        "impersonated_by"
    }
    fn col_active_organization_id() -> &'static str {
        "active_organization_id"
    }
    fn col_active() -> &'static str {
        "active"
    }
}

/// SQL column/table metadata for [`AuthAccount`] entities.
pub trait AuthAccountMeta {
    fn table() -> &'static str {
        "accounts"
    }
    fn col_id() -> &'static str {
        "id"
    }
    fn col_account_id() -> &'static str {
        "account_id"
    }
    fn col_provider_id() -> &'static str {
        "provider_id"
    }
    fn col_user_id() -> &'static str {
        "user_id"
    }
    fn col_access_token() -> &'static str {
        "access_token"
    }
    fn col_refresh_token() -> &'static str {
        "refresh_token"
    }
    fn col_id_token() -> &'static str {
        "id_token"
    }
    fn col_access_token_expires_at() -> &'static str {
        "access_token_expires_at"
    }
    fn col_refresh_token_expires_at() -> &'static str {
        "refresh_token_expires_at"
    }
    fn col_scope() -> &'static str {
        "scope"
    }
    fn col_password() -> &'static str {
        "password"
    }
    fn col_created_at() -> &'static str {
        "created_at"
    }
    fn col_updated_at() -> &'static str {
        "updated_at"
    }
}

/// SQL column/table metadata for [`AuthOrganization`] entities.
pub trait AuthOrganizationMeta {
    fn table() -> &'static str {
        "organization"
    }
    fn col_id() -> &'static str {
        "id"
    }
    fn col_name() -> &'static str {
        "name"
    }
    fn col_slug() -> &'static str {
        "slug"
    }
    fn col_logo() -> &'static str {
        "logo"
    }
    fn col_metadata() -> &'static str {
        "metadata"
    }
    fn col_created_at() -> &'static str {
        "created_at"
    }
    fn col_updated_at() -> &'static str {
        "updated_at"
    }
}

/// SQL column/table metadata for [`AuthMember`] entities.
pub trait AuthMemberMeta {
    fn table() -> &'static str {
        "member"
    }
    fn col_id() -> &'static str {
        "id"
    }
    fn col_organization_id() -> &'static str {
        "organization_id"
    }
    fn col_user_id() -> &'static str {
        "user_id"
    }
    fn col_role() -> &'static str {
        "role"
    }
    fn col_created_at() -> &'static str {
        "created_at"
    }
}

/// SQL column/table metadata for [`AuthInvitation`] entities.
pub trait AuthInvitationMeta {
    fn table() -> &'static str {
        "invitation"
    }
    fn col_id() -> &'static str {
        "id"
    }
    fn col_organization_id() -> &'static str {
        "organization_id"
    }
    fn col_email() -> &'static str {
        "email"
    }
    fn col_role() -> &'static str {
        "role"
    }
    fn col_status() -> &'static str {
        "status"
    }
    fn col_inviter_id() -> &'static str {
        "inviter_id"
    }
    fn col_expires_at() -> &'static str {
        "expires_at"
    }
    fn col_created_at() -> &'static str {
        "created_at"
    }
}

/// SQL column/table metadata for [`AuthVerification`] entities.
pub trait AuthVerificationMeta {
    fn table() -> &'static str {
        "verifications"
    }
    fn col_id() -> &'static str {
        "id"
    }
    fn col_identifier() -> &'static str {
        "identifier"
    }
    fn col_value() -> &'static str {
        "value"
    }
    fn col_expires_at() -> &'static str {
        "expires_at"
    }
    fn col_created_at() -> &'static str {
        "created_at"
    }
    fn col_updated_at() -> &'static str {
        "updated_at"
    }
}

/// SQL column/table metadata for [`AuthTwoFactor`] entities.
pub trait AuthTwoFactorMeta {
    fn table() -> &'static str {
        "two_factor"
    }
    fn col_id() -> &'static str {
        "id"
    }
    fn col_secret() -> &'static str {
        "secret"
    }
    fn col_backup_codes() -> &'static str {
        "backup_codes"
    }
    fn col_user_id() -> &'static str {
        "user_id"
    }
    fn col_created_at() -> &'static str {
        "created_at"
    }
    fn col_updated_at() -> &'static str {
        "updated_at"
    }
}

/// SQL column/table metadata for [`AuthApiKey`] entities.
pub trait AuthApiKeyMeta {
    fn table() -> &'static str {
        "api_keys"
    }
    fn col_id() -> &'static str {
        "id"
    }
    fn col_name() -> &'static str {
        "name"
    }
    fn col_start() -> &'static str {
        "start"
    }
    fn col_prefix() -> &'static str {
        "prefix"
    }
    /// Database column for the API key hash.
    ///
    /// The default better-auth schema uses the column name `key` (even though it
    /// may be a reserved word in some SQL dialects). The `SqlxAdapter` quotes SQL
    /// identifiers, so using `key` here is safe.
    fn col_key_hash() -> &'static str {
        "key"
    }
    fn col_user_id() -> &'static str {
        "user_id"
    }
    fn col_refill_interval() -> &'static str {
        "refill_interval"
    }
    fn col_refill_amount() -> &'static str {
        "refill_amount"
    }
    fn col_last_refill_at() -> &'static str {
        "last_refill_at"
    }
    fn col_enabled() -> &'static str {
        "enabled"
    }
    fn col_rate_limit_enabled() -> &'static str {
        "rate_limit_enabled"
    }
    fn col_rate_limit_time_window() -> &'static str {
        "rate_limit_time_window"
    }
    fn col_rate_limit_max() -> &'static str {
        "rate_limit_max"
    }
    fn col_request_count() -> &'static str {
        "request_count"
    }
    fn col_remaining() -> &'static str {
        "remaining"
    }
    fn col_last_request() -> &'static str {
        "last_request"
    }
    fn col_expires_at() -> &'static str {
        "expires_at"
    }
    fn col_created_at() -> &'static str {
        "created_at"
    }
    fn col_updated_at() -> &'static str {
        "updated_at"
    }
    fn col_permissions() -> &'static str {
        "permissions"
    }
    fn col_metadata() -> &'static str {
        "metadata"
    }
}

/// SQL column/table metadata for [`AuthPasskey`] entities.
pub trait AuthPasskeyMeta {
    fn table() -> &'static str {
        "passkeys"
    }
    fn col_id() -> &'static str {
        "id"
    }
    fn col_name() -> &'static str {
        "name"
    }
    fn col_public_key() -> &'static str {
        "public_key"
    }
    fn col_user_id() -> &'static str {
        "user_id"
    }
    fn col_credential_id() -> &'static str {
        "credential_id"
    }
    fn col_counter() -> &'static str {
        "counter"
    }
    fn col_device_type() -> &'static str {
        "device_type"
    }
    fn col_backed_up() -> &'static str {
        "backed_up"
    }
    fn col_transports() -> &'static str {
        "transports"
    }
    fn col_created_at() -> &'static str {
        "created_at"
    }
}

/// Minimal user info for member-related API responses.
///
/// This is a concrete framework type (not generic) used to project
/// user fields into member responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberUserView {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
}

impl MemberUserView {
    /// Construct from any type implementing [`AuthUser`].
    pub fn from_user(user: &impl AuthUser) -> Self {
        Self {
            id: user.id().to_string(),
            email: user.email().map(|s| s.to_string()),
            name: user.name().map(|s| s.to_string()),
            image: user.image().map(|s| s.to_string()),
        }
    }
}

use serde::Deserialize;
