use chrono::{DateTime, Utc};

use crate::entity::{
    AuthAccount, AuthAccountMeta, AuthApiKey, AuthApiKeyMeta, AuthInvitation, AuthInvitationMeta,
    AuthMember, AuthMemberMeta, AuthOrganization, AuthOrganizationMeta, AuthPasskey,
    AuthPasskeyMeta, AuthSession, AuthSessionMeta, AuthTwoFactor, AuthTwoFactorMeta, AuthUser,
    AuthUserMeta, AuthVerification, AuthVerificationMeta,
};

use super::types::{Account, ApiKey, Passkey, Session, TwoFactor, User, Verification};
use super::types_org::{Invitation, InvitationStatus, Member, Organization};

/// Blanket conversion from any [`AuthUser`] implementor to the concrete [`User`] type.
///
/// This avoids hand-written `to_user()` helpers scattered across plugins.
impl<T: AuthUser> From<&T> for User {
    fn from(u: &T) -> Self {
        Self {
            id: u.id().to_owned(),
            name: u.name().map(str::to_owned),
            email: u.email().map(str::to_owned),
            email_verified: u.email_verified(),
            image: u.image().map(str::to_owned),
            created_at: u.created_at(),
            updated_at: u.updated_at(),
            username: u.username().map(str::to_owned),
            display_username: u.display_username().map(str::to_owned),
            two_factor_enabled: u.two_factor_enabled(),
            role: u.role().map(str::to_owned),
            banned: u.banned(),
            ban_reason: u.ban_reason().map(str::to_owned),
            ban_expires: u.ban_expires(),
            metadata: u.metadata().clone(),
        }
    }
}

impl AuthUser for User {
    fn id(&self) -> &str {
        &self.id
    }
    fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn email_verified(&self) -> bool {
        self.email_verified
    }
    fn image(&self) -> Option<&str> {
        self.image.as_deref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
    fn display_username(&self) -> Option<&str> {
        self.display_username.as_deref()
    }
    fn two_factor_enabled(&self) -> bool {
        self.two_factor_enabled
    }
    fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }
    fn banned(&self) -> bool {
        self.banned
    }
    fn ban_reason(&self) -> Option<&str> {
        self.ban_reason.as_deref()
    }
    fn ban_expires(&self) -> Option<DateTime<Utc>> {
        self.ban_expires
    }
    fn metadata(&self) -> &serde_json::Value {
        &self.metadata
    }
}

impl AuthSession for Session {
    fn id(&self) -> &str {
        &self.id
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    fn token(&self) -> &str {
        &self.token
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    fn ip_address(&self) -> Option<&str> {
        self.ip_address.as_deref()
    }
    fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn impersonated_by(&self) -> Option<&str> {
        self.impersonated_by.as_deref()
    }
    fn active_organization_id(&self) -> Option<&str> {
        self.active_organization_id.as_deref()
    }
    fn active(&self) -> bool {
        self.active
    }
}

impl AuthAccount for Account {
    fn id(&self) -> &str {
        &self.id
    }
    fn account_id(&self) -> &str {
        &self.account_id
    }
    fn provider_id(&self) -> &str {
        &self.provider_id
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }
    fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }
    fn id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }
    fn access_token_expires_at(&self) -> Option<DateTime<Utc>> {
        self.access_token_expires_at
    }
    fn refresh_token_expires_at(&self) -> Option<DateTime<Utc>> {
        self.refresh_token_expires_at
    }
    fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }
    fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl AuthOrganization for Organization {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn slug(&self) -> &str {
        &self.slug
    }
    fn logo(&self) -> Option<&str> {
        self.logo.as_deref()
    }
    fn metadata(&self) -> Option<&serde_json::Value> {
        self.metadata.as_ref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl AuthMember for Member {
    fn id(&self) -> &str {
        &self.id
    }
    fn organization_id(&self) -> &str {
        &self.organization_id
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn role(&self) -> &str {
        &self.role
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl AuthInvitation for Invitation {
    fn id(&self) -> &str {
        &self.id
    }
    fn organization_id(&self) -> &str {
        &self.organization_id
    }
    fn email(&self) -> &str {
        &self.email
    }
    fn role(&self) -> &str {
        &self.role
    }
    fn status(&self) -> &InvitationStatus {
        &self.status
    }
    fn inviter_id(&self) -> &str {
        &self.inviter_id
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl AuthVerification for Verification {
    fn id(&self) -> &str {
        &self.id
    }
    fn identifier(&self) -> &str {
        &self.identifier
    }
    fn value(&self) -> &str {
        &self.value
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl AuthTwoFactor for TwoFactor {
    fn id(&self) -> &str {
        &self.id
    }
    fn secret(&self) -> &str {
        &self.secret
    }
    fn backup_codes(&self) -> Option<&str> {
        self.backup_codes.as_deref()
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl AuthApiKey for ApiKey {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn start(&self) -> Option<&str> {
        self.start.as_deref()
    }
    fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }
    fn key_hash(&self) -> &str {
        &self.key_hash
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn refill_interval(&self) -> Option<i64> {
        self.refill_interval
    }
    fn refill_amount(&self) -> Option<i64> {
        self.refill_amount
    }
    fn last_refill_at(&self) -> Option<&str> {
        self.last_refill_at.as_deref()
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn rate_limit_enabled(&self) -> bool {
        self.rate_limit_enabled
    }
    fn rate_limit_time_window(&self) -> Option<i64> {
        self.rate_limit_time_window
    }
    fn rate_limit_max(&self) -> Option<i64> {
        self.rate_limit_max
    }
    fn request_count(&self) -> Option<i64> {
        self.request_count
    }
    fn remaining(&self) -> Option<i64> {
        self.remaining
    }
    fn last_request(&self) -> Option<&str> {
        self.last_request.as_deref()
    }
    fn expires_at(&self) -> Option<&str> {
        self.expires_at.as_deref()
    }
    fn created_at(&self) -> &str {
        &self.created_at
    }
    fn updated_at(&self) -> &str {
        &self.updated_at
    }
    fn permissions(&self) -> Option<&str> {
        self.permissions.as_deref()
    }
    fn metadata(&self) -> Option<&str> {
        self.metadata.as_deref()
    }
}

// -- Meta trait impls for built-in types --
// Empty impls use the default column/table names which match the built-in schema.
impl AuthUserMeta for User {}
impl AuthSessionMeta for Session {}
impl AuthAccountMeta for Account {}
impl AuthOrganizationMeta for Organization {}
impl AuthMemberMeta for Member {}
impl AuthInvitationMeta for Invitation {}
impl AuthVerificationMeta for Verification {}
impl AuthTwoFactorMeta for TwoFactor {}
impl AuthApiKeyMeta for ApiKey {}
impl AuthPasskeyMeta for Passkey {}

impl AuthPasskey for Passkey {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn public_key(&self) -> &str {
        &self.public_key
    }
    fn user_id(&self) -> &str {
        &self.user_id
    }
    fn credential_id(&self) -> &str {
        &self.credential_id
    }
    fn counter(&self) -> u64 {
        self.counter
    }
    fn device_type(&self) -> &str {
        &self.device_type
    }
    fn backed_up(&self) -> bool {
        self.backed_up
    }
    fn transports(&self) -> Option<&str> {
        self.transports.as_deref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

// Manual FromRow implementations for PostgreSQL
#[cfg(feature = "sqlx-postgres")]
mod postgres_impls {
    use super::*;
    use sqlx::postgres::PgRow;
    use sqlx::{FromRow, Row};

    impl FromRow<'_, PgRow> for User {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            Ok(Self {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                email: row.try_get("email")?,
                email_verified: row.try_get("email_verified")?,
                image: row.try_get("image")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
                username: row.try_get("username")?,
                display_username: row.try_get("display_username")?,
                two_factor_enabled: row.try_get("two_factor_enabled").unwrap_or(false),
                role: row.try_get("role")?,
                banned: row.try_get("banned").unwrap_or(false),
                ban_reason: row.try_get("ban_reason")?,
                ban_expires: row.try_get("ban_expires")?,
                metadata: row
                    .try_get::<sqlx::types::Json<serde_json::Value>, _>("metadata")?
                    .0,
            })
        }
    }

    impl FromRow<'_, PgRow> for Session {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            Ok(Self {
                id: row.try_get("id")?,
                expires_at: row.try_get("expires_at")?,
                token: row.try_get("token")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
                ip_address: row.try_get("ip_address")?,
                user_agent: row.try_get("user_agent")?,
                user_id: row.try_get("user_id")?,
                impersonated_by: row.try_get("impersonated_by")?,
                active_organization_id: row.try_get("active_organization_id")?,
                active: row.try_get("active").unwrap_or(true),
            })
        }
    }

    impl FromRow<'_, PgRow> for Account {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            Ok(Self {
                id: row.try_get("id")?,
                account_id: row.try_get("account_id")?,
                provider_id: row.try_get("provider_id")?,
                user_id: row.try_get("user_id")?,
                access_token: row.try_get("access_token")?,
                refresh_token: row.try_get("refresh_token")?,
                id_token: row.try_get("id_token")?,
                access_token_expires_at: row.try_get("access_token_expires_at")?,
                refresh_token_expires_at: row.try_get("refresh_token_expires_at")?,
                scope: row.try_get("scope")?,
                password: row.try_get("password")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            })
        }
    }

    impl FromRow<'_, PgRow> for Organization {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            Ok(Self {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                slug: row.try_get("slug")?,
                logo: row.try_get("logo")?,
                metadata: row
                    .try_get::<Option<sqlx::types::Json<serde_json::Value>>, _>("metadata")?
                    .map(|j| j.0),
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            })
        }
    }

    impl FromRow<'_, PgRow> for Member {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            Ok(Self {
                id: row.try_get("id")?,
                organization_id: row.try_get("organization_id")?,
                user_id: row.try_get("user_id")?,
                role: row.try_get("role")?,
                created_at: row.try_get("created_at")?,
            })
        }
    }

    impl FromRow<'_, PgRow> for Invitation {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            let status_str: String = row.try_get("status")?;
            Ok(Self {
                id: row.try_get("id")?,
                organization_id: row.try_get("organization_id")?,
                email: row.try_get("email")?,
                role: row.try_get("role")?,
                status: InvitationStatus::from(status_str),
                inviter_id: row.try_get("inviter_id")?,
                expires_at: row.try_get("expires_at")?,
                created_at: row.try_get("created_at")?,
            })
        }
    }

    impl FromRow<'_, PgRow> for Verification {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            Ok(Self {
                id: row.try_get("id")?,
                identifier: row.try_get("identifier")?,
                value: row.try_get("value")?,
                expires_at: row.try_get("expires_at")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            })
        }
    }

    impl FromRow<'_, PgRow> for TwoFactor {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            Ok(Self {
                id: row.try_get("id")?,
                secret: row.try_get("secret")?,
                backup_codes: row.try_get("backup_codes")?,
                user_id: row.try_get("user_id")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            })
        }
    }

    impl FromRow<'_, PgRow> for Passkey {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            let counter_raw = row.try_get::<i64, _>("counter")?;
            let counter = u64::try_from(counter_raw).map_err(|_| {
                sqlx::Error::Decode(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "passkey counter cannot be negative",
                )))
            })?;

            Ok(Self {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                public_key: row.try_get("public_key")?,
                user_id: row.try_get("user_id")?,
                credential_id: row.try_get("credential_id")?,
                counter,
                device_type: row.try_get("device_type")?,
                backed_up: row.try_get("backed_up")?,
                transports: row.try_get("transports")?,
                created_at: row.try_get("created_at")?,
            })
        }
    }

    impl FromRow<'_, PgRow> for ApiKey {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            let created_at: chrono::DateTime<chrono::Utc> = row.try_get("created_at")?;
            let updated_at: chrono::DateTime<chrono::Utc> = row.try_get("updated_at")?;
            let last_refill_at: Option<chrono::DateTime<chrono::Utc>> =
                row.try_get("last_refill_at")?;
            let last_request: Option<chrono::DateTime<chrono::Utc>> =
                row.try_get("last_request")?;
            let expires_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("expires_at")?;

            Ok(Self {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                start: row.try_get("start")?,
                prefix: row.try_get("prefix")?,
                key_hash: row.try_get("key")?,
                user_id: row.try_get("user_id")?,
                refill_interval: row.try_get("refill_interval")?,
                refill_amount: row.try_get("refill_amount")?,
                last_refill_at: last_refill_at.map(|dt| dt.to_rfc3339()),
                enabled: row.try_get("enabled")?,
                rate_limit_enabled: row.try_get("rate_limit_enabled")?,
                rate_limit_time_window: row.try_get("rate_limit_time_window")?,
                rate_limit_max: row.try_get("rate_limit_max")?,
                request_count: row.try_get("request_count")?,
                remaining: row.try_get("remaining")?,
                last_request: last_request.map(|dt| dt.to_rfc3339()),
                expires_at: expires_at.map(|dt| dt.to_rfc3339()),
                created_at: created_at.to_rfc3339(),
                updated_at: updated_at.to_rfc3339(),
                permissions: row.try_get("permissions")?,
                metadata: row.try_get("metadata")?,
            })
        }
    }
}
