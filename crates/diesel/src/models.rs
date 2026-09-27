//! Row types for the Better Auth tables.
//!
//! [`User`], [`Session`], [`Account`], and [`Verification`] are the auth
//! models of [`DieselAuthSchema`](crate::DieselAuthSchema). The plugin tables
//! convert to the framework types in `better_auth_core` (`Organization`,
//! `Member`, `ApiKey`, and so on).

use std::borrow::Cow;

use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser, AuthVerification};
use better_auth_core::{
    ApiKey, DeviceCode, Invitation, InvitationStatus, Member, Organization, Passkey, TwoFactor,
};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::Serialize;

use crate::schema::{
    accounts, api_keys, device_codes, invitation, member, organization, passkeys, sessions,
    two_factor, users, verifications,
};
use crate::sql_types::{JsonDocumentValue, NullableUtcTimestampValue, UtcTimestampValue};

/// A row of the `users` table.
#[derive(Debug, Clone, PartialEq, Serialize, Queryable, Selectable, Insertable, Identifiable)]
#[diesel(table_name = users)]
#[diesel(treat_none_as_default_value = false)]
pub struct User {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub image: Option<String>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub two_factor_enabled: bool,
    pub role: Option<String>,
    pub banned: bool,
    pub ban_reason: Option<String>,
    #[diesel(serialize_as = NullableUtcTimestampValue)]
    pub ban_expires: Option<DateTime<Utc>>,
    #[diesel(serialize_as = JsonDocumentValue)]
    pub metadata: serde_json::Value,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub created_at: DateTime<Utc>,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub updated_at: DateTime<Utc>,
}

/// A row of the `sessions` table.
#[derive(Debug, Clone, PartialEq, Serialize, Queryable, Selectable, Insertable, Identifiable)]
#[diesel(table_name = sessions)]
#[diesel(treat_none_as_default_value = false)]
pub struct Session {
    pub id: String,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub expires_at: DateTime<Utc>,
    pub token: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub user_id: String,
    pub impersonated_by: Option<String>,
    pub active_organization_id: Option<String>,
    pub active: bool,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub created_at: DateTime<Utc>,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub updated_at: DateTime<Utc>,
}

/// A row of the `accounts` table.
#[derive(Debug, Clone, PartialEq, Serialize, Queryable, Selectable, Insertable, Identifiable)]
#[diesel(table_name = accounts)]
#[diesel(treat_none_as_default_value = false)]
pub struct Account {
    pub id: String,
    pub account_id: String,
    pub provider_id: String,
    pub user_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    #[diesel(serialize_as = NullableUtcTimestampValue)]
    pub access_token_expires_at: Option<DateTime<Utc>>,
    #[diesel(serialize_as = NullableUtcTimestampValue)]
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub password: Option<String>,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub created_at: DateTime<Utc>,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub updated_at: DateTime<Utc>,
}

/// A row of the `verifications` table.
#[derive(Debug, Clone, PartialEq, Serialize, Queryable, Selectable, Insertable, Identifiable)]
#[diesel(table_name = verifications)]
#[diesel(treat_none_as_default_value = false)]
pub struct Verification {
    pub id: String,
    pub identifier: String,
    pub value: String,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub expires_at: DateTime<Utc>,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub created_at: DateTime<Utc>,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub updated_at: DateTime<Utc>,
}

impl AuthUser for User {
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
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
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
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
    fn user_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.user_id)
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
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
    }
    fn account_id(&self) -> &str {
        &self.account_id
    }
    fn provider_id(&self) -> &str {
        &self.provider_id
    }
    fn user_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.user_id)
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

impl AuthVerification for Verification {
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
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

/// Partial update of a `users` row. `None` leaves the column unchanged.
#[derive(Debug, Default, AsChangeset)]
#[diesel(table_name = users)]
pub(crate) struct UserChanges {
    pub(crate) email: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) image: Option<String>,
    pub(crate) email_verified: Option<bool>,
    pub(crate) username: Option<String>,
    pub(crate) display_username: Option<String>,
    pub(crate) role: Option<String>,
    pub(crate) banned: Option<bool>,
    pub(crate) ban_reason: Option<Option<String>>,
    pub(crate) ban_expires: Option<NullableUtcTimestampValue>,
    pub(crate) two_factor_enabled: Option<bool>,
    pub(crate) metadata: Option<JsonDocumentValue>,
    pub(crate) updated_at: Option<UtcTimestampValue>,
}

/// Partial update of an `accounts` row. `None` leaves the column unchanged.
#[derive(Debug, Default, AsChangeset)]
#[diesel(table_name = accounts)]
pub(crate) struct AccountChanges {
    pub(crate) access_token: Option<String>,
    pub(crate) refresh_token: Option<String>,
    pub(crate) id_token: Option<String>,
    pub(crate) access_token_expires_at: Option<NullableUtcTimestampValue>,
    pub(crate) refresh_token_expires_at: Option<NullableUtcTimestampValue>,
    pub(crate) scope: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) updated_at: Option<UtcTimestampValue>,
}

#[derive(Debug, Clone, Queryable, Selectable, Insertable)]
#[diesel(table_name = organization)]
#[diesel(treat_none_as_default_value = false)]
pub(crate) struct OrganizationRow {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) logo: Option<String>,
    #[diesel(serialize_as = JsonDocumentValue)]
    pub(crate) metadata: serde_json::Value,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub(crate) created_at: DateTime<Utc>,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Debug, Default, AsChangeset)]
#[diesel(table_name = organization)]
pub(crate) struct OrganizationChanges {
    pub(crate) name: Option<String>,
    pub(crate) slug: Option<String>,
    pub(crate) logo: Option<String>,
    pub(crate) metadata: Option<JsonDocumentValue>,
    pub(crate) updated_at: Option<UtcTimestampValue>,
}

impl From<OrganizationRow> for Organization {
    fn from(row: OrganizationRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            slug: row.slug,
            logo: row.logo,
            metadata: Some(row.metadata),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, Clone, Queryable, Selectable, Insertable)]
#[diesel(table_name = member)]
#[diesel(treat_none_as_default_value = false)]
pub(crate) struct MemberRow {
    pub(crate) id: String,
    pub(crate) organization_id: String,
    pub(crate) user_id: String,
    pub(crate) role: String,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub(crate) created_at: DateTime<Utc>,
}

impl From<MemberRow> for Member {
    fn from(row: MemberRow) -> Self {
        Self {
            id: row.id,
            organization_id: row.organization_id,
            user_id: row.user_id,
            role: row.role,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Clone, Queryable, Selectable, Insertable)]
#[diesel(table_name = invitation)]
#[diesel(treat_none_as_default_value = false)]
pub(crate) struct InvitationRow {
    pub(crate) id: String,
    pub(crate) organization_id: String,
    pub(crate) email: String,
    pub(crate) role: String,
    pub(crate) status: String,
    pub(crate) inviter_id: String,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub(crate) expires_at: DateTime<Utc>,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub(crate) created_at: DateTime<Utc>,
}

impl From<InvitationRow> for Invitation {
    fn from(row: InvitationRow) -> Self {
        Self {
            id: row.id,
            organization_id: row.organization_id,
            email: row.email,
            role: row.role,
            status: InvitationStatus::from(row.status),
            inviter_id: row.inviter_id,
            expires_at: row.expires_at,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Clone, Queryable, Selectable, Insertable)]
#[diesel(table_name = two_factor)]
#[diesel(treat_none_as_default_value = false)]
pub(crate) struct TwoFactorRow {
    pub(crate) id: String,
    pub(crate) secret: String,
    pub(crate) backup_codes: String,
    pub(crate) user_id: String,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub(crate) created_at: DateTime<Utc>,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub(crate) updated_at: DateTime<Utc>,
}

impl From<TwoFactorRow> for TwoFactor {
    fn from(row: TwoFactorRow) -> Self {
        Self {
            id: row.id,
            secret: row.secret,
            backup_codes: row.backup_codes,
            user_id: row.user_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, Clone, Queryable, Selectable, Insertable)]
#[diesel(table_name = api_keys)]
#[diesel(treat_none_as_default_value = false)]
pub(crate) struct ApiKeyRow {
    pub(crate) id: String,
    pub(crate) name: Option<String>,
    pub(crate) start: Option<String>,
    pub(crate) prefix: Option<String>,
    pub(crate) key_hash: String,
    pub(crate) reference_id: String,
    pub(crate) config_id: String,
    pub(crate) refill_interval: Option<i32>,
    pub(crate) refill_amount: Option<i32>,
    #[diesel(serialize_as = NullableUtcTimestampValue)]
    pub(crate) last_refill_at: Option<DateTime<Utc>>,
    pub(crate) enabled: bool,
    pub(crate) rate_limit_enabled: bool,
    pub(crate) rate_limit_time_window: Option<i32>,
    pub(crate) rate_limit_max: Option<i32>,
    pub(crate) request_count: Option<i32>,
    pub(crate) remaining: Option<i32>,
    #[diesel(serialize_as = NullableUtcTimestampValue)]
    pub(crate) last_request: Option<DateTime<Utc>>,
    #[diesel(serialize_as = NullableUtcTimestampValue)]
    pub(crate) expires_at: Option<DateTime<Utc>>,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub(crate) created_at: DateTime<Utc>,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub(crate) updated_at: DateTime<Utc>,
    pub(crate) permissions: Option<String>,
    pub(crate) metadata: Option<String>,
}

/// Partial update of an `api_keys` row. `None` leaves the column unchanged;
/// `Some(NullableUtcTimestampValue(None))` writes `NULL`.
#[derive(Debug, Default, AsChangeset)]
#[diesel(table_name = api_keys)]
pub(crate) struct ApiKeyChanges {
    pub(crate) name: Option<String>,
    pub(crate) enabled: Option<bool>,
    pub(crate) remaining: Option<i32>,
    pub(crate) rate_limit_enabled: Option<bool>,
    pub(crate) rate_limit_time_window: Option<i32>,
    pub(crate) rate_limit_max: Option<i32>,
    pub(crate) refill_interval: Option<i32>,
    pub(crate) refill_amount: Option<i32>,
    pub(crate) permissions: Option<String>,
    pub(crate) metadata: Option<String>,
    pub(crate) expires_at: Option<NullableUtcTimestampValue>,
    pub(crate) last_request: Option<NullableUtcTimestampValue>,
    pub(crate) request_count: Option<i32>,
    pub(crate) last_refill_at: Option<NullableUtcTimestampValue>,
    pub(crate) updated_at: Option<UtcTimestampValue>,
}

fn to_rfc3339(value: DateTime<Utc>) -> String {
    value.to_rfc3339()
}

impl From<ApiKeyRow> for ApiKey {
    fn from(row: ApiKeyRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            start: row.start,
            prefix: row.prefix,
            key_hash: row.key_hash,
            reference_id: row.reference_id,
            config_id: row.config_id,
            refill_interval: row.refill_interval.map(i64::from),
            refill_amount: row.refill_amount.map(i64::from),
            last_refill_at: row.last_refill_at.map(to_rfc3339),
            enabled: row.enabled,
            rate_limit_enabled: row.rate_limit_enabled,
            rate_limit_time_window: row.rate_limit_time_window.map(i64::from),
            rate_limit_max: row.rate_limit_max.map(i64::from),
            request_count: row.request_count.map(i64::from),
            remaining: row.remaining.map(i64::from),
            last_request: row.last_request.map(to_rfc3339),
            expires_at: row.expires_at.map(to_rfc3339),
            created_at: to_rfc3339(row.created_at),
            updated_at: to_rfc3339(row.updated_at),
            permissions: row.permissions,
            metadata: row.metadata,
        }
    }
}

#[derive(Debug, Clone, Queryable, Selectable, Insertable)]
#[diesel(table_name = passkeys)]
#[diesel(treat_none_as_default_value = false)]
pub(crate) struct PasskeyRow {
    pub(crate) id: String,
    pub(crate) name: Option<String>,
    pub(crate) public_key: String,
    pub(crate) user_id: String,
    pub(crate) credential_id: String,
    pub(crate) counter: i64,
    pub(crate) device_type: String,
    pub(crate) backed_up: bool,
    pub(crate) transports: Option<String>,
    pub(crate) credential: String,
    pub(crate) aaguid: Option<String>,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub(crate) created_at: DateTime<Utc>,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub(crate) updated_at: DateTime<Utc>,
}

impl From<PasskeyRow> for Passkey {
    fn from(row: PasskeyRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            public_key: row.public_key,
            user_id: row.user_id,
            credential_id: row.credential_id,
            counter: u64::try_from(row.counter).unwrap_or_default(),
            device_type: row.device_type,
            backed_up: row.backed_up,
            transports: row.transports,
            created_at: row.created_at,
            updated_at: row.updated_at,
            aaguid: row.aaguid,
            credential: row.credential,
        }
    }
}

#[derive(Debug, Clone, Queryable, Selectable, Insertable)]
#[diesel(table_name = device_codes)]
#[diesel(treat_none_as_default_value = false)]
pub(crate) struct DeviceCodeRow {
    pub(crate) id: String,
    pub(crate) device_code: String,
    pub(crate) user_code: String,
    pub(crate) user_id: Option<String>,
    #[diesel(serialize_as = UtcTimestampValue)]
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) status: String,
    #[diesel(serialize_as = NullableUtcTimestampValue)]
    pub(crate) last_polled_at: Option<DateTime<Utc>>,
    pub(crate) polling_interval: Option<i64>,
    pub(crate) client_id: Option<String>,
    pub(crate) scope: Option<String>,
}

/// Partial update of a `device_code` row. `None` leaves the column
/// unchanged; `Some(None)` and `Some(NullableUtcTimestampValue(None))` write
/// `NULL`.
#[derive(Debug, Default, AsChangeset)]
#[diesel(table_name = device_codes)]
pub(crate) struct DeviceCodeChanges {
    pub(crate) status: Option<String>,
    pub(crate) user_id: Option<Option<String>>,
    pub(crate) last_polled_at: Option<NullableUtcTimestampValue>,
}

impl DeviceCodeChanges {
    pub(crate) fn is_empty(&self) -> bool {
        self.status.is_none() && self.user_id.is_none() && self.last_polled_at.is_none()
    }
}

impl From<DeviceCodeRow> for DeviceCode {
    fn from(row: DeviceCodeRow) -> Self {
        Self {
            id: row.id,
            device_code: row.device_code,
            user_code: row.user_code,
            user_id: row.user_id,
            expires_at: row.expires_at,
            status: row.status,
            last_polled_at: row.last_polled_at,
            polling_interval: row.polling_interval,
            client_id: row.client_id,
            scope: row.scope,
        }
    }
}
