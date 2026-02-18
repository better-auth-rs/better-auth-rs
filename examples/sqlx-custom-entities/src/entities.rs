//! Custom entity types for a SaaS application.
//!
//! Each struct has manual `FromRow` implementations for PostgreSQL (because some
//! fields like `metadata` and `InvitationStatus` need special deserialization),
//! and `Auth*` derive macros for the framework trait implementations.

use better_auth_core::{
    AuthAccount, AuthInvitation, AuthMember, AuthOrganization, AuthSession, AuthUser,
    AuthVerification, InvitationStatus,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

// ---------------------------------------------------------------------------
// SaasUser — extra: plan, stripe_customer_id, phone
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, AuthUser)]
pub struct SaasUser {
    pub id: String,
    pub email: Option<String>,
    #[auth(field = "name")]
    pub display_name: Option<String>,
    pub email_verified: bool,
    pub image: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub two_factor_enabled: bool,
    pub role: Option<String>,
    pub banned: bool,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<DateTime<Utc>>,
    pub metadata: serde_json::Value,
    // --- SaaS fields ---
    pub plan: String,
    pub stripe_customer_id: Option<String>,
    pub phone: Option<String>,
}

impl FromRow<'_, PgRow> for SaasUser {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            display_name: row.try_get("name")?,
            email: row.try_get("email")?,
            email_verified: row.try_get("emailVerified")?,
            image: row.try_get("image")?,
            created_at: row.try_get("createdAt")?,
            updated_at: row.try_get("updatedAt")?,
            username: row.try_get("username")?,
            display_username: row.try_get("displayUsername")?,
            two_factor_enabled: row.try_get("twoFactorEnabled").unwrap_or(false),
            role: row.try_get("role")?,
            banned: row.try_get("banned").unwrap_or(false),
            ban_reason: row.try_get("banReason")?,
            ban_expires: row.try_get("banExpires")?,
            metadata: row.try_get::<sqlx::types::Json<serde_json::Value>, _>("metadata")?.0,
            plan: row.try_get("plan").unwrap_or_else(|_| "free".to_string()),
            stripe_customer_id: row.try_get("stripe_customer_id")?,
            phone: row.try_get("phone")?,
        })
    }
}

// ---------------------------------------------------------------------------
// SaasSession — extra: device_id, country
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, AuthSession)]
pub struct SaasSession {
    pub id: String,
    pub expires_at: DateTime<Utc>,
    pub token: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub user_id: String,
    pub impersonated_by: Option<String>,
    pub active_organization_id: Option<String>,
    pub active: bool,
    // --- SaaS fields ---
    pub device_id: Option<String>,
    pub country: Option<String>,
}

impl FromRow<'_, PgRow> for SaasSession {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            expires_at: row.try_get("expiresAt")?,
            token: row.try_get("token")?,
            created_at: row.try_get("createdAt")?,
            updated_at: row.try_get("updatedAt")?,
            ip_address: row.try_get("ipAddress")?,
            user_agent: row.try_get("userAgent")?,
            user_id: row.try_get("userId")?,
            impersonated_by: row.try_get("impersonatedBy")?,
            active_organization_id: row.try_get("activeOrganizationId")?,
            active: row.try_get("active").unwrap_or(true),
            device_id: row.try_get("device_id")?,
            country: row.try_get("country")?,
        })
    }
}

// ---------------------------------------------------------------------------
// SaasAccount — standard fields, no extras
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, sqlx::FromRow, AuthAccount)]
pub struct SaasAccount {
    pub id: String,
    #[sqlx(rename = "accountId")]
    pub account_id: String,
    #[sqlx(rename = "providerId")]
    pub provider_id: String,
    #[sqlx(rename = "userId")]
    pub user_id: String,
    #[sqlx(rename = "accessToken")]
    pub access_token: Option<String>,
    #[sqlx(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[sqlx(rename = "idToken")]
    pub id_token: Option<String>,
    #[sqlx(rename = "accessTokenExpiresAt")]
    pub access_token_expires_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "refreshTokenExpiresAt")]
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub password: Option<String>,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// SaasOrganization — extra: billing_email, plan
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, AuthOrganization)]
pub struct SaasOrganization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    // --- SaaS fields ---
    pub billing_email: Option<String>,
    pub plan: String,
}

impl FromRow<'_, PgRow> for SaasOrganization {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            slug: row.try_get("slug")?,
            logo: row.try_get("logo")?,
            metadata: row
                .try_get::<Option<sqlx::types::Json<serde_json::Value>>, _>("metadata")?
                .map(|j| j.0),
            created_at: row.try_get("createdAt")?,
            updated_at: row.try_get("updatedAt")?,
            billing_email: row.try_get("billing_email")?,
            plan: row.try_get("plan").unwrap_or_else(|_| "free".to_string()),
        })
    }
}

// ---------------------------------------------------------------------------
// SaasMember — standard fields
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, sqlx::FromRow, AuthMember)]
pub struct SaasMember {
    pub id: String,
    #[sqlx(rename = "organizationId")]
    pub organization_id: String,
    #[sqlx(rename = "userId")]
    pub user_id: String,
    pub role: String,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// SaasInvitation — needs manual FromRow for InvitationStatus
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, AuthInvitation)]
pub struct SaasInvitation {
    pub id: String,
    pub organization_id: String,
    pub email: String,
    pub role: String,
    pub status: InvitationStatus,
    pub inviter_id: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl FromRow<'_, PgRow> for SaasInvitation {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        let status_str: String = row.try_get("status")?;
        Ok(Self {
            id: row.try_get("id")?,
            organization_id: row.try_get("organizationId")?,
            email: row.try_get("email")?,
            role: row.try_get("role")?,
            status: InvitationStatus::from(status_str),
            inviter_id: row.try_get("inviterId")?,
            expires_at: row.try_get("expiresAt")?,
            created_at: row.try_get("createdAt")?,
        })
    }
}

// ---------------------------------------------------------------------------
// SaasVerification — standard fields
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, sqlx::FromRow, AuthVerification)]
pub struct SaasVerification {
    pub id: String,
    pub identifier: String,
    pub value: String,
    #[sqlx(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Type alias for the PostgreSQL adapter with all custom types
// ---------------------------------------------------------------------------

pub type SaasAdapter = better_auth::adapters::SqlxAdapter<
    SaasUser,
    SaasSession,
    SaasAccount,
    SaasOrganization,
    SaasMember,
    SaasInvitation,
    SaasVerification,
>;
