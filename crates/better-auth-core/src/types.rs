use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use validator::Validate;

/// Core user type - matches OpenAPI schema
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,
    pub image: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
    pub username: Option<String>,
    #[serde(rename = "displayUsername")]
    pub display_username: Option<String>,
    #[serde(rename = "twoFactorEnabled")]
    pub two_factor_enabled: bool,
    pub role: Option<String>,
    pub banned: bool,
    #[serde(rename = "banReason")]
    pub ban_reason: Option<String>,
    #[serde(rename = "banExpires")]
    pub ban_expires: Option<DateTime<Utc>>,
    // Keep metadata for internal use but don't serialize
    #[serde(skip)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Session information - matches OpenAPI schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    pub token: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
    #[serde(rename = "ipAddress")]
    pub ip_address: Option<String>,
    #[serde(rename = "userAgent")]
    pub user_agent: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "impersonatedBy")]
    pub impersonated_by: Option<String>,
    #[serde(rename = "activeOrganizationId")]
    pub active_organization_id: Option<String>,
    // Keep active field for internal use but don't serialize
    #[serde(skip)]
    pub active: bool,
}

/// Account linking (for OAuth providers) - matches OpenAPI schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[serde(rename = "idToken")]
    pub id_token: Option<String>,
    #[serde(rename = "accessTokenExpiresAt")]
    pub access_token_expires_at: Option<DateTime<Utc>>,
    #[serde(rename = "refreshTokenExpiresAt")]
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub password: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

/// Verification token - matches OpenAPI schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verification {
    pub id: String,
    pub identifier: String,
    pub value: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

/// Two-factor authentication - matches OpenAPI schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactor {
    pub id: String,
    pub secret: String,
    #[serde(rename = "backupCodes")]
    pub backup_codes: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: String,
}

/// Passkey authentication - matches OpenAPI schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passkey {
    pub id: String,
    pub name: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    pub counter: u64,
    #[serde(rename = "deviceType")]
    pub device_type: String,
    #[serde(rename = "backedUp")]
    pub backed_up: bool,
}

/// HTTP method enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Options,
    Head,
}

/// Authentication request wrapper
#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub method: HttpMethod,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub query: HashMap<String, String>,
}

/// Authentication response wrapper
#[derive(Debug, Clone)]
pub struct AuthResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// User creation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUser {
    pub id: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: Option<bool>,
    pub password: Option<String>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub role: Option<String>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// User update data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUser {
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: Option<bool>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<DateTime<Utc>>,
    pub two_factor_enabled: Option<bool>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Session creation data
#[derive(Debug, Clone)]
pub struct CreateSession {
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub impersonated_by: Option<String>,
    pub active_organization_id: Option<String>,
}

/// Account creation data
#[derive(Debug, Clone)]
pub struct CreateAccount {
    pub user_id: String,
    pub account_id: String,
    pub provider_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub password: Option<String>,
}

/// Verification token creation data
#[derive(Debug, Clone)]
pub struct CreateVerification {
    pub identifier: String,
    pub value: String,
    pub expires_at: DateTime<Utc>,
}

impl CreateUser {
    pub fn new() -> Self {
        Self {
            id: Some(Uuid::new_v4().to_string()),
            email: None,
            name: None,
            image: None,
            email_verified: None,
            password: None,
            username: None,
            display_username: None,
            role: None,
            metadata: None,
        }
    }

    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_email_verified(mut self, verified: bool) -> Self {
        self.email_verified = Some(verified);
        self
    }

    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    pub fn with_metadata(mut self, metadata: HashMap<String, serde_json::Value>) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

impl Default for CreateUser {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthRequest {
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            headers: HashMap::new(),
            body: None,
            query: HashMap::new(),
        }
    }

    pub fn method(&self) -> &HttpMethod {
        &self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn header(&self, name: &str) -> Option<&String> {
        self.headers.get(name)
    }

    pub fn body_as_json<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        if let Some(body) = &self.body {
            serde_json::from_slice(body)
        } else {
            serde_json::from_str("{}")
        }
    }
}

impl AuthResponse {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    pub fn json<T: Serialize>(status: u16, data: &T) -> Result<Self, serde_json::Error> {
        let body = serde_json::to_vec(data)?;
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        Ok(Self {
            status,
            headers,
            body,
        })
    }

    pub fn text(status: u16, text: impl Into<String>) -> Self {
        let body = text.into().into_bytes();
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/plain".to_string());

        Self {
            status,
            headers,
            body,
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }
}

// User profile management request/response structures
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    #[validate(email(message = "Invalid email address"))]
    pub email: Option<String>,
    pub image: Option<String>,
    pub username: Option<String>,
    #[serde(rename = "displayUsername")]
    pub display_username: Option<String>,
    pub role: Option<String>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize)]
pub struct UpdateUserResponse {
    pub user: User,
}

#[derive(Debug, Serialize)]
pub struct DeleteUserResponse {
    pub success: bool,
    pub message: String,
}

// ============================================================================
// Organization Types
// ============================================================================

/// Organization entity - matches OpenAPI schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

/// Organization member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub id: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub role: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

/// Member with user details (for API responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberWithUser {
    pub id: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub role: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    pub user: MemberUser,
}

/// Minimal user info for member responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberUser {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
}

/// Invitation status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Rejected,
    Canceled,
}

impl From<String> for InvitationStatus {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "accepted" => Self::Accepted,
            "rejected" => Self::Rejected,
            "canceled" => Self::Canceled,
            _ => Self::Pending,
        }
    }
}

impl std::fmt::Display for InvitationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Accepted => write!(f, "accepted"),
            Self::Rejected => write!(f, "rejected"),
            Self::Canceled => write!(f, "canceled"),
        }
    }
}

/// Organization invitation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invitation {
    pub id: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    pub email: String,
    pub role: String,
    pub status: InvitationStatus,
    #[serde(rename = "inviterId")]
    pub inviter_id: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

impl Invitation {
    /// Check if the invitation is still pending
    pub fn is_pending(&self) -> bool {
        self.status == InvitationStatus::Pending
    }

    /// Check if the invitation has expired
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }
}

/// Organization creation data
#[derive(Debug, Clone)]
pub struct CreateOrganization {
    pub id: Option<String>,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

impl CreateOrganization {
    pub fn new(name: impl Into<String>, slug: impl Into<String>) -> Self {
        Self {
            id: Some(Uuid::new_v4().to_string()),
            name: name.into(),
            slug: slug.into(),
            logo: None,
            metadata: None,
        }
    }

    pub fn with_logo(mut self, logo: impl Into<String>) -> Self {
        self.logo = Some(logo.into());
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Organization update data
#[derive(Debug, Clone, Default)]
pub struct UpdateOrganization {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub logo: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Member creation data
#[derive(Debug, Clone)]
pub struct CreateMember {
    pub organization_id: String,
    pub user_id: String,
    pub role: String,
}

impl CreateMember {
    pub fn new(
        organization_id: impl Into<String>,
        user_id: impl Into<String>,
        role: impl Into<String>,
    ) -> Self {
        Self {
            organization_id: organization_id.into(),
            user_id: user_id.into(),
            role: role.into(),
        }
    }
}

/// Invitation creation data
#[derive(Debug, Clone)]
pub struct CreateInvitation {
    pub organization_id: String,
    pub email: String,
    pub role: String,
    pub inviter_id: String,
    pub expires_at: DateTime<Utc>,
}

impl CreateInvitation {
    pub fn new(
        organization_id: impl Into<String>,
        email: impl Into<String>,
        role: impl Into<String>,
        inviter_id: impl Into<String>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            organization_id: organization_id.into(),
            email: email.into(),
            role: role.into(),
            inviter_id: inviter_id.into(),
            expires_at,
        }
    }
}

/// Full organization with members and invitations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullOrganization {
    #[serde(flatten)]
    pub organization: Organization,
    pub members: Vec<MemberWithUser>,
    pub invitations: Vec<Invitation>,
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
                metadata: {
                    let json_value: sqlx::types::Json<HashMap<String, serde_json::Value>> =
                        row.try_get("metadata")?;
                    json_value.0
                },
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
                metadata: row.try_get::<Option<sqlx::types::Json<serde_json::Value>>, _>("metadata")?
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
}
