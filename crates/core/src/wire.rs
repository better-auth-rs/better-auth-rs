//! Wire-facing response view models.
//!
//! These types exist to decouple JSON response shapes from internal runtime
//! models and app-owned SeaORM entities.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entity::{AuthAccount, AuthSession, AuthUser, AuthVerification};

fn is_false(value: &bool) -> bool {
    !(*value)
}

/// Public user response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserView {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "displayUsername", skip_serializing_if = "Option::is_none")]
    pub display_username: Option<String>,
    #[serde(rename = "twoFactorEnabled", skip_serializing_if = "is_false", default)]
    pub two_factor_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "is_false", default)]
    pub banned: bool,
    #[serde(rename = "banReason", skip_serializing_if = "Option::is_none")]
    pub ban_reason: Option<String>,
    #[serde(rename = "banExpires", skip_serializing_if = "Option::is_none")]
    pub ban_expires: Option<DateTime<Utc>>,
}

/// Public session response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionView {
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
    #[serde(rename = "impersonatedBy", skip_serializing_if = "Option::is_none")]
    pub impersonated_by: Option<String>,
    #[serde(
        rename = "activeOrganizationId",
        skip_serializing_if = "Option::is_none"
    )]
    pub active_organization_id: Option<String>,
}

/// Public account response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountView {
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

/// Public verification response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationView {
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

impl<T: AuthUser> From<&T> for UserView {
    fn from(user: &T) -> Self {
        Self {
            id: user.id().to_owned(),
            name: user.name().map(str::to_owned),
            email: user.email().map(str::to_owned),
            email_verified: user.email_verified(),
            image: user.image().map(str::to_owned),
            created_at: user.created_at(),
            updated_at: user.updated_at(),
            username: user.username().map(str::to_owned),
            display_username: user.display_username().map(str::to_owned),
            two_factor_enabled: user.two_factor_enabled(),
            role: user.role().map(str::to_owned),
            banned: user.banned(),
            ban_reason: user.ban_reason().map(str::to_owned),
            ban_expires: user.ban_expires(),
        }
    }
}

impl<T: AuthSession> From<&T> for SessionView {
    fn from(session: &T) -> Self {
        Self {
            id: session.id().to_owned(),
            expires_at: session.expires_at(),
            token: session.token().to_owned(),
            created_at: session.created_at(),
            updated_at: session.updated_at(),
            ip_address: session.ip_address().map(str::to_owned),
            user_agent: session.user_agent().map(str::to_owned),
            user_id: session.user_id().to_owned(),
            impersonated_by: session.impersonated_by().map(str::to_owned),
            active_organization_id: session.active_organization_id().map(str::to_owned),
        }
    }
}

impl<T: AuthAccount> From<&T> for AccountView {
    fn from(account: &T) -> Self {
        Self {
            id: account.id().to_owned(),
            account_id: account.account_id().to_owned(),
            provider_id: account.provider_id().to_owned(),
            user_id: account.user_id().to_owned(),
            access_token: account.access_token().map(str::to_owned),
            refresh_token: account.refresh_token().map(str::to_owned),
            id_token: account.id_token().map(str::to_owned),
            access_token_expires_at: account.access_token_expires_at(),
            refresh_token_expires_at: account.refresh_token_expires_at(),
            scope: account.scope().map(str::to_owned),
            password: account.password().map(str::to_owned),
            created_at: account.created_at(),
            updated_at: account.updated_at(),
        }
    }
}

impl<T: AuthVerification> From<&T> for VerificationView {
    fn from(verification: &T) -> Self {
        Self {
            id: verification.id().to_owned(),
            identifier: verification.identifier().to_owned(),
            value: verification.value().to_owned(),
            expires_at: verification.expires_at(),
            created_at: verification.created_at(),
            updated_at: verification.updated_at(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Session, User};

    #[test]
    fn user_view_serializes_camel_case() {
        let user = User {
            id: "user-1".to_string(),
            name: Some("Ada".to_string()),
            email: Some("ada@example.com".to_string()),
            email_verified: true,
            image: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            username: Some("ada".to_string()),
            display_username: Some("Ada".to_string()),
            two_factor_enabled: true,
            role: Some("admin".to_string()),
            banned: false,
            ban_reason: None,
            ban_expires: None,
            metadata: serde_json::json!({}),
        };

        let json = serde_json::to_value(UserView::from(&user)).expect("serialize user view");
        assert_eq!(json["emailVerified"], true);
        assert_eq!(json["displayUsername"], "Ada");
        assert_eq!(json["twoFactorEnabled"], true);
    }

    #[test]
    fn session_view_serializes_camel_case() {
        let session = Session {
            id: "session-1".to_string(),
            expires_at: Utc::now(),
            token: "token".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("agent".to_string()),
            user_id: "user-1".to_string(),
            impersonated_by: Some("admin-1".to_string()),
            active_organization_id: Some("org-1".to_string()),
            active: true,
        };

        let json = serde_json::to_value(SessionView::from(&session))
            .expect("serialize session view");
        assert_eq!(json["expiresAt"].is_string(), true);
        assert_eq!(json["ipAddress"], "127.0.0.1");
        assert_eq!(json["activeOrganizationId"], "org-1");
    }
}
