//! Entity traits for the Better Auth framework.
//!
//! These traits define the interface that entity types must implement.
//! The framework accesses entity fields through these trait methods,
//! allowing users to define their own entity structs with custom field names
//! and extra fields.
//!
//! Use `#[derive(AuthUser)]` etc. from `better-auth-derive` to auto-implement
//! these traits, or implement them manually.

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
