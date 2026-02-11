use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvitationStatus {
    #[default]
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
