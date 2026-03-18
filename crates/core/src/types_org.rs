use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::entity::{AuthInvitation, AuthMember, AuthOrganization};
use crate::store::sea_orm::entities;

fn serialize_json_option_as_string<S>(
    value: &Option<serde_json::Value>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(inner) => serializer
            .serialize_some(&serde_json::to_string(inner).map_err(serde::ser::Error::custom)?),
        None => serializer.serialize_none(),
    }
}

fn deserialize_json_option_from_string<'de, D>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum MetadataValue {
        Json(serde_json::Value),
        String(String),
    }

    let value = Option::<MetadataValue>::deserialize(deserializer)?;
    value
        .map(|inner| match inner {
            MetadataValue::Json(value) => Ok(value),
            MetadataValue::String(value) => match serde_json::from_str(&value) {
                Ok(parsed) => Ok(parsed),
                Err(_) => Ok(serde_json::Value::String(value)),
            },
        })
        .transpose()
}

/// Organization entity - matches OpenAPI schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    #[serde(
        serialize_with = "serialize_json_option_as_string",
        deserialize_with = "deserialize_json_option_from_string",
        skip_serializing_if = "Option::is_none"
    )]
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

impl<T: AuthOrganization> From<&T> for Organization {
    fn from(organization: &T) -> Self {
        Self {
            id: organization.id().to_owned(),
            name: organization.name().to_owned(),
            slug: organization.slug().to_owned(),
            logo: organization.logo().map(str::to_owned),
            metadata: organization.metadata().cloned(),
            created_at: organization.created_at(),
            updated_at: organization.updated_at(),
        }
    }
}

impl From<&entities::organization::Model> for Organization {
    fn from(model: &entities::organization::Model) -> Self {
        Self {
            id: model.id.clone(),
            name: model.name.clone(),
            slug: model.slug.clone(),
            logo: model.logo.clone(),
            metadata: Some(model.metadata.clone()),
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
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

impl<T: AuthMember> From<&T> for Member {
    fn from(member: &T) -> Self {
        Self {
            id: member.id().to_owned(),
            organization_id: member.organization_id().to_owned(),
            user_id: member.user_id().to_owned(),
            role: member.role().to_owned(),
            created_at: member.created_at(),
        }
    }
}

impl From<&entities::member::Model> for Member {
    fn from(model: &entities::member::Model) -> Self {
        Self {
            id: model.id.clone(),
            organization_id: model.organization_id.clone(),
            user_id: model.user_id.clone(),
            role: model.role.clone(),
            created_at: model.created_at,
        }
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

impl<T: AuthInvitation> From<&T> for Invitation {
    fn from(invitation: &T) -> Self {
        Self {
            id: invitation.id().to_owned(),
            organization_id: invitation.organization_id().to_owned(),
            email: invitation.email().to_owned(),
            role: invitation.role().to_owned(),
            status: invitation.status().clone(),
            inviter_id: invitation.inviter_id().to_owned(),
            expires_at: invitation.expires_at(),
            created_at: invitation.created_at(),
        }
    }
}

impl From<&entities::invitation::Model> for Invitation {
    fn from(model: &entities::invitation::Model) -> Self {
        Self {
            id: model.id.clone(),
            organization_id: model.organization_id.clone(),
            email: model.email.clone(),
            role: model.role.clone(),
            status: InvitationStatus::from(model.status.clone()),
            inviter_id: model.inviter_id.clone(),
            expires_at: model.expires_at,
            created_at: model.created_at,
        }
    }
}
