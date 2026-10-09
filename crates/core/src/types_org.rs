use crate::SchemaValue;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use crate::entity::{AuthInvitation, AuthMember, AuthOrganization};

/// Organization entity - matches OpenAPI schema
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Organization {
    /// Application fields projected by the configured organization schema.
    #[serde(with = "crate::field_value::serde::map", flatten)]
    pub additional_fields: crate::FieldMap,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub name: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub slug: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub logo: SchemaValue<Option<String>>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub metadata: SchemaValue<Option<crate::FieldValue>>,
    #[serde(rename = "createdAt")]
    #[serde(with = "crate::field_value::serde::schema_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub created_at: SchemaValue<crate::FieldDate>,
}

/// Organization member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    /// Source property order, independent of the current typed values.
    #[serde(skip)]
    pub field_order: Vec<String>,
    /// Application fields projected by the configured member schema.
    #[serde(with = "crate::field_value::serde::map", flatten)]
    pub additional_fields: crate::FieldMap,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub id: SchemaValue<String>,
    #[serde(rename = "organizationId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub organization_id: SchemaValue<String>,
    #[serde(rename = "userId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub user_id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub role: SchemaValue<String>,
    #[serde(rename = "createdAt")]
    #[serde(with = "crate::field_value::serde::schema_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub created_at: SchemaValue<crate::FieldDate>,
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
    /// Source property order, independent of the current typed values.
    #[serde(skip)]
    pub field_order: Vec<String>,
    /// Application fields projected by the configured invitation schema.
    #[serde(with = "crate::field_value::serde::map", flatten)]
    pub additional_fields: crate::FieldMap,
    #[serde(rename = "teamId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub team_id: SchemaValue<Option<String>>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub id: SchemaValue<String>,
    #[serde(rename = "organizationId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub organization_id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub email: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub role: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub status: SchemaValue<InvitationStatus>,
    #[serde(rename = "inviterId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub inviter_id: SchemaValue<String>,
    #[serde(rename = "expiresAt")]
    #[serde(with = "crate::field_value::serde::schema_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub expires_at: SchemaValue<crate::FieldDate>,
    #[serde(rename = "createdAt")]
    #[serde(with = "crate::field_value::serde::schema_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub created_at: SchemaValue<crate::FieldDate>,
}

impl Invitation {
    /// Check if the invitation is still pending
    pub fn is_pending(&self) -> bool {
        self.status == SchemaValue::Typed(InvitationStatus::Pending)
    }

    /// Check if the invitation has expired
    pub fn is_expired(&self) -> crate::AuthResult<bool> {
        self.expires_at.is_before(Utc::now())
    }
}

impl PartialEq for Invitation {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.organization_id == other.organization_id
            && self.email == other.email
            && self.role == other.role
            && self.status == other.status
            && self.inviter_id == other.inviter_id
            && self.team_id == other.team_id
            && self.expires_at == other.expires_at
            && self.created_at == other.created_at
            && self.additional_fields == other.additional_fields
    }
}

/// Organization creation data
#[derive(Debug, Clone)]
pub struct CreateOrganization {
    /// Validated application input before adapter transforms.
    pub additional_fields: crate::FieldMap,
    pub id: Option<String>,
    pub name: SchemaValue<String>,
    pub slug: SchemaValue<String>,
    pub logo: SchemaValue<Option<String>>,
    pub metadata: SchemaValue<Option<crate::FieldValue>>,
}

impl CreateOrganization {
    pub fn new(name: impl Into<String>, slug: impl Into<String>) -> Self {
        Self {
            id: None,
            additional_fields: Default::default(),
            name: name.into().into(),
            slug: slug.into().into(),
            logo: SchemaValue::Undefined,
            metadata: SchemaValue::Undefined,
        }
    }

    pub fn with_logo(mut self, logo: impl Into<String>) -> Self {
        self.logo = Some(logo.into()).into();
        self
    }

    pub fn with_metadata(mut self, metadata: crate::FieldValue) -> Self {
        self.metadata = Some(metadata).into();
        self
    }
}

/// Organization update data
#[derive(Debug, Clone, Default)]
pub struct UpdateOrganization {
    pub id: Option<String>,
    pub created_at: Option<crate::FieldDate>,
    /// Application fields to update; omitted fields retain their stored values.
    pub additional_fields: crate::FieldMap,
    pub name: Option<String>,
    pub slug: Option<String>,
    pub logo: Option<Option<String>>,
    pub metadata: Option<crate::FieldValue>,
}

/// Member creation data
#[derive(Debug, Clone)]
pub struct CreateMember {
    /// Validated application input before adapter transforms.
    pub additional_fields: crate::FieldMap,
    pub organization_id: SchemaValue<String>,
    pub user_id: SchemaValue<String>,
    pub role: SchemaValue<String>,
}

impl CreateMember {
    pub fn new(
        organization_id: impl Into<String>,
        user_id: impl Into<String>,
        role: impl Into<String>,
    ) -> Self {
        Self {
            organization_id: organization_id.into().into(),
            additional_fields: Default::default(),
            user_id: user_id.into().into(),
            role: role.into().into(),
        }
    }
}

/// Invitation creation data
#[derive(Debug, Clone)]
pub struct CreateInvitation {
    pub id: Option<String>,
    pub created_at: Option<crate::FieldDate>,
    pub status: Option<InvitationStatus>,
    /// Validated application input before adapter transforms.
    pub additional_fields: crate::FieldMap,
    pub team_id: Option<String>,
    pub organization_id: crate::SchemaValue<String>,
    pub email: String,
    pub role: String,
    pub inviter_id: SchemaValue<String>,
    pub expires_at: crate::FieldDate,
}

impl CreateInvitation {
    pub fn new(
        organization_id: impl Into<String>,
        email: impl Into<String>,
        role: impl Into<String>,
        inviter_id: impl Into<String>,
        expires_at: crate::FieldDate,
    ) -> Self {
        Self {
            organization_id: organization_id.into().into(),
            additional_fields: Default::default(),
            email: email.into(),
            role: role.into(),
            inviter_id: inviter_id.into().into(),
            team_id: None,
            id: None,
            created_at: None,
            status: None,
            expires_at,
        }
    }
}

impl<T: AuthOrganization> From<&T> for Organization {
    fn from(organization: &T) -> Self {
        Self {
            additional_fields: organization.projected_fields().cloned().unwrap_or_default(),
            id: organization.id().into_owned(),
            name: organization.name().clone(),
            slug: organization.slug().clone(),
            logo: organization.logo().clone(),
            metadata: organization.metadata().clone(),
            created_at: organization.created_at().clone(),
        }
    }
}

impl AuthOrganization for Organization {
    fn projected_fields(&self) -> Option<&crate::FieldMap> {
        Some(&self.additional_fields)
    }

    fn id(&self) -> SchemaValue<Cow<'_, str>> {
        self.id.as_ref().map(|id| Cow::Borrowed(id.as_str()))
    }
    fn name(&self) -> &SchemaValue<String> {
        &self.name
    }
    fn slug(&self) -> &SchemaValue<String> {
        &self.slug
    }
    fn logo(&self) -> &SchemaValue<Option<String>> {
        &self.logo
    }
    fn metadata(&self) -> &SchemaValue<Option<crate::FieldValue>> {
        &self.metadata
    }
    fn created_at(&self) -> &SchemaValue<crate::FieldDate> {
        &self.created_at
    }
}

impl AuthMember for Member {
    fn projected_fields(&self) -> Option<&crate::FieldMap> {
        Some(&self.additional_fields)
    }

    fn id(&self) -> SchemaValue<Cow<'_, str>> {
        self.id.as_ref().map(|id| Cow::Borrowed(id.as_str()))
    }
    fn organization_id(&self) -> &SchemaValue<String> {
        &self.organization_id
    }
    fn user_id(&self) -> &SchemaValue<String> {
        &self.user_id
    }
    fn role(&self) -> &SchemaValue<String> {
        &self.role
    }
    fn created_at(&self) -> &SchemaValue<crate::FieldDate> {
        &self.created_at
    }
}

impl PartialEq for Member {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.organization_id == other.organization_id
            && self.user_id == other.user_id
            && self.role == other.role
            && self.created_at == other.created_at
            && self.additional_fields == other.additional_fields
    }
}

impl Member {
    /// Preserve the source field values and property order.
    pub fn try_from_member(member: &impl AuthMember) -> crate::AuthResult<Self> {
        <Self as crate::FromFieldMap>::from_field_values(member.field_values()?)
    }
}

impl AuthInvitation for Invitation {
    fn projected_fields(&self) -> Option<&crate::FieldMap> {
        Some(&self.additional_fields)
    }

    fn team_id(&self) -> &SchemaValue<Option<String>> {
        &self.team_id
    }
    fn id(&self) -> SchemaValue<Cow<'_, str>> {
        self.id.as_ref().map(|id| Cow::Borrowed(id.as_str()))
    }
    fn organization_id(&self) -> &SchemaValue<String> {
        &self.organization_id
    }
    fn email(&self) -> &SchemaValue<String> {
        &self.email
    }
    fn role(&self) -> &SchemaValue<String> {
        &self.role
    }
    fn status(&self) -> &SchemaValue<InvitationStatus> {
        &self.status
    }
    fn inviter_id(&self) -> &SchemaValue<String> {
        &self.inviter_id
    }
    fn expires_at(&self) -> &SchemaValue<crate::FieldDate> {
        &self.expires_at
    }
    fn created_at(&self) -> &SchemaValue<crate::FieldDate> {
        &self.created_at
    }
}

impl Invitation {
    /// Preserve native fields and source property order from the invitation output.
    pub fn try_from_invitation(invitation: &impl AuthInvitation) -> crate::AuthResult<Self> {
        crate::FromFieldMap::from_field_values(invitation.field_values()?)
    }
}
