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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Member {
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Invitation {
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

impl<T: AuthMember> From<&T> for Member {
    fn from(member: &T) -> Self {
        Self {
            additional_fields: member.projected_fields().cloned().unwrap_or_default(),
            id: member.id().into_owned(),
            organization_id: member.organization_id().clone(),
            user_id: member.user_id().clone(),
            role: member.role().clone(),
            created_at: member.created_at().clone(),
        }
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

impl<T: AuthInvitation> From<&T> for Invitation {
    fn from(invitation: &T) -> Self {
        Self {
            additional_fields: invitation.projected_fields().cloned().unwrap_or_default(),
            id: invitation.id().into_owned(),
            organization_id: invitation.organization_id().clone(),
            email: invitation.email().clone(),
            role: invitation.role().clone(),
            status: invitation.status().clone(),
            inviter_id: invitation.inviter_id().clone(),
            team_id: invitation.team_id().clone(),
            expires_at: invitation.expires_at().clone(),
            created_at: invitation.created_at().clone(),
        }
    }
}
