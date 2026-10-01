use crate::SchemaValue;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::borrow::Cow;

use crate::entity::{AuthInvitation, AuthMember, AuthOrganization};

fn serialize_json_option_as_string<S>(
    value: &SchemaValue<Option<serde_json::Value>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        SchemaValue::Typed(Some(inner)) => serializer
            .serialize_some(&serde_json::to_string(inner).map_err(serde::ser::Error::custom)?),
        value => value.serialize(serializer),
    }
}

fn deserialize_json_option_from_string<'de, D>(
    deserializer: D,
) -> Result<SchemaValue<Option<serde_json::Value>>, D::Error>
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
        .map(SchemaValue::Typed)
}

/// Organization entity - matches OpenAPI schema
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Organization {
    /// Application fields projected by the configured organization schema.
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub name: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub slug: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub logo: SchemaValue<Option<String>>,
    #[serde(
        serialize_with = "serialize_json_option_as_string",
        deserialize_with = "deserialize_json_option_from_string"
    )]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub metadata: SchemaValue<Option<serde_json::Value>>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::schema_value::serialize_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub created_at: SchemaValue<DateTime<Utc>>,
}

/// Organization member
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Member {
    /// Application fields projected by the configured member schema.
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id: SchemaValue<String>,
    #[serde(rename = "organizationId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub organization_id: SchemaValue<String>,
    #[serde(rename = "userId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub user_id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub role: SchemaValue<String>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::schema_value::serialize_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub created_at: SchemaValue<DateTime<Utc>>,
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
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    #[serde(rename = "teamId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub team_id: SchemaValue<Option<String>>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id: SchemaValue<String>,
    #[serde(rename = "organizationId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub organization_id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub email: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub role: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub status: SchemaValue<InvitationStatus>,
    #[serde(rename = "inviterId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub inviter_id: SchemaValue<String>,
    #[serde(rename = "expiresAt")]
    #[serde(serialize_with = "crate::schema_value::serialize_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub expires_at: SchemaValue<DateTime<Utc>>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::schema_value::serialize_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub created_at: SchemaValue<DateTime<Utc>>,
}

impl Invitation {
    /// Check if the invitation is still pending
    pub fn is_pending(&self) -> bool {
        self.status == SchemaValue::Typed(InvitationStatus::Pending)
    }

    /// Check if the invitation has expired
    pub fn is_expired(&self) -> crate::AuthResult<bool> {
        let timestamp = match &self.expires_at {
            SchemaValue::Typed(value) => return Ok(*value < Utc::now()),
            SchemaValue::Dynamic(Value::Null) => Some(0.0),
            SchemaValue::Dynamic(Value::Bool(value)) => Some(f64::from(u8::from(*value))),
            SchemaValue::Dynamic(Value::Number(value)) => value.as_f64(),
            SchemaValue::Dynamic(Value::String(_) | Value::Array(_)) => {
                let value = self.expires_at.display_string()?;
                if value
                    .trim_matches(|ch: char| {
                        (ch.is_whitespace() && ch != '\u{85}') || ch == '\u{feff}'
                    })
                    .is_empty()
                {
                    Some(0.0)
                } else {
                    crate::organization_fields::numeric_filter(&value)
                }
            }
            SchemaValue::Dynamic(Value::Object(_))
            | SchemaValue::Undefined
            | SchemaValue::InvalidDate => None,
        };
        // Upstream compares the replacement value with a Date, which coerces to milliseconds.
        Ok(timestamp.is_some_and(|value| value < Utc::now().timestamp_millis() as f64))
    }
}

/// Organization creation data
#[derive(Debug, Clone)]
pub struct CreateOrganization {
    /// Validated application input before adapter transforms.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    pub id: Option<String>,
    pub name: SchemaValue<String>,
    pub slug: SchemaValue<String>,
    pub logo: SchemaValue<Option<String>>,
    pub metadata: SchemaValue<Option<serde_json::Value>>,
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

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata).into();
        self
    }
}

/// Organization update data
#[derive(Debug, Clone, Default)]
pub struct UpdateOrganization {
    pub id: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    /// Application fields to update; omitted fields retain their stored values.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    pub name: Option<String>,
    pub slug: Option<String>,
    pub logo: Option<Option<String>>,
    pub metadata: Option<serde_json::Value>,
}

/// Member creation data
#[derive(Debug, Clone)]
pub struct CreateMember {
    /// Validated application input before adapter transforms.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
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
    pub created_at: Option<DateTime<Utc>>,
    pub status: Option<InvitationStatus>,
    /// Validated application input before adapter transforms.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    pub team_id: Option<String>,
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
            additional_fields: Default::default(),
            email: email.into(),
            role: role.into(),
            inviter_id: inviter_id.into(),
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
    fn projected_fields(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
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
    fn metadata(&self) -> &SchemaValue<Option<serde_json::Value>> {
        &self.metadata
    }
    fn created_at(&self) -> &SchemaValue<DateTime<Utc>> {
        &self.created_at
    }
}

impl AuthMember for Member {
    fn projected_fields(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
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
    fn created_at(&self) -> &SchemaValue<DateTime<Utc>> {
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
    fn projected_fields(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
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
    fn expires_at(&self) -> &SchemaValue<DateTime<Utc>> {
        &self.expires_at
    }
    fn created_at(&self) -> &SchemaValue<DateTime<Utc>> {
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
