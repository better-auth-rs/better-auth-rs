//! Organization teams and dynamic access-control records.
use crate::SchemaValue;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A team belonging to one organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Team {
    /// Application fields projected by the configured team schema.
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    pub id: String,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub name: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub organization_id: SchemaValue<String>,
    #[serde(serialize_with = "crate::schema_value::serialize_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub created_at: SchemaValue<DateTime<Utc>>,
    #[serde(serialize_with = "crate::schema_value::serialize_optional_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub updated_at: SchemaValue<Option<DateTime<Utc>>>,
}

/// Data required to create a team.
#[derive(Debug, Clone, Default)]
pub struct CreateTeam {
    pub id: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    /// Validated application input before adapter transforms.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    pub updated_at: Option<DateTime<Utc>>,
    pub name: SchemaValue<String>,
    pub organization_id: String,
}

/// Mutable team fields. Team IDs cannot be changed.
#[derive(Debug, Clone, Default)]
pub struct UpdateTeam {
    pub name: Option<SchemaValue<String>>,
    pub organization_id: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<Option<DateTime<Utc>>>,
    /// Application fields to update.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

/// A user's membership in a team.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamMember {
    pub id: String,
    pub team_id: String,
    pub user_id: String,
    #[serde(serialize_with = "crate::utils::date::serialize")]
    pub created_at: DateTime<Utc>,
}

/// A dynamic role scoped to one organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationRole {
    /// Application fields projected by the configured role schema.
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    pub id: String,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub organization_id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub role: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub permission: SchemaValue<serde_json::Value>,
    #[serde(serialize_with = "crate::schema_value::serialize_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub created_at: SchemaValue<DateTime<Utc>>,
    #[serde(serialize_with = "crate::schema_value::serialize_optional_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub updated_at: SchemaValue<Option<DateTime<Utc>>>,
}

/// Data required to create a dynamic role.
#[derive(Debug, Clone)]
pub struct CreateOrganizationRole {
    /// Validated application input before adapter transforms.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    pub organization_id: String,
    pub role: String,
    pub permission: serde_json::Value,
}

/// Mutable dynamic-role fields.
#[derive(Debug, Clone, Default)]
pub struct UpdateOrganizationRole {
    /// Application fields to update.
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    pub role: Option<String>,
    pub permission: Option<serde_json::Value>,
}
