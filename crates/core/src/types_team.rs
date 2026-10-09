//! Organization teams and dynamic access-control records.
use crate::SchemaValue;
use serde::{Deserialize, Serialize};

/// A team belonging to one organization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Team {
    /// Application fields projected by the configured team schema.
    #[serde(with = "crate::field_value::serde::map", flatten)]
    pub additional_fields: crate::FieldMap,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub name: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub organization_id: SchemaValue<String>,
    #[serde(with = "crate::field_value::serde::schema_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub created_at: SchemaValue<crate::FieldDate>,
    #[serde(with = "crate::field_value::serde::optional_schema_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub updated_at: SchemaValue<Option<crate::FieldDate>>,
}

/// Data required to create a team.
#[derive(Debug, Clone, Default)]
pub struct CreateTeam {
    pub id: Option<String>,
    pub created_at: Option<crate::FieldDate>,
    /// Validated application input before adapter transforms.
    pub additional_fields: crate::FieldMap,
    pub updated_at: Option<crate::FieldDate>,
    pub name: SchemaValue<String>,
    pub organization_id: SchemaValue<String>,
}

/// Mutable team fields. Team IDs cannot be changed.
#[derive(Debug, Clone, Default)]
pub struct UpdateTeam {
    pub name: Option<SchemaValue<String>>,
    pub organization_id: Option<String>,
    pub created_at: Option<crate::FieldDate>,
    pub updated_at: Option<Option<crate::FieldDate>>,
    /// Application fields to update.
    pub additional_fields: crate::FieldMap,
}

/// A user's membership in a team.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TeamMember {
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub team_id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub user_id: SchemaValue<String>,
    #[serde(with = "crate::field_value::serde::date")]
    pub created_at: crate::FieldDate,
}

/// A dynamic role scoped to one organization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationRole {
    /// Application fields projected by the configured role schema.
    #[serde(with = "crate::field_value::serde::map", flatten)]
    pub additional_fields: crate::FieldMap,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub organization_id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub role: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub permission: SchemaValue<crate::FieldValue>,
    #[serde(with = "crate::field_value::serde::schema_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub created_at: SchemaValue<crate::FieldDate>,
    #[serde(with = "crate::field_value::serde::optional_schema_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub updated_at: SchemaValue<Option<crate::FieldDate>>,
}

/// Data required to create a dynamic role.
#[derive(Debug, Clone)]
pub struct CreateOrganizationRole {
    /// Validated application input before adapter transforms.
    pub additional_fields: crate::FieldMap,
    pub organization_id: crate::SchemaValue<String>,
    pub role: String,
    pub permission: crate::FieldValue,
}

/// Mutable dynamic-role fields.
#[derive(Debug, Clone, Default)]
pub struct UpdateOrganizationRole {
    /// Application fields to update.
    pub additional_fields: crate::FieldMap,
    pub role: Option<String>,
    pub permission: Option<crate::FieldValue>,
}
