//! Organization teams and dynamic access-control records.
use crate::SchemaValue;
use serde::{Deserialize, Serialize};

/// A team belonging to one organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Team {
    /// Source property order, independent of the current typed values.
    #[serde(skip)]
    pub field_order: Vec<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamMember {
    /// Source property order, independent of the current typed values.
    #[serde(skip)]
    pub field_order: Vec<String>,
    /// Application fields projected by the registered membership schema.
    #[serde(with = "crate::field_value::serde::map", flatten)]
    pub additional_fields: crate::FieldMap,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub team_id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub user_id: SchemaValue<String>,
    #[serde(with = "crate::field_value::serde::schema_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub created_at: SchemaValue<crate::FieldDate>,
}

impl PartialEq for Team {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.name == other.name
            && self.organization_id == other.organization_id
            && self.created_at == other.created_at
            && self.updated_at == other.updated_at
            && self.additional_fields == other.additional_fields
    }
}

impl PartialEq for TeamMember {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.team_id == other.team_id
            && self.user_id == other.user_id
            && self.created_at == other.created_at
            && self.additional_fields == other.additional_fields
    }
}

impl Team {
    /// Apply the Organization adapter's object rest operation to a projected relationship.
    #[doc(hidden)]
    pub fn from_membership_join(
        records: Vec<crate::FieldMap>,
        many: bool,
    ) -> crate::AuthResult<Self> {
        let mut fields = if many {
            records
                .into_iter()
                .enumerate()
                .map(|(index, fields)| (index.to_string(), fields.into()))
                .collect()
        } else {
            records.into_iter().next().ok_or_else(|| {
                crate::AuthError::type_error("Cannot destructure a null Team relationship")
            })?
        };
        let _ = fields.shift_remove("memberCount");
        crate::FromFieldMap::from_field_values(fields)
    }
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
