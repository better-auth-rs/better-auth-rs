use crate::{AuthRecordFields, AuthResult, FromFieldMap, SchemaValue};
use serde::{Deserialize, Serialize};

/// A database projection or an untransformed secondary verification snapshot.
/// Omitted core fields remain omitted; pure secondary creation does not generate an adapter ID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VerificationView {
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub identifier: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub value: SchemaValue<String>,
    #[serde(
        default,
        skip_serializing_if = "SchemaValue::is_undefined",
        with = "crate::field_value::serde::schema_date"
    )]
    pub expires_at: SchemaValue<crate::FieldDate>,
    #[serde(
        default,
        skip_serializing_if = "SchemaValue::is_undefined",
        with = "crate::field_value::serde::schema_date"
    )]
    pub created_at: SchemaValue<crate::FieldDate>,
    #[serde(
        default,
        skip_serializing_if = "SchemaValue::is_undefined",
        with = "crate::field_value::serde::schema_date"
    )]
    pub updated_at: SchemaValue<crate::FieldDate>,
    #[serde(with = "crate::field_value::serde::map", flatten)]
    pub additional_fields: crate::FieldMap,
}

impl VerificationView {
    /// Decode cached or adapter-projected fields without running field policies again.
    /// Preserve projected date values before JSON serialization loses invalid-date provenance.
    pub fn from_adapter_fields(mut fields: crate::FieldMap) -> Self {
        Self {
            id: SchemaValue::from_field(fields.shift_remove("id").unwrap_or_default()),
            identifier: SchemaValue::from_field(
                fields.shift_remove("identifier").unwrap_or_default(),
            ),
            value: SchemaValue::from_field(fields.shift_remove("value").unwrap_or_default()),
            expires_at: SchemaValue::from_field(
                fields.shift_remove("expiresAt").unwrap_or_default(),
            ),
            created_at: SchemaValue::from_field(
                fields.shift_remove("createdAt").unwrap_or_default(),
            ),
            updated_at: SchemaValue::from_field(
                fields.shift_remove("updatedAt").unwrap_or_default(),
            ),
            additional_fields: fields,
        }
    }

    pub fn from_fields(fields: crate::FieldMap) -> AuthResult<Self> {
        Self::from_field_values(fields)
    }

    pub fn fields(&self) -> AuthResult<crate::FieldMap> {
        self.field_values()
    }
}
