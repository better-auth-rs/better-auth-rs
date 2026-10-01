use crate::{AuthResult, SchemaValue};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

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
        serialize_with = "crate::schema_value::serialize_date"
    )]
    pub expires_at: SchemaValue<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "SchemaValue::is_undefined",
        serialize_with = "crate::schema_value::serialize_date"
    )]
    pub created_at: SchemaValue<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "SchemaValue::is_undefined",
        serialize_with = "crate::schema_value::serialize_date"
    )]
    pub updated_at: SchemaValue<DateTime<Utc>>,
    #[serde(flatten)]
    pub additional_fields: indexmap::IndexMap<String, SchemaValue<Value>>,
}

impl VerificationView {
    /// Decode cached or adapter-projected fields without running field policies again.
    /// Preserve projected date values before JSON serialization loses invalid-date provenance.
    pub fn from_adapter_fields(mut fields: indexmap::IndexMap<String, SchemaValue<Value>>) -> Self {
        Self {
            id: fields.shift_remove("id").unwrap_or_default().into_field(),
            identifier: fields
                .shift_remove("identifier")
                .unwrap_or_default()
                .into_field(),
            value: fields
                .shift_remove("value")
                .unwrap_or_default()
                .into_field(),
            expires_at: fields
                .shift_remove("expiresAt")
                .unwrap_or_default()
                .into_field(),
            created_at: fields
                .shift_remove("createdAt")
                .unwrap_or_default()
                .into_field(),
            updated_at: fields
                .shift_remove("updatedAt")
                .unwrap_or_default()
                .into_field(),
            additional_fields: fields,
        }
    }

    pub fn from_fields(fields: Map<String, Value>) -> AuthResult<Self> {
        serde_json::from_value(Value::Object(fields)).map_err(Into::into)
    }

    pub fn fields(&self) -> AuthResult<Map<String, Value>> {
        serde_json::from_value(serde_json::to_value(self)?).map_err(Into::into)
    }
}
