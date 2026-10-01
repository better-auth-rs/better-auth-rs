use crate::{AuthResult, SchemaValue};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A projected account returned by the adapter and trusted database hooks.
/// Field readers must require a type only when an operation needs that type.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub account_id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub provider_id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub user_id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub access_token: SchemaValue<Option<String>>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub refresh_token: SchemaValue<Option<String>>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id_token: SchemaValue<Option<String>>,
    #[serde(
        default,
        skip_serializing_if = "SchemaValue::is_undefined",
        serialize_with = "crate::schema_value::serialize_optional_date"
    )]
    pub access_token_expires_at: SchemaValue<Option<DateTime<Utc>>>,
    #[serde(
        default,
        skip_serializing_if = "SchemaValue::is_undefined",
        serialize_with = "crate::schema_value::serialize_optional_date"
    )]
    pub refresh_token_expires_at: SchemaValue<Option<DateTime<Utc>>>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub scope: SchemaValue<Option<String>>,
    // Account cookies serialize this view. Keep the password out of every implicit serialization.
    #[serde(default, skip_serializing)]
    pub password: SchemaValue<Option<String>>,
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
    #[serde(flatten, serialize_with = "serialize_additional_fields")]
    pub additional_fields: indexmap::IndexMap<String, SchemaValue<Value>>,
}

fn serialize_additional_fields<S: serde::Serializer>(
    fields: &indexmap::IndexMap<String, SchemaValue<Value>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut output = serializer.serialize_map(None)?;
    for (name, value) in fields {
        // Explicit native construction must not bypass the account cookie password boundary.
        if name != "password" && !value.is_undefined() {
            output.serialize_entry(name, value)?;
        }
    }
    output.end()
}

impl AccountView {
    /// Read a complete trusted adapter projection, including the password when present.
    /// Do not use this method to construct account cookies or public account-list responses.
    pub fn internal_fields(&self) -> AuthResult<Map<String, Value>> {
        let mut fields = serde_json::from_value::<Map<String, Value>>(serde_json::to_value(self)?)?;
        if let Some(password) = self.password.json()? {
            let _ = fields.insert("password".into(), password);
        }
        Ok(fields)
    }

    /// Preserve projected date values before JSON serialization loses invalid-date provenance.
    pub fn from_adapter_fields(mut fields: indexmap::IndexMap<String, SchemaValue<Value>>) -> Self {
        Self {
            id: fields.shift_remove("id").unwrap_or_default().into_field(),
            account_id: fields
                .shift_remove("accountId")
                .unwrap_or_default()
                .into_field(),
            provider_id: fields
                .shift_remove("providerId")
                .unwrap_or_default()
                .into_field(),
            user_id: fields
                .shift_remove("userId")
                .unwrap_or_default()
                .into_field(),
            access_token: fields
                .shift_remove("accessToken")
                .unwrap_or_default()
                .into_field(),
            refresh_token: fields
                .shift_remove("refreshToken")
                .unwrap_or_default()
                .into_field(),
            id_token: fields
                .shift_remove("idToken")
                .unwrap_or_default()
                .into_field(),
            access_token_expires_at: fields
                .shift_remove("accessTokenExpiresAt")
                .unwrap_or_default()
                .into_field(),
            refresh_token_expires_at: fields
                .shift_remove("refreshTokenExpiresAt")
                .unwrap_or_default()
                .into_field(),
            scope: fields
                .shift_remove("scope")
                .unwrap_or_default()
                .into_field(),
            password: fields
                .shift_remove("password")
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

    /// Decode an adapter result without validating a replacement field's default Rust type.
    pub fn from_fields(fields: Map<String, Value>) -> AuthResult<Self> {
        serde_json::from_value(Value::Object(fields)).map_err(Into::into)
    }
}
