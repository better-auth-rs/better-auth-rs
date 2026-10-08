use crate::{AuthRecordFields, AuthResult, FromFieldMap, SchemaValue};
use serde::Deserialize;

/// A projected account returned by the adapter and trusted database hooks.
/// Field readers must require a type only when an operation needs that type.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    #[serde(skip)]
    pub field_order: Vec<String>,
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
        with = "crate::field_value::serde::optional_schema_date"
    )]
    pub access_token_expires_at: SchemaValue<Option<crate::FieldDate>>,
    #[serde(
        default,
        skip_serializing_if = "SchemaValue::is_undefined",
        with = "crate::field_value::serde::optional_schema_date"
    )]
    pub refresh_token_expires_at: SchemaValue<Option<crate::FieldDate>>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub scope: SchemaValue<Option<String>>,
    // Account cookies serialize this view. Keep the password out of every implicit serialization.
    #[serde(default, skip_serializing)]
    pub password: SchemaValue<Option<String>>,
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
    #[serde(
        deserialize_with = "crate::field_value::serde::map::deserialize",
        flatten
    )]
    pub additional_fields: crate::FieldMap,
}

impl serde::Serialize for AccountView {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let mut fields = self.field_values().map_err(S::Error::custom)?;
        // Account cookies must exclude passwords, including explicit additional-field overrides.
        let _ = fields.shift_remove("password");
        crate::field_value::serde::map::serialize(&fields, serializer)
    }
}

impl AccountView {
    /// Read a complete trusted adapter projection, including the password when present.
    /// Do not use this method to construct account cookies or public account-list responses.
    pub fn internal_fields(&self) -> AuthResult<crate::FieldMap> {
        self.field_values()
    }

    /// Preserve projected date values before JSON serialization loses invalid-date provenance.
    pub fn from_adapter_fields(mut fields: crate::FieldMap) -> Self {
        Self {
            field_order: fields.keys().cloned().collect(),
            id: SchemaValue::from_field(fields.shift_remove("id").unwrap_or_default()),
            account_id: SchemaValue::from_field(
                fields.shift_remove("accountId").unwrap_or_default(),
            ),
            provider_id: SchemaValue::from_field(
                fields.shift_remove("providerId").unwrap_or_default(),
            ),
            user_id: SchemaValue::from_field(fields.shift_remove("userId").unwrap_or_default()),
            access_token: SchemaValue::from_field(
                fields.shift_remove("accessToken").unwrap_or_default(),
            ),
            refresh_token: SchemaValue::from_field(
                fields.shift_remove("refreshToken").unwrap_or_default(),
            ),
            id_token: SchemaValue::from_field(fields.shift_remove("idToken").unwrap_or_default()),
            access_token_expires_at: SchemaValue::from_field(
                fields
                    .shift_remove("accessTokenExpiresAt")
                    .unwrap_or_default(),
            ),
            refresh_token_expires_at: SchemaValue::from_field(
                fields
                    .shift_remove("refreshTokenExpiresAt")
                    .unwrap_or_default(),
            ),
            scope: SchemaValue::from_field(fields.shift_remove("scope").unwrap_or_default()),
            password: SchemaValue::from_field(fields.shift_remove("password").unwrap_or_default()),
            created_at: SchemaValue::from_field(
                fields.shift_remove("createdAt").unwrap_or_default(),
            ),
            updated_at: SchemaValue::from_field(
                fields.shift_remove("updatedAt").unwrap_or_default(),
            ),
            additional_fields: fields,
        }
    }

    /// Decode an adapter result without validating a replacement field's default Rust type.
    pub fn from_fields(fields: crate::FieldMap) -> AuthResult<Self> {
        Self::from_field_values(fields)
    }
}
