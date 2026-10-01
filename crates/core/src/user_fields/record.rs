use super::{UserConfig, UserFieldConfig, UserFieldReference, UserFieldType};
use crate::{AuthResult, SchemaValue};
use serde_json::{Map, Value};
use std::sync::Arc;

fn field(field_type: UserFieldType, required: bool) -> UserFieldConfig {
    UserFieldConfig {
        field_type,
        required: Some(required),
        ..Default::default()
    }
}

fn timestamp(default: bool, update: bool) -> UserFieldConfig {
    let now: Arc<dyn Fn() -> Value + Send + Sync> = Arc::new(|| {
        Value::String(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    });
    UserFieldConfig {
        default_value_fn: default.then(|| now.clone()),
        on_update: update.then_some(now),
        ..field(UserFieldType::Date, true)
    }
}

impl crate::config::AccountConfig {
    /// Compose the adapter schema. A replacement field replaces all built-in attributes.
    pub fn field_schema(&self) -> UserConfig {
        let mut fields = [
            ("accountId".into(), field(UserFieldType::String, true)),
            ("providerId".into(), field(UserFieldType::String, true)),
            (
                "userId".into(),
                UserFieldConfig {
                    references: Some(UserFieldReference {
                        model: "user".into(),
                        field: "id".into(),
                    }),
                    ..field(UserFieldType::String, true)
                },
            ),
            (
                "accessToken".into(),
                UserFieldConfig {
                    returned: false,
                    ..field(UserFieldType::String, false)
                },
            ),
            (
                "refreshToken".into(),
                UserFieldConfig {
                    returned: false,
                    ..field(UserFieldType::String, false)
                },
            ),
            (
                "idToken".into(),
                UserFieldConfig {
                    returned: false,
                    ..field(UserFieldType::String, false)
                },
            ),
            (
                "accessTokenExpiresAt".into(),
                UserFieldConfig {
                    returned: false,
                    ..field(UserFieldType::Date, false)
                },
            ),
            (
                "refreshTokenExpiresAt".into(),
                UserFieldConfig {
                    returned: false,
                    ..field(UserFieldType::Date, false)
                },
            ),
            ("scope".into(), field(UserFieldType::String, false)),
            (
                "password".into(),
                UserFieldConfig {
                    returned: false,
                    ..field(UserFieldType::String, false)
                },
            ),
            ("createdAt".into(), timestamp(true, false)),
            ("updatedAt".into(), timestamp(false, true)),
        ]
        .into_iter()
        .collect::<indexmap::IndexMap<_, _>>();
        fields.extend(self.additional_fields.clone());
        UserConfig {
            additional_fields: fields,
        }
    }
}

impl crate::config::VerificationConfig {
    /// Compose database field policies without applying them to secondary-only values.
    pub fn field_schema(&self) -> UserConfig {
        let mut fields = [
            ("identifier".into(), field(UserFieldType::String, true)),
            ("value".into(), field(UserFieldType::String, true)),
            ("expiresAt".into(), field(UserFieldType::Date, true)),
            ("createdAt".into(), timestamp(true, false)),
            ("updatedAt".into(), timestamp(true, true)),
        ]
        .into_iter()
        .collect::<indexmap::IndexMap<_, _>>();
        fields.extend(self.additional_fields.clone());
        UserConfig {
            additional_fields: fields,
        }
    }
}

impl UserConfig {
    /// Resolve a logical field in an adapter-owned record.
    pub fn record_storage_key<'a>(&'a self, name: &'a str) -> &'a str {
        if name == "id" {
            return name;
        }
        self.additional_fields
            .get(name)
            .and_then(|field| field.field_name.as_deref())
            .unwrap_or(name)
    }

    /// Project a raw adapter record without retaining unmapped storage field names.
    pub fn project_record(
        &self,
        storage: &Map<String, Value>,
        supports_native_json: bool,
        supports_native_dates: bool,
    ) -> AuthResult<indexmap::IndexMap<String, SchemaValue<Value>>> {
        let mut core = Map::new();
        if let Some(id) = storage.get("id") {
            let _ = core.insert(
                "id".into(),
                Value::String(
                    crate::SchemaValue::<String>::from_json(Some(id.clone())).display_string()?,
                ),
            );
        }
        self.record_output_fields(core, storage, supports_native_json, supports_native_dates)
    }

    /// Apply adapter input policies once to a complete logical record or update patch.
    /// Native adapter writes do not run HTTP input validation or remove `input: false` fields.
    pub fn record_storage_fields_for_adapter(
        &self,
        input: Map<String, Value>,
        create: bool,
        supports_native_json: bool,
        native_json_field: impl Fn(&str) -> bool,
    ) -> AuthResult<Map<String, Value>> {
        let mut output = Map::new();
        if let Some(id) = input.get("id") {
            let _ = output.insert("id".into(), id.clone());
        }
        let transformed = self.storage_fields_inner(input, create, true)?;
        for (name, field) in &self.additional_fields {
            if name == "id" {
                continue;
            }
            let storage = field.field_name.as_deref().unwrap_or(name);
            if let Some(value) = transformed.get(storage) {
                let _ = output.insert(
                    storage.to_owned(),
                    field.adapter_input(
                        value.clone(),
                        supports_native_json,
                        native_json_field(storage),
                    ),
                );
            }
        }
        Ok(output)
    }

    /// Project stored values without applying endpoint visibility or decoding replacement types.
    /// The caller must invoke this after the write and before cache writes or database after hooks.
    pub fn record_output_fields(
        &self,
        core: Map<String, Value>,
        storage: &Map<String, Value>,
        supports_native_json: bool,
        supports_native_dates: bool,
    ) -> AuthResult<indexmap::IndexMap<String, SchemaValue<Value>>> {
        let mut output = core
            .into_iter()
            .map(|(name, value)| (name, SchemaValue::Typed(value)))
            .collect::<indexmap::IndexMap<_, _>>();
        for (name, field) in &self.additional_fields {
            if name == "id" {
                continue;
            }
            let value = storage
                .get(field.field_name.as_deref().unwrap_or(name))
                .cloned();
            let value = field.adapter_output(value, supports_native_json)?;
            let value = if !supports_native_dates
                && !field.references_id()
                && matches!(field.field_type, UserFieldType::Date)
            {
                match value {
                    Some(Value::String(text)) => {
                        match crate::utils::date::parse_adapter_date(&text) {
                            Some(date) => SchemaValue::Typed(Value::String(
                                date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                            )),
                            None => SchemaValue::InvalidDate,
                        }
                    }
                    value => SchemaValue::from_json(value),
                }
            } else {
                SchemaValue::from_json(value)
            };
            if value.is_undefined() {
                let _ = output.shift_remove(name);
            } else {
                let _ = output.insert(name.clone(), value);
            }
        }
        Ok(output)
    }
}
