use super::{UserConfig, UserFieldType};
use crate::{AuthError, AuthResult};
use serde_json::{Map, Value};

impl UserConfig {
    /// Apply configured policies once to logical core fields and application fields.
    /// The adapter owns `id`; custom field attributes cannot replace its policy.
    pub fn organization_storage_fields(
        &self,
        core: Map<String, Value>,
        extras: Map<String, Value>,
        create: bool,
    ) -> AuthResult<Map<String, Value>> {
        let mut output = core.clone();
        output.retain(|name, _| name == "id" || !self.additional_fields.contains_key(name));
        let mut input = extras;
        input.extend(core);
        output.extend(self.storage_fields_inner(input, create, true)?);
        Ok(output)
    }

    /// Merge transformed storage fields into the public logical core fields.
    pub fn organization_output_fields(
        &self,
        mut core: Map<String, Value>,
        storage: &Map<String, Value>,
    ) -> AuthResult<Map<String, Value>> {
        let transformed = self.output_fields_inner(storage, true)?;
        for name in core.keys() {
            if name != "id"
                && self.additional_fields.contains_key(name)
                && !transformed.contains_key(name)
            {
                return Err(AuthError::config(format!(
                    "Organization built-in field {name} output is undefined; typed fields require a compatible value"
                )));
            }
        }
        core.retain(|name, _| name == "id" || !self.additional_fields.contains_key(name));
        core.extend(transformed);
        Ok(core)
    }

    /// Validate Organization route fields without applying adapter defaults or transforms.
    pub fn parse_organization_input(
        &self,
        input: &Map<String, Value>,
        prefix: &str,
        partial: bool,
    ) -> AuthResult<Map<String, Value>> {
        let mut parsed = Map::new();
        let mut errors = Vec::new();
        for (name, field) in &self.additional_fields {
            if !field.input {
                continue;
            }
            let value = input.get(name);
            if value.is_none() && (partial || field.required == Some(false)) {
                continue;
            }
            if value == Some(&Value::Null) && field.required == Some(false) {
                let _ = parsed.insert(name.clone(), Value::Null);
                continue;
            }
            let location = format!("{prefix}.{name}");
            let expected = match &field.field_type {
                UserFieldType::Enum(_) => {
                    if let Some(value) = value {
                        let _ = parsed.insert(name.clone(), value.clone());
                    }
                    continue;
                }
                UserFieldType::String => "string",
                UserFieldType::Number => "number",
                UserFieldType::Boolean => "boolean",
                UserFieldType::Date => "date",
                UserFieldType::Json => "json",
                UserFieldType::StringArray | UserFieldType::NumberArray => "array",
            };
            let valid = match (&field.field_type, value) {
                (UserFieldType::String, Some(Value::String(_)))
                | (UserFieldType::Number, Some(Value::Number(_)))
                | (UserFieldType::Boolean, Some(Value::Bool(_)))
                | (UserFieldType::Json, Some(_)) => true,
                (
                    UserFieldType::StringArray | UserFieldType::NumberArray,
                    Some(Value::Array(values)),
                ) => {
                    let item_type = if matches!(field.field_type, UserFieldType::StringArray) {
                        "string"
                    } else {
                        "number"
                    };
                    for (index, value) in values.iter().enumerate() {
                        if type_name(Some(value)) != item_type {
                            errors.push(invalid_type(
                                &format!("{location}.{index}"),
                                item_type,
                                Some(value),
                            ));
                        }
                    }
                    true
                }
                _ => false,
            };
            if !valid {
                errors.push(invalid_type(&location, expected, value));
            } else if let Some(value) = value {
                let _ = parsed.insert(name.clone(), value.clone());
            }
        }
        if errors.is_empty() {
            Ok(parsed)
        } else {
            Err(AuthError::FieldInput {
                code: "VALIDATION_ERROR",
                message: errors.join("; "),
            })
        }
    }

    /// Apply the adapter's field mapping and output transforms before route visibility filtering.
    pub fn output_fields(&self, storage: &Map<String, Value>) -> AuthResult<Map<String, Value>> {
        self.output_fields_inner(storage, false)
    }

    fn output_fields_inner(
        &self,
        storage: &Map<String, Value>,
        preserve_id: bool,
    ) -> AuthResult<Map<String, Value>> {
        let mut output = Map::new();
        for (name, field) in &self.additional_fields {
            if preserve_id && name == "id" {
                continue;
            }
            let mut value = storage
                .get(field.field_name.as_ref().unwrap_or(name))
                .cloned();
            if let Some(transform) = &field.output_transform {
                value = transform(value)?;
            }
            if let Some(mut value) = value {
                field.normalize_date(&mut value)?;
                let _ = output.insert(name.clone(), value);
            }
        }
        Ok(output)
    }

    /// Apply only `returned` flags to fields already projected by the adapter.
    pub fn filter_returned_fields(&self, fields: &mut Map<String, Value>) {
        fields.retain(|name, _| {
            self.additional_fields
                .get(name)
                .is_none_or(|field| field.returned)
        });
    }
}

fn type_name(value: Option<&Value>) -> &'static str {
    match value {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

fn invalid_type(location: &str, expected: &str, value: Option<&Value>) -> String {
    format!(
        "[{location}] Invalid input: expected {expected}, received {}",
        type_name(value)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user_fields::UserFieldConfig;
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    fn organization_validation_keeps_route_and_adapter_policies_separate() {
        let schema = UserConfig {
            additional_fields: [
                (
                    "implicit".into(),
                    UserFieldConfig {
                        default_value: Some(json!("default")),
                        ..Default::default()
                    },
                ),
                (
                    "label".into(),
                    UserFieldConfig {
                        required: Some(false),
                        field_name: Some("stored_label".into()),
                        validator: Some(Arc::new(|_| Err(AuthError::bad_request("must not run")))),
                        input_transform: Some(Arc::new(|value| {
                            Ok(value.map(|value| json!(format!("{}:in", value.as_str().unwrap()))))
                        })),
                        ..Default::default()
                    },
                ),
                (
                    "protected".into(),
                    UserFieldConfig {
                        input: false,
                        default_value: Some(json!("server")),
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        };
        let error = schema
            .parse_organization_input(&Map::new(), "body", false)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("[body.implicit] Invalid input: expected string, received undefined")
        );
        let input =
            json!({"implicit":"supplied", "label":"raw", "protected":"client", "unknown":true});
        let parsed = schema
            .parse_organization_input(input.as_object().unwrap(), "body", false)
            .unwrap();
        assert_eq!(
            parsed,
            json!({"implicit":"supplied", "label":"raw"})
                .as_object()
                .unwrap()
                .clone()
        );
        let stored = schema.storage_fields(parsed, true).unwrap();
        assert_eq!(
            stored,
            json!({"implicit":"supplied", "stored_label":"raw:in", "protected":"server"})
                .as_object()
                .unwrap()
                .clone()
        );
        assert!(
            schema
                .parse_organization_input(&Map::new(), "body.data", true)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn organization_partial_fields_keep_nullable_and_array_contracts() {
        let schema = UserConfig {
            additional_fields: [
                (
                    "required".into(),
                    UserFieldConfig {
                        required: Some(true),
                        ..Default::default()
                    },
                ),
                (
                    "optional".into(),
                    UserFieldConfig {
                        required: Some(false),
                        ..Default::default()
                    },
                ),
                (
                    "tags".into(),
                    UserFieldConfig {
                        required: Some(false),
                        field_type: UserFieldType::StringArray,
                        ..Default::default()
                    },
                ),
                (
                    "category".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Enum(vec!["basic".into()]),
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        };
        let valid = json!({"optional":null,"category":"unlisted"});
        assert_eq!(
            schema
                .parse_organization_input(valid.as_object().unwrap(), "body.data", true)
                .unwrap(),
            valid.as_object().unwrap().clone()
        );
        let invalid = json!({"required":null,"tags":["valid",4]});
        assert!(
            schema
                .parse_organization_input(invalid.as_object().unwrap(), "body.data", true)
                .unwrap_err()
                .to_string()
                .contains("[body.data.tags.1] Invalid input: expected string, received number")
        );
    }
}
