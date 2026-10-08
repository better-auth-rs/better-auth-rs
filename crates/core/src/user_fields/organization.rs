use super::{UserConfig, UserFieldConfig, UserFieldType};
use crate::store::schema::resolve_field_name;
#[cfg(test)]
use crate::user_fields::{FieldTransforms, UserFieldTransform};
use crate::{AuthError, AuthResult};
use crate::{FieldMap, FieldValue as Value};

impl UserConfig {
    /// Apply configured policies once to logical core fields and application fields.
    /// The adapter owns `id`; custom field attributes cannot replace its policy.
    pub async fn organization_storage_fields(
        &self,
        core: FieldMap,
        extras: FieldMap,
        create: bool,
    ) -> AuthResult<FieldMap> {
        self.organization_storage_fields_with_binding(core, extras, create, |_, _, value| Ok(value))
            .await
    }

    /// Bind each configured field before omitting Undefined or merging its storage column.
    #[doc(hidden)]
    pub async fn organization_storage_fields_with_binding(
        &self,
        core: FieldMap,
        extras: FieldMap,
        create: bool,
        bind: impl Fn(&str, &UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<FieldMap> {
        let mut output = core.clone();
        output.retain(|name, _| name == "id" || !self.fields().contains_key(name));
        let mut input = extras;
        input.extend(core);
        output.extend(self.storage_fields_async(input, create, true, bind).await?);
        Ok(output)
    }

    /// Validate Organization route fields without applying adapter defaults or transforms.
    pub fn parse_organization_input(
        &self,
        input: &FieldMap,
        prefix: &str,
        partial: bool,
    ) -> AuthResult<FieldMap> {
        let mut parsed = FieldMap::new();
        let mut errors = Vec::new();
        for (name, field) in self.fields() {
            match field.validate_organization_input(
                input.get(name),
                &format!("{prefix}.{name}"),
                partial,
            ) {
                Ok(Some(value)) => {
                    let _ = parsed.insert(name.clone(), value);
                }
                Ok(None) => {}
                Err(AuthError::FieldInput { message, .. }) => errors.push(message),
                Err(error) => return Err(error),
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
    pub async fn output_fields(&self, storage: &FieldMap) -> AuthResult<FieldMap> {
        // Projection preserves the one input row.
        Ok(self
            .output_fields_many(std::slice::from_ref(storage))
            .await?
            .remove(0))
    }

    /// Project a database result while retaining row order and per-row field order.
    pub async fn output_fields_many(&self, storage: &[FieldMap]) -> AuthResult<Vec<FieldMap>> {
        self.output_fields_many_with_json(storage, |_| true).await
    }

    pub(crate) async fn output_memory_fields_many(
        &self,
        storage: &[FieldMap],
    ) -> AuthResult<Vec<FieldMap>> {
        self.output_fields_many_with_json(storage, UserFieldConfig::references_id)
            .await
    }

    async fn output_fields_many_with_json(
        &self,
        storage: &[FieldMap],
        supports_native_json: impl Fn(&UserFieldConfig) -> bool + Sync,
    ) -> AuthResult<Vec<FieldMap>> {
        let mut rows: Vec<_> = storage
            .iter()
            .map(|storage| (storage, FieldMap::new()))
            .collect();
        super::batch::project_fields(
            &mut rows,
            self.fields(),
            |(storage, output), name, field| {
                let supports_native_json = supports_native_json(field);
                Box::pin(async move {
                    let value = storage
                        .get(resolve_field_name(field.field_name.as_deref(), name))
                        .cloned();
                    let value = field
                        .adapter_output(value.unwrap_or_default(), supports_native_json)
                        .await?;
                    let _ = output.insert(name.to_owned(), value);
                    Ok(())
                })
            },
        )
        .await?;
        Ok(rows.into_iter().map(|(_, output)| output).collect())
    }

    /// Apply only `returned` flags to fields already projected by the adapter.
    pub fn filter_returned_fields(&self, fields: &mut FieldMap) {
        fields.retain(|name, _| self.fields().get(name).is_none_or(|field| field.returned()));
    }
}
impl UserFieldConfig {
    /// Validate one Organization field without applying adapter defaults or transforms.
    pub fn validate_organization_input(
        &self,
        value: Option<&Value>,
        location: &str,
        partial: bool,
    ) -> AuthResult<Option<Value>> {
        if !self.input() || value.is_none() && (partial || self.required == Some(false)) {
            return Ok(None);
        }
        if matches!(value, Some(Value::Null | Value::Undefined)) && self.required == Some(false) {
            return Ok(value.cloned());
        }
        let expected = match &self.field_type {
            UserFieldType::Enum(_) => return Ok(value.cloned()),
            UserFieldType::String => "string",
            UserFieldType::Number => "number",
            UserFieldType::Boolean => "boolean",
            UserFieldType::Date => "date",
            UserFieldType::Json => "json",
            UserFieldType::StringArray | UserFieldType::NumberArray => "array",
        };
        let mut errors = Vec::new();
        let valid = match (&self.field_type, value) {
            (UserFieldType::String, Some(Value::String(_) | Value::Utf16String(_)))
            | (UserFieldType::Boolean, Some(Value::Bool(_))) => true,
            (UserFieldType::Number, Some(Value::Number(value))) => value.is_finite(),
            (UserFieldType::Json, Some(value)) => json_input(value),
            (UserFieldType::Date, Some(Value::Date(value))) => value.milliseconds().is_finite(),
            (
                UserFieldType::StringArray | UserFieldType::NumberArray,
                Some(Value::Array(values)),
            ) => {
                let item_type = if matches!(self.field_type, UserFieldType::StringArray) {
                    "string"
                } else {
                    "number"
                };
                for (index, value) in values.iter().enumerate() {
                    if type_name(Some(value)) != item_type
                        || matches!(value, Value::Number(number) if !number.is_finite())
                    {
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
            errors.push(if matches!(self.field_type, UserFieldType::Json) {
                format!("[{location}] Invalid input")
            } else {
                invalid_type(location, expected, value)
            });
        }
        if errors.is_empty() {
            Ok(value.cloned())
        } else {
            Err(AuthError::FieldInput {
                code: "VALIDATION_ERROR",
                message: errors.join("; "),
            })
        }
    }
}

fn json_input(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) | Value::Utf16String(_) => true,
        Value::Number(value) => value.is_finite(),
        Value::Array(values) => values.iter().all(json_input),
        Value::Object(values) => values.values().all(json_input),
        Value::Undefined | Value::Date(_) => false,
    }
}

fn type_name(value: Option<&Value>) -> &'static str {
    match value {
        None | Some(Value::Undefined) => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(value)) if value.is_nan() => "NaN",
        Some(Value::Number(value)) if *value == f64::INFINITY => "Infinity",
        Some(Value::Number(value)) if *value == f64::NEG_INFINITY => "-Infinity",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_) | Value::Utf16String(_)) => "string",
        Some(Value::Date(_)) => "Date",
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
    macro_rules! json {
        ($($token:tt)*) => { Value::from_json(serde_json::json!($($token)*)).expect("valid JSON field") };
    }
    use std::sync::Arc;

    #[test]
    fn native_json_fields_reject_values_that_json_would_omit_or_change() {
        let field = UserFieldConfig {
            field_type: UserFieldType::Json,
            ..Default::default()
        };
        for value in [
            Value::Undefined,
            Value::from(crate::FieldDate::from_milliseconds(0.0)),
            Value::from(f64::NAN),
            Value::from(vec![Value::from(f64::INFINITY)]),
            Value::from(FieldMap::from([("omitted".into(), Value::Undefined)])),
        ] {
            let error = field
                .validate_organization_input(Some(&value), "body.payload", false)
                .unwrap_err();
            assert!(
                matches!(error, AuthError::FieldInput { code: "VALIDATION_ERROR", message } if message == "[body.payload] Invalid input")
            );
        }
        let lone_surrogate = Value::from(crate::Utf16String::from_units(vec![0xd800]));
        let object = Value::from(FieldMap::from([("text".into(), lone_surrogate)]));
        let output = field
            .validate_organization_input(Some(&object), "body.payload", false)
            .unwrap()
            .unwrap();
        assert!(output.strict_equals(&object));
    }

    #[test]
    fn native_schema_validation_preserves_dates_and_rejects_nonfinite_numbers() {
        let field = UserFieldConfig {
            field_type: UserFieldType::Date,
            required: Some(false),
            ..Default::default()
        };
        let date = Value::from(crate::FieldDate::from_milliseconds(0.0));
        let output = field
            .validate_organization_input(Some(&date), "body.date", false)
            .unwrap()
            .unwrap();
        assert!(output.strict_equals(&date));
        assert_eq!(
            field
                .validate_organization_input(Some(&Value::Undefined), "body.date", false)
                .unwrap(),
            Some(Value::Undefined)
        );
        let invalid = Value::from(crate::FieldDate::invalid());
        assert!(
            matches!(field.validate_organization_input(Some(&invalid), "body.date", false).unwrap_err(), AuthError::FieldInput { message, .. } if message == "[body.date] Invalid input: expected date, received Date")
        );
        let field = UserFieldConfig {
            field_type: UserFieldType::Number,
            ..Default::default()
        };
        for (number, label) in [
            (f64::NAN, "NaN"),
            (f64::INFINITY, "Infinity"),
            (f64::NEG_INFINITY, "-Infinity"),
        ] {
            assert!(
                matches!(field.validate_organization_input(Some(&Value::from(number)), "body.number", false).unwrap_err(), AuthError::FieldInput { message, .. } if message == format!("[body.number] Invalid input: expected number, received {label}"))
            );
        }
    }

    #[tokio::test]
    async fn organization_validation_keeps_route_and_adapter_policies_separate() {
        let schema = UserConfig {
            additional_fields: Some(
                [
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
                            validator: Some(crate::user_fields::FieldValidators {
                                input: Some(Arc::new(|_| {
                                    Err(AuthError::bad_request("must not run"))
                                })),
                                ..Default::default()
                            }),
                            transform: Some(FieldTransforms {
                                input: Some(UserFieldTransform::new(|value| {
                                    Ok(json!(format!("{}:in", value.as_str().unwrap())))
                                })),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    ),
                    (
                        "protected".into(),
                        UserFieldConfig {
                            input: Some(false),
                            default_value: Some(json!("server")),
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
            ),
        };
        let error = schema
            .parse_organization_input(&FieldMap::new(), "body", false)
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
        let stored = schema.storage_fields(parsed, true).await.unwrap();
        assert_eq!(
            stored,
            json!({"implicit":"supplied", "stored_label":"raw:in", "protected":"server"})
                .as_object()
                .unwrap()
                .clone()
        );
        assert!(
            schema
                .parse_organization_input(&FieldMap::new(), "body.data", true)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn organization_partial_fields_keep_nullable_and_array_contracts() {
        let schema = UserConfig {
            additional_fields: Some(
                [
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
            ),
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
