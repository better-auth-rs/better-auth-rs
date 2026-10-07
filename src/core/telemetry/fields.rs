use super::option;
use better_auth_core::{
    AuthResult,
    user_fields::{UserFieldConfig, UserFieldType},
};
use serde_json::{Map, Value, json};

pub(super) fn configuration<'a>(
    fields: impl IntoIterator<Item = (&'a String, &'a UserFieldConfig)>,
) -> AuthResult<Value> {
    fields
        .into_iter()
        .map(|(name, field)| {
            let field_type = match &field.field_type {
                UserFieldType::String => json!("string"),
                UserFieldType::Number => json!("number"),
                UserFieldType::Boolean => json!("boolean"),
                UserFieldType::Date => json!("date"),
                UserFieldType::Json => json!("json"),
                UserFieldType::StringArray => json!("string[]"),
                UserFieldType::NumberArray => json!("number[]"),
                UserFieldType::Enum(values) => json!(values),
            };
            let mut value = Map::from_iter([("type".into(), field_type)]);
            option(&mut value, "required", field.required)?;
            option(&mut value, "input", field.input)?;
            option(&mut value, "returned", field.returned)?;
            option(&mut value, "unique", field.unique)?;
            option(&mut value, "fieldName", field.field_name.as_ref())?;
            if let Some(reference) = &field.references {
                let _ = value.insert(
                    "references".into(),
                    json!({"model":reference.model,"field":reference.field}),
                );
            }
            // JSON omits function-valued attributes. Never invoke application callbacks for telemetry.
            if field.default_value_fn.is_none() {
                option(
                    &mut value,
                    "defaultValue",
                    field
                        .default_value
                        .as_ref()
                        .map(better_auth_core::FieldValue::json)
                        .transpose()?
                        .flatten(),
                )?;
            }
            if field.transform.is_some() {
                let _ = value.insert("transform".into(), json!({}));
            }
            Ok((name.clone(), Value::Object(value)))
        })
        .collect::<AuthResult<Map<_, _>>>()
        .map(Value::Object)
}
