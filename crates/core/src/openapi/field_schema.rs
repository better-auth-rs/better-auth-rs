//! OpenAPI projections do not evaluate application field callbacks.
use crate::user_fields::{UserFieldConfig, UserFieldType};
use serde_json::{Map, Value, json};

pub(super) fn component_property(field: &UserFieldConfig) -> Value {
    let kind = match &field.field_type {
        UserFieldType::String | UserFieldType::Date => json!("string"),
        UserFieldType::Number => json!("number"),
        UserFieldType::Boolean => json!("boolean"),
        UserFieldType::Json => json!("json"),
        UserFieldType::StringArray | UserFieldType::NumberArray => json!("array"),
        UserFieldType::Enum(values) => json!(values),
    };
    let mut schema = Map::from_iter([("type".into(), kind)]);
    match field.field_type {
        UserFieldType::Date => {
            let _ = schema.insert("format".into(), json!("date-time"));
        }
        UserFieldType::StringArray => {
            let _ = schema.insert("items".into(), json!({"type":"string"}));
        }
        UserFieldType::NumberArray => {
            let _ = schema.insert("items".into(), json!({"type":"number"}));
        }
        _ => {}
    }
    if field.default_value_fn.is_none()
        && let Some(default) = &field.default_value
    {
        let _ = schema.insert("default".into(), default.clone());
    }
    if !field.input {
        let _ = schema.insert("readOnly".into(), Value::Bool(true));
    }
    Value::Object(schema)
}

pub(super) fn input_property(field: &UserFieldConfig) -> Value {
    match &field.field_type {
        UserFieldType::Date => json!({"type":"string","format":"date-time"}),
        UserFieldType::Json => json!({}),
        UserFieldType::StringArray => json!({"type":"array","items":{"type":"string"}}),
        UserFieldType::NumberArray => json!({"type":"array","items":{"type":"number"}}),
        UserFieldType::Enum(values) => json!({"type":"string","enum":values}),
        _ => {
            let mut schema = component_property(field);
            if let Some(schema) = schema.as_object_mut() {
                let _ = schema.remove("readOnly");
            }
            schema
        }
    }
}
