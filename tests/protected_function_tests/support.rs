use better_auth_core::{AuthError, AuthResult, FieldMap, FieldValue};
use serde_json::{Value, json};

pub(super) fn fixture(kind: &str) -> Value {
    assert!(matches!(kind, "input" | "memory"));
    let source = if kind == "input" {
        include_str!("../fixtures/protected-function-input-1.7.6.json")
    } else {
        include_str!("../fixtures/protected-function-memory-1.7.6.json")
    };
    serde_json::from_str(source).unwrap()
}

pub(super) fn operation<'a>(case: &'a Value, name: &str) -> &'a Value {
    case["observation"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|operation| operation["name"] == name)
        .unwrap()
}

pub(super) fn observe(
    value: &FieldValue,
    default: &FieldValue,
    returned: &FieldValue,
) -> AuthResult<Value> {
    Ok(match value {
        FieldValue::Undefined => json!({"type": "undefined"}),
        FieldValue::Function(_) => {
            let identity = if value.strict_equals(default) {
                "default-function"
            } else if value.strict_equals(returned) {
                "returned-function"
            } else {
                return Err(AuthError::internal(
                    "Unregistered function in contract observation",
                ));
            };
            json!({"type": "function", "identity": identity})
        }
        FieldValue::Date(_) => json!({"type": "date", "value": value.json()?.unwrap()}),
        FieldValue::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| observe(value, default, returned))
                .collect::<AuthResult<_>>()?,
        ),
        FieldValue::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(name, value)| Ok((name.clone(), observe(value, default, returned)?)))
                .collect::<AuthResult<_>>()?,
        ),
        value => value.json()?.ok_or_else(|| {
            AuthError::internal("Contract observation requires a representable field value")
        })?,
    })
}

pub(super) fn user(id: &str, extra: FieldMap) -> FieldMap {
    let date = "2030-01-02T03:04:05.000Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap();
    let mut fields = FieldMap::from([
        ("id".into(), id.into()),
        ("name".into(), "Protected function owner".into()),
        (
            "email".into(),
            format!("{id}@protected-function.test").into(),
        ),
        ("emailVerified".into(), false.into()),
        ("image".into(), FieldValue::Null),
        ("createdAt".into(), date.into()),
        ("updatedAt".into(), date.into()),
    ]);
    fields.extend(extra);
    fields
}
