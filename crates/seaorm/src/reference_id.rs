//! Bind declared ID references through the configured generation policy and storage type.

use sea_orm::sea_query::{ArrayType, ColumnType, Nullable, Value, ValueType, ValueTypeErr};
use sea_orm::{ColIdx, QueryResult, TryGetError, TryGetable};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) fn input_binding<C: sea_orm::ColumnTrait>(
    name: &str,
    field: &better_auth_core::user_fields::UserFieldConfig,
    value: serde_json::Value,
    policy: &better_auth_core::id::IdGeneration,
    column: impl Fn(&str) -> better_auth_core::AuthResult<C>,
    native_json_field: impl Fn(&str) -> bool,
    backend: sea_orm::DbBackend,
) -> better_auth_core::AuthResult<serde_json::Value> {
    if matches!(policy, better_auth_core::id::IdGeneration::Serial) && field.references_id() {
        let text_column = matches!(
            column(name)?.def().get_column_type(),
            ColumnType::String(_) | ColumnType::Text | ColumnType::Char(_)
        );
        return serial_reference(value, text_column);
    }
    Ok(field.adapter_input(
        value,
        backend == sea_orm::DbBackend::Postgres,
        native_json_field(name),
    ))
}

/// Apply Serial conversion after field transforms and before typed model decoding.
pub(crate) fn prepare_fields<C: sea_orm::ColumnTrait>(
    fields: &mut serde_json::Map<String, serde_json::Value>,
    policy: &better_auth_core::id::IdGeneration,
    config: Option<&better_auth_core::user_fields::UserConfig>,
    column: impl Fn(&str) -> better_auth_core::AuthResult<C>,
    is_reference: impl Fn(&C) -> bool,
) -> better_auth_core::AuthResult<()> {
    if !matches!(policy, better_auth_core::id::IdGeneration::Serial) {
        return Ok(());
    }
    for (name, value) in fields {
        let column = column(name)?;
        let configured = config.and_then(|config| {
            config.fields().iter().find_map(|(logical, field)| {
                (field.field_name.as_deref().unwrap_or(logical) == name).then_some(field)
            })
        });
        if name == "id"
            || configured.map_or_else(|| is_reference(&column), |field| field.references_id())
        {
            let text = matches!(
                column.def().get_column_type(),
                ColumnType::String(_) | ColumnType::Text | ColumnType::Char(_)
            );
            *value = serial_reference(value.take(), text)?;
        }
    }
    Ok(())
}

fn serial_reference(
    value: serde_json::Value,
    text_column: bool,
) -> better_auth_core::AuthResult<serde_json::Value> {
    use serde_json::Value;
    let convert = |value: Value| {
        if value.is_null() {
            return Ok(Value::Null);
        }
        let number = better_auth_core::query::number(&value)?;
        let text = better_auth_core::schema_value::number_string(number);
        if text_column {
            Ok(Value::String(text))
        } else {
            Ok(serde_json::from_str(&text)?)
        }
    };
    match value {
        Value::Array(values) => values
            .into_iter()
            .map(convert)
            .collect::<better_auth_core::AuthResult<Vec<_>>>()
            .map(Value::Array),
        value => convert(value),
    }
}

pub(crate) fn apply_bindings<A: sea_orm::ActiveModelTrait>(
    active: &mut A,
    fields: &better_auth_core::user_fields::UserConfig,
    backend: sea_orm::DbBackend,
    column: impl Fn(&str) -> better_auth_core::AuthResult<<A::Entity as sea_orm::EntityTrait>::Column>,
) -> better_auth_core::AuthResult<()> {
    for (name, field) in fields.fields() {
        if name == "id" || !field.references_id() {
            continue;
        }
        let column = column(field.field_name.as_deref().unwrap_or(name))?;
        if let sea_orm::ActiveValue::Set(value) = active.get(column) {
            use sea_orm::ColumnTrait;
            let text_column = matches!(
                column.def().get_column_type(),
                ColumnType::String(_) | ColumnType::Text | ColumnType::Char(_)
            );
            if backend != sea_orm::DbBackend::Postgres || text_column {
                active.set(column, binding(value, backend)?);
            }
        }
    }
    Ok(())
}

/// A database ID reference whose public field may have a non-string input type.
///
/// Writes retain scalar bindings. Reads use the database's text conversion.
/// The field output policy then applies Better Auth's reference-to-ID conversion.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ReferenceId {
    /// Text stored or read from the referenced ID column.
    Text(String),
    /// An integral input represented exactly by the upstream SQLite driver.
    Integer(i64),
    /// A floating-point input, including negative zero.
    Real(f64),
    /// A boolean binding for adapters with native boolean support.
    Boolean(bool),
}

impl std::str::FromStr for ReferenceId {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self::Text(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for ReferenceId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::String(value) => Ok(Self::Text(value)),
            serde_json::Value::Bool(value) => Ok(Self::Boolean(value)),
            serde_json::Value::Number(value) => {
                let value = value.as_f64().ok_or_else(|| {
                    D::Error::custom("reference number exceeds the JavaScript number range")
                })?;
                Ok(Self::Real(value))
            }
            _ => Err(D::Error::custom(
                "an ID reference requires an adapter-converted scalar",
            )),
        }
    }
}

pub(crate) fn binding(
    value: Value,
    backend: sea_orm::DbBackend,
) -> better_auth_core::AuthResult<Value> {
    use better_auth_core::{AuthError, SchemaValue};
    match (backend, value) {
        // The pinned Bun SQLite driver uses signed 52-bit integers; other adapters do not share this boundary.
        (sea_orm::DbBackend::Sqlite, Value::Double(Some(value)))
            if value.fract() == 0.0
                && (-2_251_799_813_685_248.0..2_251_799_813_685_248.0).contains(&value)
                && !(value == 0.0 && value.is_sign_negative()) =>
        {
            let value = format!("{value:.0}").parse().map_err(|error| {
                AuthError::internal(format!("Cannot bind integral SQLite reference: {error}"))
            })?;
            Ok(Value::BigInt(Some(value)))
        }
        // node-postgres sends number and boolean parameters as their JavaScript string values.
        (sea_orm::DbBackend::Postgres, Value::Double(Some(value))) => {
            let number = serde_json::Number::from_f64(value)
                .ok_or_else(|| AuthError::internal("Reference number must be finite"))?;
            let text = SchemaValue::<String>::Dynamic(serde_json::Value::Number(number))
                .display_string()?;
            Ok(Value::String(Some(text)))
        }
        (sea_orm::DbBackend::Postgres, Value::BigInt(Some(value))) => {
            Ok(Value::String(Some(value.to_string())))
        }
        (sea_orm::DbBackend::Postgres, Value::Bool(Some(value))) => {
            Ok(Value::String(Some(value.to_string())))
        }
        (_, value) => Ok(value),
    }
}

impl From<ReferenceId> for Value {
    fn from(value: ReferenceId) -> Self {
        match value {
            ReferenceId::Text(value) => Self::String(Some(value)),
            ReferenceId::Integer(value) => Self::BigInt(Some(value)),
            ReferenceId::Real(value) => Self::Double(Some(value)),
            ReferenceId::Boolean(value) => Self::Bool(Some(value)),
        }
    }
}

impl Nullable for ReferenceId {
    fn null() -> Value {
        Value::String(None)
    }
}

impl ValueType for ReferenceId {
    fn try_from(value: Value) -> Result<Self, ValueTypeErr> {
        match value {
            Value::String(Some(value)) => Ok(Self::Text(value)),
            Value::BigInt(Some(value)) => Ok(Self::Integer(value)),
            Value::Double(Some(value)) => Ok(Self::Real(value)),
            Value::Bool(Some(value)) => Ok(Self::Boolean(value)),
            _ => Err(ValueTypeErr),
        }
    }
    fn type_name() -> String {
        "ReferenceId".to_owned()
    }
    fn array_type() -> ArrayType {
        ArrayType::String
    }
    fn column_type() -> ColumnType {
        ColumnType::Text
    }
}

impl TryGetable for ReferenceId {
    fn try_get_by<I: ColIdx>(result: &QueryResult, index: I) -> Result<Self, TryGetError> {
        String::try_get_by(result, index).map(Self::Text)
    }
}

#[cfg(test)]
mod tests {
    use super::input_binding;
    use better_auth_core::id::IdGeneration;
    use better_auth_core::user_fields::{
        UserConfig, UserFieldConfig, UserFieldReference, UserFieldType,
    };
    use serde_json::json;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn serial_references_skip_json_encoding_after_one_application_transform() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let config = UserConfig {
            additional_fields: Some(
                [(
                    "owner".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Json,
                        references: Some(UserFieldReference {
                            model: "user".into(),
                            field: "id".into(),
                        }),
                        transform: Some(better_auth_core::user_fields::FieldTransforms {
                            input: Some(better_auth_core::user_fields::UserFieldTransform::new(
                                move |value| {
                                    assert_eq!(value, Some(json!("alias")));
                                    let _ = observed.fetch_add(1, Ordering::SeqCst);
                                    Ok(Some(json!(["0x10", null, [], ["1e0"]])))
                                },
                            )),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        };
        for (policy, expected) in [
            (IdGeneration::Serial, json!([16, null, 0, 1])),
            (IdGeneration::Random, json!("[\"0x10\",null,[],[\"1e0\"]]")),
        ] {
            let values = config
                .storage_fields_with_binding(
                    [("owner".into(), json!("alias"))].into_iter().collect(),
                    true,
                    |name, field, value| {
                        input_binding(
                            name,
                            field,
                            value,
                            &policy,
                            |_| Ok(crate::store::entities::user::Column::Metadata),
                            |_| true,
                            sea_orm::DbBackend::Sqlite,
                        )
                    },
                )
                .await;
            assert!(
                values
                    .as_ref()
                    .is_ok_and(|values| values.get("owner") == Some(&expected)),
                "{values:?}"
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
