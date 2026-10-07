//! Bind declared ID references through the configured generation policy and storage type.

use better_auth_core::store::schema::resolve_field_name;
use better_auth_core::{FieldMap, FieldValue};
use sea_orm::sea_query::{ArrayType, ColumnType, Nullable, Value, ValueType, ValueTypeErr};
use sea_orm::{ColIdx, QueryResult, TryGetError, TryGetable};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) fn input_binding<C: sea_orm::ColumnTrait>(
    name: &str,
    field: &better_auth_core::user_fields::UserFieldConfig,
    value: FieldValue,
    policy: &better_auth_core::id::IdGeneration,
    column: impl Fn(&str) -> better_auth_core::AuthResult<C>,
    native_json_field: impl Fn(&str) -> bool,
    backend: sea_orm::DbBackend,
) -> better_auth_core::AuthResult<FieldValue> {
    if matches!(policy, better_auth_core::id::IdGeneration::Serial) && field.references_id() {
        let text_column = matches!(
            column(name)?.def().get_column_type(),
            ColumnType::String(_) | ColumnType::Text | ColumnType::Char(_)
        );
        return serial_reference(value, text_column);
    }
    use better_auth_core::user_fields::UserFieldType;
    // RecordWrite serializes native JSON columns. Only text columns need an encoded array here.
    if backend != sea_orm::DbBackend::Postgres
        && matches!(field.field_type, UserFieldType::Json)
        && (!native_json_field(name) || field.references_id())
        && matches!(
            value,
            FieldValue::Null | FieldValue::Object(_) | FieldValue::Array(_) | FieldValue::Date(_)
        )
        || matches!(
            field.field_type,
            UserFieldType::StringArray | UserFieldType::NumberArray
        ) && value.is_array()
            && !native_json_field(name)
    {
        return value.stringify()?.map(FieldValue::String).ok_or_else(|| {
            better_auth_core::AuthError::internal("SQL JSON encoding returned undefined")
        });
    }
    if backend == sea_orm::DbBackend::Sqlite
        && matches!(field.field_type, UserFieldType::Date)
        && let FieldValue::Date(date) = value
    {
        return crate::store::record_bindings::sqlite_date(date);
    }
    if backend != sea_orm::DbBackend::Postgres
        && let FieldValue::Bool(value) = value
    {
        return Ok(FieldValue::Number(f64::from(u8::from(value))));
    }
    Ok(value)
}

/// Apply Serial conversion after field transforms and before typed model decoding.
pub(crate) fn prepare_fields<C: sea_orm::ColumnTrait>(
    fields: &mut FieldMap,
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
                (resolve_field_name(field.field_name.as_deref(), logical) == name).then_some(field)
            })
        });
        if name == "id"
            || configured.map_or_else(|| is_reference(&column), |field| field.references_id())
        {
            let text = matches!(
                column.def().get_column_type(),
                ColumnType::String(_) | ColumnType::Text | ColumnType::Char(_)
            );
            *value = serial_reference(std::mem::take(value), text)?;
        }
    }
    Ok(())
}

fn serial_reference(
    value: FieldValue,
    text_column: bool,
) -> better_auth_core::AuthResult<FieldValue> {
    let convert = |value: FieldValue| {
        if value.is_null() {
            return Ok(FieldValue::Null);
        }
        let number = better_auth_core::query::field_number(&value)?;
        let text = better_auth_core::schema_value::number_string(number);
        if text_column {
            Ok(FieldValue::String(text))
        } else {
            Ok(FieldValue::Number(number))
        }
    };
    match value {
        FieldValue::Array(values) => values
            .iter()
            .cloned()
            .map(convert)
            .collect::<better_auth_core::AuthResult<Vec<_>>>()
            .map(FieldValue::from),
        value => convert(value),
    }
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
    use better_auth_core::AuthError;
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
            let text = better_auth_core::schema_value::number_string(value);
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
                                    assert_eq!(
                                        value,
                                        better_auth_core::FieldValue::String("alias".into())
                                    );
                                    let _ = observed.fetch_add(1, Ordering::SeqCst);
                                    better_auth_core::FieldValue::from_json(json!([
                                        "0x10",
                                        null,
                                        [],
                                        ["1e0"]
                                    ]))
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
            let expected = better_auth_core::FieldValue::from_json(expected).unwrap();
            let values = config
                .storage_fields_with_binding(
                    [(
                        "owner".into(),
                        better_auth_core::FieldValue::String("alias".into()),
                    )]
                    .into_iter()
                    .collect(),
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
