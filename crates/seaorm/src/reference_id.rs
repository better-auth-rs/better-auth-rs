//! Preserve scalar database bindings for fields that reference a text ID.

use sea_orm::sea_query::{ArrayType, ColumnType, Nullable, Value, ValueType, ValueTypeErr};
use sea_orm::{ColIdx, QueryResult, TryGetError, TryGetable};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) fn apply_bindings<A: sea_orm::ActiveModelTrait>(
    active: &mut A,
    fields: &better_auth_core::user_fields::UserConfig,
    backend: sea_orm::DbBackend,
    column: impl Fn(&str) -> better_auth_core::AuthResult<<A::Entity as sea_orm::EntityTrait>::Column>,
) -> better_auth_core::AuthResult<()> {
    for (name, field) in &fields.additional_fields {
        if name == "id" || !field.references_id() {
            continue;
        }
        let column = column(field.field_name.as_deref().unwrap_or(name))?;
        if let sea_orm::ActiveValue::Set(value) = active.get(column) {
            active.set(column, binding(value, backend)?);
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
