//! Convert typed SQL columns without passing runtime values through JSON.

use better_auth_core::{AuthError, AuthResult, FieldValue};
use sea_orm::sea_query::{ArrayType, ColumnType, Value, ValueType};

/// Convert a SQL column value while preserving native dates, arrays, and SQL NULL.
/// Return a configuration error for an unsupported column type.
pub fn from_column(value: Value) -> AuthResult<FieldValue> {
    if value == value.as_null() {
        return Ok(FieldValue::Null);
    }
    Ok(match value {
        Value::Bool(Some(value)) => value.into(),
        Value::TinyInt(Some(value)) => f64::from(value).into(),
        Value::SmallInt(Some(value)) => f64::from(value).into(),
        Value::Int(Some(value)) => f64::from(value).into(),
        Value::BigInt(Some(value)) => (value as f64).into(),
        Value::TinyUnsigned(Some(value)) => f64::from(value).into(),
        Value::SmallUnsigned(Some(value)) => f64::from(value).into(),
        Value::Unsigned(Some(value)) => f64::from(value).into(),
        Value::BigUnsigned(Some(value)) => (value as f64).into(),
        Value::Float(Some(value)) => f64::from(value).into(),
        Value::Double(Some(value)) => value.into(),
        Value::String(Some(value)) => value.into(),
        Value::Char(Some(value)) => value.to_string().into(),
        Value::Json(Some(value)) => FieldValue::from_json(*value)?,
        Value::ChronoDateTimeUtc(Some(value)) => value.into(),
        Value::ChronoDateTimeLocal(Some(value)) => value.to_utc().into(),
        Value::ChronoDateTimeWithTimeZone(Some(value)) => value.to_utc().into(),
        Value::ChronoDateTime(Some(value)) => value.and_utc().into(),
        Value::ChronoDate(Some(value)) => value.to_string().into(),
        Value::ChronoTime(Some(value)) => value.to_string().into(),
        Value::Uuid(Some(value)) => value.to_string().into(),
        Value::Array(_, Some(values)) => (*values)
            .into_iter()
            .map(from_column)
            .collect::<AuthResult<Vec<_>>>()?
            .into(),
        _ => {
            return Err(AuthError::config(
                "SQL column type cannot be represented as an adapter field",
            ));
        }
    })
}

/// Decode an adapter field into the model's declared SQL column type.
/// Return an error if the field cannot be represented by that type.
/// Handle nullable non-JSON columns outside this function. Native SQL array writes are unsupported.
pub fn decode_column<T: ValueType>(value: FieldValue) -> AuthResult<T> {
    let value = if matches!(T::column_type(), ColumnType::Json | ColumnType::JsonBinary) {
        Value::Json(Some(Box::new(value.json()?.ok_or_else(|| {
            AuthError::internal("An undefined field cannot be assigned to a SQL JSON column")
        })?)))
    } else {
        match value {
            FieldValue::Bool(value) => Value::Bool(Some(value)),
            FieldValue::String(value) if T::array_type() == ArrayType::Uuid => {
                Value::Uuid(Some(value.parse().map_err(|error| {
                    AuthError::bad_request(format!("Invalid SQL UUID: {error}"))
                })?))
            }
            FieldValue::String(value) => Value::String(Some(value)),
            FieldValue::Utf16String(value) => {
                Value::String(Some(value.to_utf8().map_err(|error| {
                    AuthError::internal(format!("A typed SQL string requires valid UTF-8: {error}"))
                })?))
            }
            value @ FieldValue::Number(_) => match T::array_type() {
                ArrayType::TinyInt => Value::TinyInt(Some(value.decode()?)),
                ArrayType::SmallInt => Value::SmallInt(Some(value.decode()?)),
                ArrayType::Int => Value::Int(Some(value.decode()?)),
                ArrayType::BigInt => Value::BigInt(Some(value.decode()?)),
                ArrayType::TinyUnsigned => Value::TinyUnsigned(Some(value.decode()?)),
                ArrayType::SmallUnsigned => Value::SmallUnsigned(Some(value.decode()?)),
                ArrayType::Unsigned => Value::Unsigned(Some(value.decode()?)),
                ArrayType::BigUnsigned => Value::BigUnsigned(Some(value.decode()?)),
                ArrayType::Float => Value::Float(Some(value.decode::<f64>()? as f32)),
                _ => Value::Double(Some(value.decode()?)),
            },
            FieldValue::Date(value) => {
                let date = value.to_datetime()?.ok_or_else(|| {
                    AuthError::internal("An invalid Date cannot be decoded into a typed SQL model")
                })?;
                match T::array_type() {
                    ArrayType::ChronoDateTime => Value::ChronoDateTime(Some(date.naive_utc())),
                    ArrayType::ChronoDateTimeLocal => {
                        Value::ChronoDateTimeLocal(Some(date.with_timezone(&chrono::Local)))
                    }
                    ArrayType::ChronoDateTimeWithTimeZone => {
                        Value::ChronoDateTimeWithTimeZone(Some(date.fixed_offset()))
                    }
                    _ => Value::ChronoDateTimeUtc(Some(date)),
                }
            }
            _ => {
                return Err(AuthError::internal(format!(
                    "Adapter field cannot be decoded as SQL {}",
                    T::type_name()
                )));
            }
        }
    };
    T::try_from(value).map_err(|error| {
        AuthError::internal(format!("Cannot decode SQL {}: {error}", T::type_name()))
    })
}
