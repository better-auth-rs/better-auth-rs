//! Preserve runtime values until the selected SQL driver encodes each parameter.

use better_auth_core::{AuthError, AuthResult, FieldDate, FieldValue};
use chrono::Datelike;
use sea_orm::{
    ColumnTrait, DbBackend,
    sea_query::{SimpleExpr, Value},
};

#[derive(Clone)]
pub(super) enum Binding {
    Native(Value),
    Raw(FieldValue),
    Date(FieldDate),
    Json(FieldValue),
}

impl Binding {
    pub(super) fn for_column(column: impl ColumnTrait, value: FieldValue) -> Self {
        if matches!(
            column.def().get_column_type(),
            sea_orm::ColumnType::Json | sea_orm::ColumnType::JsonBinary
        ) && !matches!(
            value,
            FieldValue::Undefined
                | FieldValue::Null
                | FieldValue::String(_)
                | FieldValue::Utf16String(_)
        ) {
            Self::Json(value)
        } else {
            // Preserve SQL NULL and JSON text that the declared field policy has already encoded.
            Self::Raw(value)
        }
    }

    pub(super) fn bind(self, backend: DbBackend) -> AuthResult<SimpleExpr> {
        match self {
            Self::Native(value) => Ok(SimpleExpr::Value(value)),
            Self::Json(value) => Ok(SimpleExpr::Value(Value::Json(value.json()?.map(Box::new)))),
            Self::Raw(value) => parameter(value, backend),
            Self::Date(date) => {
                let value = if backend == DbBackend::Sqlite {
                    sqlite_date(date)?
                } else {
                    FieldValue::Date(date)
                };
                parameter(value, backend)
            }
        }
    }
}

pub(super) fn bind(backend: DbBackend, values: Vec<Binding>) -> AuthResult<Vec<SimpleExpr>> {
    values
        .into_iter()
        .map(|value| value.bind(backend))
        .collect()
}

pub(super) fn parameter(value: FieldValue, backend: DbBackend) -> AuthResult<SimpleExpr> {
    if backend == DbBackend::Postgres {
        // pg sends OID-unspecified text parameters. A quoted unknown literal preserves column inference.
        return Ok(SimpleExpr::Constant(Value::String(postgres_parameter(
            &value,
        )?)));
    }
    let value = match value {
        FieldValue::Undefined | FieldValue::Null => Value::String(None),
        FieldValue::Bool(value) if backend == DbBackend::Sqlite => {
            Value::BigInt(Some(i64::from(value)))
        }
        FieldValue::Bool(value) => Value::Bool(Some(value)),
        FieldValue::String(value) => Value::String(Some(value)),
        FieldValue::Utf16String(value) => Value::String(Some(utf16_string(&value, backend))),
        FieldValue::Array(values) if backend == DbBackend::MySql => {
            let parameters = values
                .iter()
                .cloned()
                .map(|value| {
                    if let FieldValue::Array(nested) = value {
                        nested
                            .iter()
                            .cloned()
                            .map(|value| parameter(value, backend))
                            .collect::<AuthResult<Vec<_>>>()
                            .map(SimpleExpr::Tuple)
                    } else {
                        parameter(value, backend)
                    }
                })
                .collect::<AuthResult<Vec<_>>>()?;
            return Ok(SimpleExpr::cust_with_exprs(
                vec!["?"; parameters.len()].join(", "),
                parameters,
            ));
        }
        FieldValue::Number(value) if backend == DbBackend::MySql && !value.is_finite() => {
            // mysql2 query interpolation emits JavaScript numeric tokens, including non-finite numbers.
            let token = if value.is_nan() {
                "NaN"
            } else if value.is_sign_positive() {
                "Infinity"
            } else {
                "-Infinity"
            };
            return Ok(SimpleExpr::Custom(token.into()));
        }
        FieldValue::Number(value) => {
            crate::reference_id::binding(Value::Double(Some(value)), backend)?
        }
        FieldValue::Date(date) if backend == DbBackend::MySql => {
            // sql-escaper converts an invalid Date to SQL NULL without changing the comparison operator.
            Value::String(date.to_datetime()?.map(|date| {
                date.with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M:%S%.3f")
                    .to_string()
            }))
        }
        FieldValue::Date(_) | FieldValue::Array(_) | FieldValue::Object(_)
            if backend == DbBackend::Sqlite =>
        {
            return Err(AuthError::internal(
                "Binding expected string, TypedArray, boolean, number, bigint or null",
            ));
        }
        value => Value::String(Some(utf16_string(&value.display_utf16()?, backend))),
    };
    Ok(SimpleExpr::Value(value))
}

fn postgres_parameter(value: &FieldValue) -> AuthResult<Option<String>> {
    Ok(match value {
        FieldValue::Undefined | FieldValue::Null => None,
        FieldValue::String(value) => Some(value.clone()),
        FieldValue::Utf16String(value) => Some(utf16_string(value, DbBackend::Postgres)),
        FieldValue::Date(date) => Some(postgres_date(date)?),
        FieldValue::Array(values) => {
            let mut text = String::from("{");
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    text.push(',');
                }
                if matches!(value, FieldValue::Array(_)) {
                    text.push_str(&postgres_parameter(value)?.ok_or_else(|| {
                        AuthError::internal("PostgreSQL array encoding lost a nested array")
                    })?);
                } else if let Some(value) = postgres_parameter(value)? {
                    text.push('"');
                    text.push_str(&value.replace('\\', "\\\\").replace('"', "\\\""));
                    text.push('"');
                } else {
                    text.push_str("NULL");
                }
            }
            text.push('}');
            Some(text)
        }
        FieldValue::Object(_) => value.stringify()?,
        value => Some(utf16_string(&value.display_utf16()?, DbBackend::Postgres)),
    })
}

fn postgres_date(date: &FieldDate) -> AuthResult<String> {
    let Some(date) = date.to_datetime()? else {
        // pg 8 dateToString pads the invalid Date getters, then lets PostgreSQL reject the parameter.
        let nan = better_auth_core::schema_value::number_string(date.milliseconds());
        return Ok(format!(
            "{nan:0>4}-{nan:0>2}-{nan:0>2}T{nan:0>2}:{nan:0>2}:{nan:0>2}.{nan:0>3}+{nan:0>2}:{nan:0>2}"
        ));
    };
    let local = date.with_timezone(&chrono::Local);
    let year = local.year();
    let year = if year < 1 { 1 - year } else { year };
    Ok(format!(
        "{year:04}{}{}",
        local.format("-%m-%dT%H:%M:%S%.3f%:z"),
        if local.year() < 1 { " BC" } else { "" }
    ))
}

pub(super) fn utf16_string(value: &better_auth_core::Utf16String, backend: DbBackend) -> String {
    match backend {
        DbBackend::Sqlite => String::from_utf8_lossy(&value.to_wtf8()).into_owned(),
        _ => String::from_utf16_lossy(value.as_utf16()),
    }
}

pub(crate) fn sqlite_date(date: FieldDate) -> AuthResult<FieldValue> {
    let value = date
        .to_datetime()?
        .ok_or_else(|| AuthError::internal("Invalid Date"))?;
    Ok(FieldValue::String(
        value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    ))
}
