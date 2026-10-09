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
    pub(super) fn is_null(&self) -> bool {
        match self {
            Self::Native(value) => *value == value.as_null(),
            Self::Raw(value) | Self::Json(value) => value.is_null(),
            // An invalid Date encodes as SQL NULL but remains a non-null source value.
            Self::Date(_) => false,
        }
    }

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
        self.parse_expression()?.encode(backend)
    }

    fn parse_expression(self) -> AuthResult<Self> {
        if let Self::Raw(value) | Self::Json(value) = &self {
            parse_expression(value)?;
        }
        Ok(self)
    }

    fn encode(self, backend: DbBackend) -> AuthResult<SimpleExpr> {
        match self {
            Self::Native(value) => Ok(SimpleExpr::Value(value)),
            Self::Json(value) if backend == DbBackend::Postgres => driver_parameter(value, backend),
            Self::Json(value) => Ok(SimpleExpr::Value(Value::Json(value.json()?.map(Box::new)))),
            Self::Raw(value) => driver_parameter(value, backend),
            Self::Date(date) => {
                let value = if backend == DbBackend::Sqlite {
                    sqlite_date(date)?
                } else {
                    FieldValue::Date(date)
                };
                driver_parameter(value, backend)
            }
        }
    }
}

pub(super) fn bind(backend: DbBackend, values: Vec<Binding>) -> AuthResult<Vec<SimpleExpr>> {
    // Kysely parses every expression before the driver encodes any parameter.
    values
        .into_iter()
        .map(Binding::parse_expression)
        .collect::<AuthResult<Vec<_>>>()?
        .into_iter()
        .map(|value| value.encode(backend))
        .collect()
}

pub(super) fn parameter(value: FieldValue, backend: DbBackend) -> AuthResult<SimpleExpr> {
    parse_expression(&value)?;
    driver_parameter(value, backend)
}

fn parse_expression(value: &FieldValue) -> AuthResult<()> {
    let FieldValue::Function(function) = value else {
        return Ok(());
    };
    // Ordinary factory results are values, not Kysely operation-node sources.
    let message = match function.call()? {
        FieldValue::Undefined => {
            "undefined is not an object (evaluating 'exp(expressionBuilder()).toOperationNode')"
        }
        FieldValue::Null => {
            "null is not an object (evaluating 'exp(expressionBuilder()).toOperationNode')"
        }
        _ => {
            "exp(expressionBuilder()).toOperationNode is not a function. (In 'exp(expressionBuilder()).toOperationNode()', 'exp(expressionBuilder()).toOperationNode' is undefined)"
        }
    };
    Err(AuthError::internal(message))
}

fn driver_parameter(value: FieldValue, backend: DbBackend) -> AuthResult<SimpleExpr> {
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
                            .map(|value| driver_parameter(value, backend))
                            .collect::<AuthResult<Vec<_>>>()
                            .map(SimpleExpr::Tuple)
                    } else {
                        driver_parameter(value, backend)
                    }
                })
                .collect::<AuthResult<Vec<_>>>()?;
            return Ok(SimpleExpr::cust_with_exprs(
                vec!["?"; parameters.len()].join(", "),
                parameters,
            ));
        }
        FieldValue::Number(value) if backend == DbBackend::MySql => {
            // mysql2 emits numeric literals; DOUBLE parameters change MySQL's integer rounding.
            return Ok(SimpleExpr::Custom(
                better_auth_core::schema_value::number_string(value).into(),
            ));
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

#[cfg(test)]
#[path = "record_function_tests.rs"]
mod function_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::sea_query::{MysqlQueryBuilder, Query};

    #[test]
    fn mysql_numbers_keep_literal_types_while_strings_remain_bound() -> AuthResult<()> {
        for (number, literal) in [
            (1.5, "1.5"),
            (2.5, "2.5"),
            (-2.5, "-2.5"),
            (-0.0, "0"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (f64::NAN, "NaN"),
            (f64::INFINITY, "Infinity"),
            (f64::NEG_INFINITY, "-Infinity"),
        ] {
            let (sql, parameters) = Query::select()
                .expr(parameter(number.into(), DbBackend::MySql)?)
                .build(MysqlQueryBuilder);
            assert_eq!(sql, format!("SELECT {literal}"));
            assert!(parameters.0.is_empty());
        }
        for text in ["2.5", "NaN", "2.5); DROP TABLE users; --"] {
            let (sql, parameters) = Query::select()
                .expr(parameter(text.into(), DbBackend::MySql)?)
                .build(MysqlQueryBuilder);
            assert_eq!(sql, "SELECT ?");
            assert_eq!(parameters.0, vec![Value::String(Some(text.into()))]);
        }
        Ok(())
    }
}
