//! JavaScript-number storage over SQL numeric column types.

use sea_orm::sea_query::{ArrayType, ColumnType, Nullable, Value, ValueType, ValueTypeErr};
use sea_orm::sqlx::{MySql, Row, Type, TypeInfo, ValueRef};
use sea_orm::{ColIdx, DbErr, QueryResult, TryGetError, TryGetable};

/// A floating-point application value stored in a SQL numeric column.
///
/// SQLite can store both INTEGER and REAL values in INTEGER and BIGINT columns.
/// Read both representations without changing the stored value or losing fractions.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct SqlNumber(pub f64);

impl From<f64> for SqlNumber {
    fn from(value: f64) -> Self {
        Self(value)
    }
}

impl From<SqlNumber> for f64 {
    fn from(value: SqlNumber) -> Self {
        value.0
    }
}

impl From<SqlNumber> for Value {
    fn from(value: SqlNumber) -> Self {
        Self::Double(Some(value.0))
    }
}

impl Nullable for SqlNumber {
    fn null() -> Value {
        Value::Double(None)
    }
}

impl ValueType for SqlNumber {
    fn try_from(value: Value) -> Result<Self, ValueTypeErr> {
        <f64 as ValueType>::try_from(value).map(Self)
    }
    fn type_name() -> String {
        "SqlNumber".into()
    }
    fn array_type() -> ArrayType {
        ArrayType::Double
    }
    fn column_type() -> ColumnType {
        ColumnType::Double
    }
}

fn query_error(error: sea_orm::sqlx::Error) -> TryGetError {
    DbErr::Query(sea_orm::RuntimeErr::SqlxError(std::sync::Arc::new(error))).into()
}

impl TryGetable for SqlNumber {
    fn try_get_by<I: ColIdx>(result: &QueryResult, index: I) -> Result<Self, TryGetError> {
        let integer = if let Some(row) = result.try_as_sqlite_row() {
            let raw = row
                .try_get_raw(index.as_sqlx_sqlite_index())
                .map_err(query_error)?;
            if raw.is_null() {
                return Err(TryGetError::Null(format!("{index:?}")));
            }
            if raw.type_info().name() == "INTEGER" {
                Some(
                    row.try_get::<i64, _>(index.as_sqlx_sqlite_index())
                        .map_err(query_error)?,
                )
            } else {
                None
            }
        } else if let Some(row) = result.try_as_pg_row() {
            let raw = row
                .try_get_raw(index.as_sqlx_postgres_index())
                .map_err(query_error)?;
            if raw.is_null() {
                return Err(TryGetError::Null(format!("{index:?}")));
            }
            match raw.type_info().name() {
                "INT2" => Some(i64::from(
                    row.try_get::<i16, _>(index.as_sqlx_postgres_index())
                        .map_err(query_error)?,
                )),
                "INT4" => Some(i64::from(
                    row.try_get::<i32, _>(index.as_sqlx_postgres_index())
                        .map_err(query_error)?,
                )),
                "INT8" => Some(
                    row.try_get::<i64, _>(index.as_sqlx_postgres_index())
                        .map_err(query_error)?,
                ),
                _ => None,
            }
        } else if let Some(row) = result.try_as_mysql_row() {
            let raw = row
                .try_get_raw(index.as_sqlx_mysql_index())
                .map_err(query_error)?;
            if raw.is_null() {
                return Err(TryGetError::Null(format!("{index:?}")));
            }
            if <i64 as Type<MySql>>::compatible(&raw.type_info()) {
                Some(
                    row.try_get::<i64, _>(index.as_sqlx_mysql_index())
                        .map_err(query_error)?,
                )
            } else {
                None
            }
        } else {
            None
        };
        if let Some(integer) = integer {
            return serde_json::Number::from(integer)
                .as_f64()
                .map(Self)
                .ok_or_else(|| {
                    DbErr::Type("SQL integer exceeds the JavaScript number range".into()).into()
                });
        }
        f64::try_get_by(result, index).map(Self)
    }
}
