//! Read driver values before plugin output policies or typed model conversion.

use better_auth_core::{
    AuthError, AuthResult, FieldMap, FieldValue,
    user_fields::{AdapterRecord, UserConfig},
};
use sea_orm::sqlx::{Row, TypeInfo, ValueRef};
use sea_orm::{DbBackend, IdenStatic, Iterable, QueryResult};

use crate::SeaOrmPluginModel;

pub(super) fn record<M: SeaOrmPluginModel>(
    row: &QueryResult,
    fields: &UserConfig,
    backend: DbBackend,
) -> AuthResult<AdapterRecord> {
    record_from_columns::<M::Entity>(row, fields, backend, M::column("id")?, M::column)
}

pub(super) fn record_from_columns<E: sea_orm::EntityTrait>(
    row: &QueryResult,
    fields: &UserConfig,
    backend: DbBackend,
    primary: E::Column,
    column: impl Fn(&str) -> AuthResult<E::Column>,
) -> AuthResult<AdapterRecord> {
    let mut core = FieldMap::new();
    let mut storage = FieldMap::new();
    let raw = value(row, primary.as_str())?;
    let id = if !raw.is_null() && !raw.is_undefined() {
        raw.display_utf16()?.into()
    } else {
        raw
    };
    let _ = core.insert("id".into(), id);
    for (name, field) in fields.fields() {
        if name == "id" {
            continue;
        }
        let name =
            better_auth_core::store::schema::resolve_field_name(field.field_name.as_deref(), name);
        let column = column(name)?;
        let _ = storage.insert(name.into(), value(row, column.as_str())?);
    }
    let mut record = AdapterRecord::new(core, storage);
    record.map_storage_fields(
        fields,
        super::field_output::capabilities(backend),
        |_, _| Ok(None),
    )?;
    Ok(record)
}

pub(super) fn undeclared_fields<M: SeaOrmPluginModel>(
    row: &QueryResult,
    fields: &UserConfig,
) -> AuthResult<FieldMap> {
    M::Column::iter()
        .filter_map(|column| {
            M::core_field_name(&column)
                .filter(|name| !fields.fields().contains_key(*name))
                .map(|name| value(row, column.as_str()).map(|value| (name.to_owned(), value)))
        })
        .collect()
}

fn error(column: &str, error: impl std::fmt::Display) -> AuthError {
    AuthError::internal(format!("Cannot read raw plugin column {column}: {error}"))
}

fn local_date(value: chrono::NaiveDateTime, column: &str) -> AuthResult<FieldValue> {
    value
        .and_local_timezone(chrono::Local)
        .single()
        .map(|value| value.with_timezone(&chrono::Utc).into())
        .ok_or_else(|| error(column, "database local timestamp is ambiguous or invalid"))
}

pub(super) fn value(row: &QueryResult, column: &str) -> AuthResult<FieldValue> {
    macro_rules! read {
        ($row:expr, $ty:ty) => {
            $row.try_get::<$ty, _>(column)
                .map_err(|cause| error(column, cause))?
        };
    }
    if let Some(row) = row.try_as_sqlite_row() {
        let raw = row
            .try_get_raw(column)
            .map_err(|cause| error(column, cause))?;
        if raw.is_null() {
            return Ok(FieldValue::Null);
        }
        return Ok(match raw.type_info().name() {
            "INTEGER" => FieldValue::Number(read!(row, i64) as f64),
            "REAL" => FieldValue::Number(read!(row, f64)),
            "TEXT" => FieldValue::String(read!(row, String)),
            kind => {
                return Err(error(
                    column,
                    format!("unsupported SQLite storage type {kind}"),
                ));
            }
        });
    }
    if let Some(row) = row.try_as_pg_row() {
        let raw = row
            .try_get_raw(column)
            .map_err(|cause| error(column, cause))?;
        if raw.is_null() {
            return Ok(FieldValue::Null);
        }
        return Ok(match raw.type_info().name() {
            "BOOL" => read!(row, bool).into(),
            "INT2" => f64::from(read!(row, i16)).into(),
            "INT4" => f64::from(read!(row, i32)).into(),
            // node-postgres leaves 64-bit integer results as decimal strings.
            "INT8" => read!(row, i64).to_string().into(),
            "FLOAT4" => f64::from(read!(row, f32)).into(),
            "FLOAT8" => read!(row, f64).into(),
            "TEXT" | "VARCHAR" | "BPCHAR" | "NAME" => read!(row, String).into(),
            "UUID" => read!(row, uuid::Uuid).to_string().into(),
            "JSON" | "JSONB" => FieldValue::from_json(read!(row, serde_json::Value))?,
            "TIMESTAMPTZ" => read!(row, chrono::DateTime<chrono::Utc>).into(),
            "TIMESTAMP" => local_date(read!(row, chrono::NaiveDateTime), column)?,
            kind => {
                return Err(error(
                    column,
                    format!("unsupported PostgreSQL storage type {kind}"),
                ));
            }
        });
    }
    if let Some(row) = row.try_as_mysql_row() {
        let raw = row
            .try_get_raw(column)
            .map_err(|cause| error(column, cause))?;
        if raw.is_null() {
            return Ok(FieldValue::Null);
        }
        return Ok(match raw.type_info().name() {
            "BOOLEAN"
                if <u8 as sea_orm::sqlx::Type<sea_orm::sqlx::MySql>>::compatible(
                    &raw.type_info(),
                ) =>
            {
                f64::from(read!(row, u8)).into()
            }
            "BOOLEAN" | "TINYINT" => f64::from(read!(row, i8)).into(),
            "SMALLINT" => f64::from(read!(row, i16)).into(),
            "MEDIUMINT" | "INT" => f64::from(read!(row, i32)).into(),
            "BIGINT" => (read!(row, i64) as f64).into(),
            "TINYINT UNSIGNED" => f64::from(read!(row, u8)).into(),
            "SMALLINT UNSIGNED" | "YEAR" => f64::from(read!(row, u16)).into(),
            "MEDIUMINT UNSIGNED" | "INT UNSIGNED" => f64::from(read!(row, u32)).into(),
            "BIGINT UNSIGNED" => (read!(row, u64) as f64).into(),
            "FLOAT" => f64::from(read!(row, f32)).into(),
            "DOUBLE" => read!(row, f64).into(),
            "CHAR" | "VARCHAR" | "TINYTEXT" | "TEXT" | "MEDIUMTEXT" | "LONGTEXT" | "ENUM"
            | "SET" => read!(row, String).into(),
            "JSON" => FieldValue::from_json(read!(row, serde_json::Value))?,
            "TIMESTAMP" => read!(row, chrono::DateTime<chrono::Utc>).into(),
            "DATETIME" => local_date(read!(row, chrono::NaiveDateTime), column)?,
            kind => {
                return Err(error(
                    column,
                    format!("unsupported MySQL storage type {kind}"),
                ));
            }
        });
    }
    Err(error(
        column,
        "the query result has no supported SQL driver",
    ))
}
