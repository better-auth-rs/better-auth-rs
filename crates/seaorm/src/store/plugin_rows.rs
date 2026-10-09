//! Read driver values before plugin output policies or typed model conversion.

use better_auth_core::{
    AuthError, AuthResult, FieldMap, FieldValue,
    user_fields::{AdapterRecord, UserConfig},
};
use sea_orm::sqlx::{Row, TypeInfo, ValueRef};
use sea_orm::{
    ConnectionTrait, DbBackend, EntityTrait, FromQueryResult, IdenStatic, Iterable, QueryResult,
    QuerySelect, QueryTrait, Select,
};
use std::sync::Arc;

use crate::SeaOrmPluginModel;

mod drivers;

#[derive(Debug, Clone)]
pub(super) struct SqlRow {
    row: Arc<QueryResult>,
    prefix: &'static str,
}

impl From<QueryResult> for SqlRow {
    fn from(row: QueryResult) -> Self {
        Self {
            row: Arc::new(row),
            prefix: "",
        }
    }
}

impl SqlRow {
    pub(super) fn prefixed(&self, prefix: &'static str) -> Self {
        Self {
            row: self.row.clone(),
            prefix,
        }
    }

    pub(super) fn value(&self, column: &str) -> AuthResult<FieldValue> {
        value(&self.row, &format!("{}{column}", self.prefix))
    }

    pub(super) fn model<M: FromQueryResult>(&self) -> AuthResult<M> {
        M::from_query_result(&self.row, self.prefix).map_err(super::map_db_err)
    }

    pub(super) fn record<E: EntityTrait>(
        &self,
        fields: &UserConfig,
        backend: DbBackend,
        primary: E::Column,
        column: impl Fn(&str) -> AuthResult<E::Column>,
    ) -> AuthResult<AdapterRecord> {
        record_from_reader::<E>(fields, backend, primary, column, |column| {
            self.value(column)
        })
    }

    pub(super) fn native_record<E: EntityTrait>(
        &self,
        fields: &UserConfig,
        backend: DbBackend,
        primary: E::Column,
        column: impl Fn(&str) -> AuthResult<E::Column>,
    ) -> AuthResult<AdapterRecord> {
        let storage = super::joins::native_child_fields(fields, |name, _| {
            self.value(column(name)?.as_str())
        })?;
        let mut record = self.record::<E>(fields, backend, primary, column)?;
        record.map_storage_fields(
            fields,
            super::field_output::capabilities(backend),
            |name, _| Ok(Some(storage.get(name).cloned().unwrap_or_default())),
        )?;
        Ok(record)
    }
}

pub(super) async fn all<E: EntityTrait>(
    db: &impl ConnectionTrait,
    query: Select<E>,
) -> AuthResult<Vec<SqlRow>> {
    db.query_all(&query.into_query())
        .await
        .map(|rows| rows.into_iter().map(Into::into).collect())
        .map_err(super::map_db_err)
}

pub(super) async fn one<E: EntityTrait>(
    db: &impl ConnectionTrait,
    query: Select<E>,
) -> AuthResult<Option<SqlRow>> {
    db.query_one(&query.limit(1).into_query())
        .await
        .map(|row| row.map(Into::into))
        .map_err(super::map_db_err)
}

pub(super) fn ordered_output(fields: &UserConfig, output: FieldMap) -> FieldMap {
    output.in_field_order(&fields.fields().keys().cloned().collect::<Vec<_>>())
}

pub(super) fn record<M: SeaOrmPluginModel>(
    row: &QueryResult,
    fields: &UserConfig,
    backend: DbBackend,
) -> AuthResult<AdapterRecord> {
    record_from_columns::<M::Entity>(row, fields, backend, M::column("id")?, M::column)
}

pub(super) fn record_from_columns<E: EntityTrait>(
    row: &QueryResult,
    fields: &UserConfig,
    backend: DbBackend,
    primary: E::Column,
    column: impl Fn(&str) -> AuthResult<E::Column>,
) -> AuthResult<AdapterRecord> {
    record_from_reader::<E>(fields, backend, primary, column, |column| {
        value(row, column)
    })
}

fn record_from_reader<E: EntityTrait>(
    fields: &UserConfig,
    backend: DbBackend,
    primary: E::Column,
    column: impl Fn(&str) -> AuthResult<E::Column>,
    read: impl Fn(&str) -> AuthResult<FieldValue>,
) -> AuthResult<AdapterRecord> {
    let mut core = FieldMap::new();
    let mut storage = FieldMap::new();
    let raw = read(primary.as_str())?;
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
        let _ = storage.insert(name.into(), read(column.as_str())?);
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
            // Bun replaces invalid UTF-8 when returning TEXT, after SQLite has retained the original bytes.
            "TEXT" => String::from_utf8_lossy(&read!(row, Vec<u8>))
                .into_owned()
                .into(),
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
            "NUMERIC" => drivers::postgres_numeric(raw, column)?,
            "TEXT" | "VARCHAR" | "BPCHAR" | "NAME" => read!(row, String).into(),
            "UUID" => read!(row, uuid::Uuid).to_string().into(),
            "JSON" | "JSONB" => FieldValue::from_json(read!(row, serde_json::Value))?,
            "TIMESTAMPTZ" => read!(row, chrono::DateTime<chrono::Utc>).into(),
            "TIMESTAMP" => local_date(read!(row, chrono::NaiveDateTime), column)?,
            "DATE" => drivers::postgres_date(raw, column)?,
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
        // SQLx classifies binary zero dates as NULL; mysql2 query parsing retains calendar overflow.
        if raw.type_info().name() == "DATE" {
            return drivers::mysql_date(raw, column);
        }
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
            "DECIMAL" => drivers::mysql_decimal(raw, column)?,
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
