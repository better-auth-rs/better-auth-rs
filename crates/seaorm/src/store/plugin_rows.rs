//! Read driver values before plugin output policies or typed model conversion.

use better_auth_core::{
    AuthError, AuthResult, FieldMap, FieldObject, FieldValue,
    user_fields::{AdapterRecord, UserConfig},
};
use sea_orm::sqlx::{Row, TypeInfo, ValueRef};
use sea_orm::{
    ConnectionTrait, DbBackend, EntityTrait, IdenStatic, QueryResult, QuerySelect, Select,
    sea_query::{Alias, Asterisk, Expr, ExprTrait},
};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use super::query_compile::Compile;
use crate::SeaOrmPluginModel;

mod drivers;
#[cfg(test)]
mod legacy_private_tests;
#[cfg(test)]
mod native_snapshot_tests;

#[derive(Debug, Clone)]
pub(super) struct SqlRow {
    row: Arc<QueryResult>,
    prefix: Arc<str>,
    omitted: Arc<HashSet<String>>,
    native_object: Arc<Mutex<Option<FieldObject>>>,
}

impl From<QueryResult> for SqlRow {
    fn from(row: QueryResult) -> Self {
        Self {
            row: Arc::new(row),
            prefix: Arc::from(""),
            omitted: Default::default(),
            native_object: Default::default(),
        }
    }
}

impl SqlRow {
    pub(super) fn prefixed(&self, prefix: &str) -> Self {
        Self {
            row: self.row.clone(),
            prefix: Arc::from(prefix),
            omitted: Default::default(),
            native_object: Default::default(),
        }
    }

    pub(super) fn value(&self, column: &str) -> AuthResult<FieldValue> {
        if self.omitted.contains(column) {
            return Ok(FieldValue::Undefined);
        }
        value(&self.row, &format!("{}{column}", self.prefix))
    }

    pub(super) fn is_nullish(&self, column: &str) -> AuthResult<bool> {
        if self.omitted.contains(column) {
            return Ok(true);
        }
        let column = format!("{}{column}", self.prefix);
        if let Some(row) = self.row.try_as_sqlite_row() {
            return row
                .try_get_raw(column.as_str())
                .map(|raw| raw.is_null())
                .map_err(|cause| error(&column, cause));
        }
        if let Some(row) = self.row.try_as_pg_row() {
            return row
                .try_get_raw(column.as_str())
                .map(|raw| raw.is_null())
                .map_err(|cause| error(&column, cause));
        }
        if let Some(row) = self.row.try_as_mysql_row() {
            let raw = row
                .try_get_raw(column.as_str())
                .map_err(|cause| error(&column, cause))?;
            // SQLx's is_null also classifies zero dates as null; raw bytes distinguish SQL NULL.
            return drivers::mysql_bytes(raw, &column).map(|bytes| bytes.is_none());
        }
        Err(error(
            &column,
            "the query result has no supported SQL driver",
        ))
    }

    pub(super) fn without_columns(&self, columns: impl IntoIterator<Item = String>) -> Self {
        Self {
            omitted: Arc::new(columns.into_iter().collect()),
            ..self.clone()
        }
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

    pub(super) fn native_object<C: IdenStatic>(
        &self,
        fields: &UserConfig,
        column: impl Fn(&str) -> AuthResult<C>,
    ) -> AuthResult<FieldObject> {
        let mut object = self.native_object.lock().map_err(|_| {
            AuthError::internal("Native SQL relationship snapshot lock is poisoned")
        })?;
        if let Some(object) = &*object {
            return Ok(object.clone());
        }
        let fields = super::joins::native_child_fields(&fields.adapter_fields(&[]), |name, _| {
            self.value(column(name)?.as_str())
        })?;
        let fields = FieldObject::from(fields);
        *object = Some(fields.clone());
        Ok(fields)
    }

    pub(super) fn native_record<C: IdenStatic>(
        &self,
        fields: &UserConfig,
        backend: DbBackend,
        column: impl Fn(&str) -> AuthResult<C>,
    ) -> AuthResult<AdapterRecord> {
        Ok(AdapterRecord::from_storage_object(
            self.native_object(fields, column)?,
            super::field_output::capabilities(backend),
        ))
    }
}

/// Read physical columns before applying the effective declarations to the SQL snapshot.
pub(super) fn select_all<E: EntityTrait>() -> Select<E> {
    E::find().select_only().expr(Expr::col(Asterisk))
}

pub(super) async fn all<E: EntityTrait>(
    db: &impl ConnectionTrait,
    query: Select<E>,
) -> AuthResult<Vec<SqlRow>> {
    db.query_all_raw(query.compile_find(db.get_database_backend())?)
        .await
        .map(|rows| rows.into_iter().map(Into::into).collect())
        .map_err(super::map_db_err)
}

pub(super) async fn one<E: EntityTrait>(
    db: &impl ConnectionTrait,
    query: Select<E>,
) -> AuthResult<Option<SqlRow>> {
    let backend = db.get_database_backend();
    let query = if backend == DbBackend::MySql {
        query
    } else {
        query.limit(1)
    };
    db.query_one_raw(query.compile_find(backend)?)
        .await
        .map(|row| row.map(Into::into))
        .map_err(super::map_db_err)
}

pub(super) async fn count<E: EntityTrait>(
    db: &impl ConnectionTrait,
    query: Select<E>,
) -> AuthResult<u64> {
    // Kysely counts the literal id column, independently of declaration aliases and primary keys.
    let query = query
        .select_only()
        .expr_as(Expr::col(Alias::new("id")).count(), "count");
    let backend = db.get_database_backend();
    let query = if backend == DbBackend::MySql {
        query
    } else {
        query.limit(1)
    };
    let row = db
        .query_one_raw(query.compile(backend)?)
        .await
        .map_err(super::map_db_err)?
        .map(SqlRow::from)
        .ok_or_else(|| AuthError::internal("Adapter count returned no row"))?;
    Ok(better_auth_core::query::field_number(&row.value("count")?)? as u64)
}

pub(super) fn ordered_output(fields: &UserConfig, output: FieldMap) -> FieldMap {
    output.in_field_order(&fields.fields().keys().cloned().collect::<Vec<_>>())
}

pub(super) async fn project_records<T>(
    fields: &UserConfig,
    records: Vec<AdapterRecord>,
    backend: DbBackend,
    decode: impl Fn(FieldMap) -> AuthResult<T>,
) -> AuthResult<Vec<T>> {
    fields
        .project_adapter_records_with_capabilities(
            records,
            super::field_output::capabilities(backend),
        )
        .await?
        .into_iter()
        .map(|output| decode(ordered_output(fields, output)))
        .collect()
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

pub(super) fn private_column<M: SeaOrmPluginModel>(
    fields: &UserConfig,
    name: &str,
) -> AuthResult<Option<M::Column>> {
    super::record_write::private_column(fields, name, || M::column(name).map(Some), M::column)
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
        if matches!(
            raw.type_info().kind(),
            sea_orm::sqlx::postgres::PgTypeKind::Enum(_)
        ) {
            // PostgreSQL sends enum labels in both protocols; SQLx excludes enums from String's type check.
            return raw
                .as_str()
                .map(FieldValue::from)
                .map_err(|cause| error(column, cause));
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
