//! Keep transformed fields intact until SQL parameter encoding.

use better_auth_core::{AuthResult, FieldValue};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, Iden, Iterable,
    QueryFilter, QueryResult,
    sea_query::{Query, Value},
};

use super::{create_readback::CreateReadback, map_db_err, record_bindings::Binding};

pub(super) struct RecordWrite<E: EntityTrait> {
    fields: Vec<(E::Column, Binding)>,
}

pub(super) struct RecordUpdate<E: EntityTrait> {
    pub(super) query: sea_orm::UpdateMany<E>,
    null_columns: Vec<E::Column>,
}

impl<E: EntityTrait> RecordUpdate<E> {
    pub(super) fn filter(mut self, filter: sea_orm::sea_query::SimpleExpr) -> Self {
        self.query = self.query.filter(filter);
        self
    }

    pub(super) fn source_is_null(&self, column: E::Column) -> bool {
        self.null_columns
            .iter()
            .any(|stored| stored.to_string() == column.to_string())
    }
}

impl<E: EntityTrait> Default for RecordWrite<E> {
    fn default() -> Self {
        Self { fields: Vec::new() }
    }
}

impl<E: EntityTrait> RecordWrite<E> {
    pub(super) fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub(super) fn from_active(active: impl ActiveModelTrait<Entity = E>) -> Self {
        let mut write = Self::default();
        for column in E::Column::iter() {
            if let sea_orm::ActiveValue::Set(value) = active.get(column) {
                write.set(column, value);
            }
        }
        write
    }

    pub(super) fn from_fields(
        fields: better_auth_core::FieldMap,
        column: impl Fn(&str) -> AuthResult<E::Column>,
    ) -> AuthResult<Self> {
        let mut write = Self::default();
        write.apply_fields(fields, column)?;
        Ok(write)
    }

    pub(super) fn from_initialized_fields<M: ActiveModelTrait<Entity = E>>(
        fields: better_auth_core::FieldMap,
        column: impl Fn(&str) -> AuthResult<E::Column>,
        extra_columns: Vec<E::Column>,
        initialize: impl FnOnce(&better_auth_core::FieldMap) -> AuthResult<M>,
    ) -> AuthResult<Self> {
        let initial = if extra_columns.is_empty() {
            None
        } else {
            Some(initialize(&fields)?)
        };
        let mut write = Self::from_fields(fields, column)?;
        if let Some(initial) = initial {
            for column in extra_columns {
                // Prepared fields retain their value and position when an initializer also sets the column.
                if !write
                    .fields
                    .iter()
                    .any(|(stored, _)| stored.to_string() == column.to_string())
                    && let sea_orm::ActiveValue::Set(value) = initial.get(column)
                {
                    write.set(column, value);
                }
            }
        }
        Ok(write)
    }

    pub(super) fn apply_fields(
        &mut self,
        fields: better_auth_core::FieldMap,
        column: impl Fn(&str) -> AuthResult<E::Column>,
    ) -> AuthResult<()> {
        for (name, value) in fields {
            self.field(column(&name)?, value);
        }
        Ok(())
    }

    pub(super) fn not_set(&mut self, column: E::Column) {
        self.fields
            .retain(|(stored, _)| stored.to_string() != column.to_string());
    }

    fn assign(&mut self, column: E::Column, value: Binding) {
        if let Some((_, stored)) = self
            .fields
            .iter_mut()
            .find(|(stored, _)| stored.to_string() == column.to_string())
        {
            *stored = value;
        } else {
            self.fields.push((column, value));
        }
    }

    pub(super) fn field(&mut self, column: E::Column, value: FieldValue) {
        if !value.is_undefined() {
            self.assign(column, Binding::for_column(column, value));
        }
    }

    pub(super) fn native_field(&mut self, column: E::Column, value: FieldValue) {
        if let FieldValue::Date(date) = value {
            self.assign(column, Binding::Date(date));
        } else {
            self.field(column, value);
        }
    }

    pub(super) fn set(&mut self, column: E::Column, value: Value) {
        let binding = match value {
            Value::ChronoDateTimeUtc(Some(value)) => Binding::Date(value.into()),
            Value::ChronoDateTime(Some(value)) => Binding::Date(value.and_utc().into()),
            Value::ChronoDateTimeLocal(Some(value)) => Binding::Date(value.to_utc().into()),
            Value::ChronoDateTimeWithTimeZone(Some(value)) => Binding::Date(value.to_utc().into()),
            value => Binding::Native(value),
        };
        self.assign(column, binding);
    }

    pub(super) fn apply_to(
        self,
        mut query: sea_orm::UpdateMany<E>,
        backend: sea_orm::DbBackend,
    ) -> AuthResult<sea_orm::UpdateMany<E>> {
        let (columns, bindings): (Vec<_>, Vec<_>) = self.fields.into_iter().unzip();
        let values = super::record_bindings::bind(backend, bindings)?;
        for (column, value) in columns.into_iter().zip(values) {
            query = query.col_expr(column, column.save_as(value));
        }
        Ok(query)
    }

    pub(super) fn update(self, backend: sea_orm::DbBackend) -> AuthResult<sea_orm::UpdateMany<E>> {
        self.apply_to(E::update_many(), backend)
    }

    pub(super) fn update_returning(
        self,
        backend: sea_orm::DbBackend,
    ) -> AuthResult<RecordUpdate<E>> {
        let null_columns = self
            .fields
            .iter()
            .filter_map(|(column, value)| value.is_null().then_some(*column))
            .collect();
        Ok(RecordUpdate {
            query: self.update(backend)?,
            null_columns,
        })
    }

    pub(super) async fn insert(
        self,
        db: &impl ConnectionTrait,
        readback: CreateReadback<'_, E>,
    ) -> AuthResult<Option<E::Model>> {
        self.insert_raw(db, readback)
            .await?
            .map(|row| E::Model::from_query_result(&row, "").map_err(map_db_err))
            .transpose()
    }

    pub(super) async fn insert_raw(
        self,
        db: &impl ConnectionTrait,
        readback: CreateReadback<'_, E>,
    ) -> AuthResult<Option<QueryResult>> {
        let backend = db.get_database_backend();
        let (columns, bindings): (Vec<_>, Vec<_>) = self.fields.iter().cloned().unzip();
        let values = super::record_bindings::bind(backend, bindings)?;
        let values = columns
            .iter()
            .zip(values)
            .map(|(column, value)| column.save_as(value));
        let mut query = Query::insert();
        let _ = query
            .into_table(E::default())
            .columns(columns.iter().copied())
            .values_panic(values);
        if db.support_returning() {
            let _ = query.returning(
                Query::returning().exprs(
                    E::Column::iter()
                        .map(|column| column.select_as(column.into_returning_expr(backend))),
                ),
            );
            return db
                .query_one_raw(backend.build(&query))
                .await
                .map_err(map_db_err);
        }
        let _ = db
            .execute_raw(backend.build(&query))
            .await
            .map_err(map_db_err)?;
        readback.fetch(db, &self.fields).await
    }
}
