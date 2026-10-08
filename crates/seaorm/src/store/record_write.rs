//! Keep transformed fields intact until SQL parameter encoding.

use better_auth_core::{AuthError, AuthResult, FieldValue};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, Iden, Iterable,
    PrimaryKeyToColumn, QueryFilter, QueryResult, QueryTrait,
    sea_query::{ExprTrait, Query, Value},
};

use super::{map_db_err, record_bindings::Binding};

pub(super) struct RecordWrite<E: EntityTrait> {
    fields: Vec<(E::Column, Binding)>,
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

    pub(super) fn expression(
        &self,
        column: E::Column,
        backend: sea_orm::DbBackend,
    ) -> AuthResult<Option<sea_orm::sea_query::SimpleExpr>> {
        self.fields
            .iter()
            .find(|(stored, _)| stored.to_string() == column.to_string())
            .map(|(_, value)| value.clone().bind(backend))
            .transpose()
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
        for (column, value) in self.fields {
            query = query.col_expr(column, column.save_as(value.bind(backend)?));
        }
        Ok(query)
    }

    pub(super) fn update(self, backend: sea_orm::DbBackend) -> AuthResult<sea_orm::UpdateMany<E>> {
        self.apply_to(E::update_many(), backend)
    }

    pub(super) async fn insert(self, db: &impl ConnectionTrait) -> AuthResult<E::Model> {
        let row = self.insert_raw(db).await?;
        E::Model::from_query_result(&row, "").map_err(map_db_err)
    }

    pub(super) async fn insert_raw(self, db: &impl ConnectionTrait) -> AuthResult<QueryResult> {
        let backend = db.get_database_backend();
        let primary = E::PrimaryKey::iter()
            .next()
            .ok_or_else(|| AuthError::config("An auth model requires a primary key"))?
            .into_column();
        let (columns, bindings): (Vec<_>, Vec<_>) = self.fields.into_iter().unzip();
        let values = super::record_bindings::bind(backend, bindings)?;
        let id = columns
            .iter()
            .zip(&values)
            .find(|(column, _)| column.to_string() == primary.to_string())
            .map(|(_, value)| value.clone());
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
                .map_err(map_db_err)?
                .ok_or_else(|| AuthError::internal("SQL insert returned no record"));
        }
        let result = db
            .execute_raw(backend.build(&query))
            .await
            .map_err(map_db_err)?;
        let select = E::find().filter(
            primary
                .into_expr()
                .eq(primary.save_as(id.unwrap_or_else(|| result.last_insert_id().into()))),
        );
        db.query_one_raw(select.build(backend))
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| AuthError::internal("SQL insert returned no record"))
    }
}
