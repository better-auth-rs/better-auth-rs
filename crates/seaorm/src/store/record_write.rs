//! Keep transformed fields intact until SQL parameter encoding.

use better_auth_core::{
    AuthResult, FieldMap, FieldValue,
    id::{AdapterIdInput, IdGeneration},
    plugin_runtime::{ModelFields, ModelKey},
    store::schema::EntityRole,
    user_fields::{UserConfig, UserFieldConfig},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, Iden, QueryFilter,
    QueryResult,
    sea_query::{Condition, Query, SimpleExpr, Value},
};

use super::{
    create_readback::CreateReadback,
    map_db_err,
    record_bindings::{Binding, ParsedBinding},
    value_filter::QueryPredicate,
};

#[cfg(test)]
#[path = "record_write_tests.rs"]
mod tests;

pub(super) async fn prepare_fields(
    schema: &UserConfig,
    input: FieldMap,
    create_model: Option<&str>,
    (runtime, role): (&ModelFields, EntityRole),
    policy: &IdGeneration,
    backend: DbBackend,
    bind: impl Fn(&str, &UserFieldConfig, FieldValue) -> AuthResult<FieldValue>,
) -> AuthResult<FieldMap> {
    let force_allow_id = create_model.is_some() && input.contains_key("id");
    prepare_fields_from_source(
        schema,
        input.into(),
        (create_model, force_allow_id),
        (runtime, role),
        policy,
        backend,
        bind,
    )
    .await
}

/// The caller resolves ID admission before source reads begin.
pub(super) async fn prepare_fields_from_source(
    schema: &UserConfig,
    input: FieldValue,
    (create_model, force_allow_id): (Option<&str>, bool),
    (runtime, model): (&ModelFields, impl Into<ModelKey>),
    policy: &IdGeneration,
    backend: DbBackend,
    bind: impl Fn(&str, &UserFieldConfig, FieldValue) -> AuthResult<FieldValue>,
) -> AuthResult<FieldMap> {
    let model = model.into();
    runtime
        .with_id_input(
            &model,
            AdapterIdInput {
                force_allow_id,
                supports_native_uuid: backend == DbBackend::Postgres,
            },
            schema.storage_fields_from_source_with_bound_id(
                create_model.is_some(),
                |name| input.model_property(name).map(Some),
                || {
                    let supplied = Some(input.model_property("id")?);
                    // Earlier callbacks can replace the runtime ID policy before this declaration slot.
                    let Some(current) = runtime.id_input_policy(&model)? else {
                        return Ok(supplied);
                    };
                    match create_model {
                        Some(model) => policy.adapter_create_id_input(model, supplied, current),
                        None => supplied
                            .map(|value| policy.adapter_id_input(value, current))
                            .transpose()
                            .map(Option::flatten),
                    }
                },
                bind,
            ),
        )
        .await
}

pub(super) fn private_column<C: ColumnTrait>(
    schema: &better_auth_core::user_fields::UserConfig,
    name: &str,
    candidate: impl FnOnce() -> AuthResult<Option<C>>,
    resolve: impl Fn(&str) -> AuthResult<C>,
) -> AuthResult<Option<C>> {
    if schema.fields().contains_key(name) {
        return Ok(None);
    }
    let Some(column) = candidate()? else {
        return Ok(None);
    };
    Ok((!schema.owns_adapter_column(&column.to_string(), |name| {
        resolve(name).map(|column| column.to_string())
    })?)
    .then_some(column))
}

pub(super) struct RecordWrite<E: EntityTrait> {
    fields: Vec<(E::Column, Binding)>,
}

pub(super) struct RecordUpdate<E: EntityTrait> {
    pub(super) query: sea_orm::UpdateMany<E>,
    null_columns: Vec<E::Column>,
}

pub(super) struct ParsedRecordWrite<E: EntityTrait> {
    fields: Vec<(E::Column, ParsedBinding)>,
    null_columns: Vec<E::Column>,
}

impl<E: EntityTrait> ParsedRecordWrite<E> {
    pub(super) fn encode(
        self,
        mut query: sea_orm::UpdateMany<E>,
        backend: sea_orm::DbBackend,
    ) -> AuthResult<RecordUpdate<E>> {
        let (columns, bindings): (Vec<_>, Vec<_>) = self.fields.into_iter().unzip();
        let values = bindings
            .into_iter()
            .map(|binding| {
                let expression = binding.is_expression();
                Ok((binding.encode(backend)?, expression))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        for (column, (value, expression)) in columns.into_iter().zip(values) {
            query = query.col_expr(
                column,
                if expression {
                    value
                } else {
                    column.save_as(value)
                },
            );
        }
        Ok(RecordUpdate {
            query,
            null_columns: self.null_columns,
        })
    }
}

impl<E: EntityTrait> RecordUpdate<E> {
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

    pub(super) fn from_fields(
        fields: better_auth_core::FieldMap,
        column: impl Fn(&str) -> AuthResult<E::Column>,
    ) -> AuthResult<Self> {
        let mut write = Self::default();
        write.apply_fields(fields, column)?;
        Ok(write)
    }

    pub(super) fn from_initialized_fields<M: ActiveModelTrait<Entity = E>>(
        schema: &better_auth_core::user_fields::UserConfig,
        fields: better_auth_core::FieldMap,
        column: impl Fn(&str) -> AuthResult<E::Column>,
        extra_columns: Vec<E::Column>,
        initialize: impl FnOnce(&better_auth_core::FieldMap) -> AuthResult<M>,
    ) -> AuthResult<Self> {
        let extra_columns = extra_columns
            .into_iter()
            .filter_map(|extra| {
                schema
                    .owns_adapter_column(&extra.to_string(), |name| {
                        column(name).map(|column| column.to_string())
                    })
                    .map(|owned| (!owned).then_some(extra))
                    .transpose()
            })
            .collect::<AuthResult<Vec<_>>>()?;
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

    pub(super) fn expression(&mut self, column: E::Column, expression: SimpleExpr) {
        self.assign(column, Binding::Expression(expression));
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

    pub(super) fn parse_update(self) -> AuthResult<ParsedRecordWrite<E>> {
        let null_columns = self
            .fields
            .iter()
            .filter_map(|(column, value)| value.is_null().then_some(*column))
            .collect();
        let fields = self
            .fields
            .into_iter()
            .map(|(column, binding)| Ok((column, binding.parse_expression()?)))
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(ParsedRecordWrite {
            fields,
            null_columns,
        })
    }

    fn compile_where(
        self,
        backend: sea_orm::DbBackend,
        predicates: impl IntoIterator<Item = QueryPredicate<E::Column>>,
    ) -> AuthResult<(RecordUpdate<E>, Option<SimpleExpr>)> {
        let write = self.parse_update()?;
        let predicates = predicates
            .into_iter()
            .map(QueryPredicate::parse)
            .collect::<AuthResult<Vec<_>>>()?;
        let mut update = write.encode(E::update_many(), backend)?;
        let selectors = predicates
            .into_iter()
            .map(|predicate| predicate.encode(backend))
            .collect::<AuthResult<Vec<_>>>()?;
        let reselect = selectors.first().cloned();
        let condition = selectors.into_iter().fold(Condition::all(), Condition::add);
        update.query = update.query.filter(condition);
        Ok((update, reselect))
    }

    /// Resolve every WHERE field before calling this method. SET and WHERE expressions parse before parameter encoding.
    pub(super) fn update_where(
        self,
        backend: sea_orm::DbBackend,
        predicates: impl IntoIterator<Item = QueryPredicate<E::Column>>,
    ) -> AuthResult<RecordUpdate<E>> {
        self.compile_where(backend, predicates)
            .map(|(update, _)| update)
    }

    /// Keep every WHERE condition and return the first encoded selector for MySQL readback without evaluating the selector again.
    pub(super) fn update_where_returning(
        self,
        backend: sea_orm::DbBackend,
        predicates: impl IntoIterator<Item = QueryPredicate<E::Column>>,
    ) -> AuthResult<(RecordUpdate<E>, SimpleExpr)> {
        let (update, selector) = self.compile_where(backend, predicates)?;
        let selector = selector.ok_or_else(|| {
            better_auth_core::AuthError::internal("Returning update requires a selector")
        })?;
        Ok((update, selector))
    }

    pub(super) async fn insert_raw(
        self,
        db: &impl ConnectionTrait,
        readback: CreateReadback<'_, E>,
    ) -> AuthResult<Option<QueryResult>> {
        let backend = db.get_database_backend();
        let (columns, bindings): (Vec<_>, Vec<_>) = self.fields.iter().cloned().unzip();
        let values = super::record_bindings::bind(backend, bindings)?;
        let values = self
            .fields
            .iter()
            .zip(values)
            .map(|((column, binding), value)| {
                if binding.is_expression() {
                    value
                } else {
                    column.save_as(value)
                }
            });
        let mut query = Query::insert();
        let _ = query
            .into_table(E::default())
            .columns(columns.iter().copied())
            .values_panic(values);
        if db.support_returning() {
            let _ = query.returning(Query::returning().all());
            return db
                .query_one_raw(crate::store::query_compile::build(backend, &query)?)
                .await
                .map_err(map_db_err);
        }
        let _ = db
            .execute_raw(crate::store::query_compile::build(backend, &query)?)
            .await
            .map_err(map_db_err)?;
        readback.fetch(db, &self.fields).await
    }
}
