//! Execute raw records with entity metadata and shared field policies.

use better_auth_core::{
    AuthConfig, AuthResult, FieldMap, FieldValue, FromFieldMap, plugin_runtime::ModelFields,
    store::schema::EntityRole, user_fields::UserConfig,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, QueryFilter, QueryResult, QuerySelect,
};

use super::{
    create_readback::{CreateReadback, ReadbackScope},
    instrumentation::database_operation,
    map_db_err,
    query_compile::{Compile, Execute},
    record_write::RecordWrite,
    value_filter::{BoundQueryField, QueryPredicate},
};

pub(super) struct SqlRecordModel<'a, E: EntityTrait> {
    config: &'a AuthConfig,
    runtime: &'a ModelFields,
    role: EntityRole,
    fields: UserConfig,
    backend: DbBackend,
    column: fn(&str) -> AuthResult<E::Column>,
}

impl<'a, E: EntityTrait> SqlRecordModel<'a, E> {
    pub(super) fn new(
        config: &'a AuthConfig,
        runtime: &'a ModelFields,
        role: EntityRole,
        fields: UserConfig,
        backend: DbBackend,
        column: fn(&str) -> AuthResult<E::Column>,
    ) -> Self {
        Self {
            config,
            runtime,
            role,
            fields,
            backend,
            column,
        }
    }

    pub(super) fn bind_query_field(
        &self,
        name: &str,
        value: &FieldValue,
    ) -> AuthResult<BoundQueryField> {
        super::value_filter::bind_factory_query_field(
            self.runtime,
            self.role,
            &self.fields,
            name,
            value,
            self.config.advanced.database.generate_id(),
            self.backend,
        )
    }

    pub(super) fn resolve_query_field(
        &self,
        bound: BoundQueryField,
    ) -> AuthResult<(E::Column, FieldValue)> {
        let (column, value) = bound.resolve(self.role, &self.fields)?;
        Ok(((self.column)(&column)?, value))
    }

    pub(super) async fn prepare(
        &self,
        input: FieldValue,
        create_model: Option<&str>,
        force_allow_id: bool,
    ) -> AuthResult<RecordWrite<E>> {
        let policy = self.config.advanced.database.generate_id();
        let stored = super::record_write::prepare_fields_from_source(
            &self.fields,
            input,
            (create_model, force_allow_id),
            (self.runtime, self.role),
            policy,
            self.backend,
            |name, field, value| {
                crate::reference_id::input_binding(
                    name,
                    field,
                    value,
                    policy,
                    self.column,
                    |name| {
                        (self.column)(name).is_ok_and(|column| {
                            matches!(
                                column.def().get_column_type(),
                                sea_orm::ColumnType::Json | sea_orm::ColumnType::JsonBinary
                            )
                        })
                    },
                    self.backend,
                )
            },
        )
        .await?;
        RecordWrite::from_fields(stored, self.column)
    }

    pub(super) async fn project<T: FromFieldMap>(
        &self,
        rows: &[QueryResult],
    ) -> AuthResult<Vec<T>> {
        let fields = &self.fields;
        let records = rows
            .iter()
            .map(|row| {
                super::plugin_rows::record_from_columns::<E>(
                    row,
                    fields,
                    self.backend,
                    (self.column)("id")?,
                    self.column,
                )
                .map(|record| record.with_id_output(self.runtime, self.role))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        super::plugin_rows::project_records(
            &fields.adapter_fields(&[]),
            records,
            self.backend,
            T::from_field_values,
        )
        .await
    }

    /// The caller admits the input ID; this operation only applies the selected ID field policy.
    pub(super) async fn create(
        &self,
        connection: &impl ConnectionTrait,
        scope: ReadbackScope<'_>,
        model: &str,
        input: FieldValue,
        force_allow_id: bool,
    ) -> AuthResult<Option<FieldMap>> {
        let active = self.prepare(input, Some(model), force_allow_id).await?;
        let row = database_operation::<E, _>(self.config, "create", async {
            active
                .insert_raw(
                    connection,
                    CreateReadback {
                        schema: &self.fields,
                        policy: self.config.advanced.database.generate_id(),
                        scope,
                        column: self.column,
                    },
                )
                .await
        })
        .await?;
        Ok(self.project(row.as_slice()).await?.pop())
    }

    pub(super) async fn find_by_id(
        &self,
        connection: &impl ConnectionTrait,
        id: &FieldValue,
    ) -> AuthResult<Option<FieldMap>> {
        let selector = self.bind_query_field("id", id)?;
        let (column, value) = self.resolve_query_field(selector)?;
        let filter = super::value_filter::equals(column, &value, self.backend)?;
        let row = database_operation::<E, _>(self.config, "findOne", async {
            connection
                .query_one_raw(
                    super::plugin_rows::select_all::<E>()
                        .filter(filter)
                        .compile_find(connection.get_database_backend())?,
                )
                .await
                .map_err(map_db_err)
        })
        .await?;
        Ok(self.project(row.as_slice()).await?.pop())
    }

    pub(super) async fn update_by_id(
        &self,
        connection: &impl ConnectionTrait,
        id: &FieldValue,
        input: FieldValue,
    ) -> AuthResult<Option<FieldMap>> {
        let selector = self.bind_query_field("id", id)?;
        let active = self.prepare(input, None, false).await?;
        let row = database_operation::<E, _>(self.config, "update", async {
            let (column, value) = self.resolve_query_field(selector)?;
            let predicate = QueryPredicate::equals(column, value);
            let (query, reselect) =
                active.update_where_returning(connection.get_database_backend(), [predicate])?;
            super::updates::execute_update_returning_raw::<E, _>(connection, query, reselect).await
        })
        .await?;
        Ok(self.project(row.as_slice()).await?.pop())
    }

    pub(super) async fn delete_by_id(
        &self,
        connection: &impl ConnectionTrait,
        id: &FieldValue,
    ) -> AuthResult<()> {
        let selector = self.bind_query_field("id", id)?;
        let (column, value) = self.resolve_query_field(selector)?;
        let filter = super::value_filter::equals(column, &value, self.backend)?;
        database_operation::<E, _>(self.config, "delete", async {
            let _ = E::delete_many()
                .filter(filter)
                .exec_native(connection)
                .await?;
            Ok(())
        })
        .await
    }

    pub(super) async fn list(
        &self,
        connection: &impl ConnectionTrait,
    ) -> AuthResult<Vec<FieldMap>> {
        let rows = database_operation::<E, _>(self.config, "findMany", async {
            connection
                .query_all_raw(
                    super::plugin_rows::select_all::<E>()
                        .limit(super::pagination::default_limit(
                            self.config,
                            connection.get_database_backend(),
                        )?)
                        .compile_find(connection.get_database_backend())?,
                )
                .await
                .map_err(map_db_err)
        })
        .await?;
        self.project(&rows).await
    }
}
