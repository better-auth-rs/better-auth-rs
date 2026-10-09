use super::id_filter::IdColumn;
use crate::SeaOrmOrganizationModel;
use better_auth_core::store::schema::resolve_field_name;
use better_auth_core::{AuthError, AuthResult, user_fields::UserConfig};
use better_auth_core::{FieldMap, FieldValue};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, QueryFilter,
};

pub(super) type Entity<M> = <M as SeaOrmOrganizationModel>::Entity;

impl<S: crate::schema::AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    super::SeaOrmStore<S, O, P>
{
    pub(super) fn organization_field_equals<M: SeaOrmOrganizationModel>(
        &self,
        role: better_auth_schema_registry::EntityRole,
        name: &str,
        value: &FieldValue,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        self.model_fields.begin_id_query(role)?;
        let fields = self.organization_fields()?.schema_for(role)?;
        let field = fields.fields().get(name).ok_or_else(|| {
            AuthError::config(format!("Unknown organization field {role:?}.{name}"))
        })?;
        let column = M::column(resolve_field_name(field.field_name.as_deref(), name))?;
        let bound = if name == "id" || field.references_id() {
            self.config()
                .advanced
                .database
                .generate_id()
                .adapter_id_query(value.clone())?
        } else {
            value.clone()
        };
        let bound = better_auth_core::user_query::bind_filter(field, &bound)?;
        let backend = self.connection().get_database_backend();
        let bound = super::value_filter::adapter_query_value(bound, value, field, backend)?;
        super::value_filter::equals(column, &bound, backend)
    }
}

pub(crate) fn record_fields<M: SeaOrmOrganizationModel>(
    model: &M,
    fields: &UserConfig,
    backend: DbBackend,
) -> AuthResult<better_auth_core::user_fields::AdapterRecord> {
    let mut record = model.record_fields(fields)?;
    if backend == DbBackend::Sqlite {
        record.map_native_fields(fields, |name| {
            super::field_output::sqlite_json_output(
                &super::field_output::column_value::<M::Entity>(model, M::column(name)?),
            )
        })?;
    }
    record.map_storage_fields(
        fields,
        super::field_output::capabilities(backend),
        |name, field| {
            super::field_output::plugin_field_output(
                super::field_output::column_value::<M::Entity>(model, M::column(name)?),
                field,
                backend,
            )
        },
    )?;
    Ok(record)
}

pub(super) fn values<const N: usize>(fields: [(&str, FieldValue); N]) -> FieldMap {
    fields
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
}

pub(super) async fn active<M: SeaOrmOrganizationModel>(
    core: FieldMap,
    input: FieldMap,
    config: &UserConfig,
    create: bool,
    backend: sea_orm::DbBackend,
    policy: &better_auth_core::id::IdGeneration,
) -> AuthResult<super::record_write::RecordWrite<Entity<M>>> {
    let mut core = core
        .into_iter()
        .map(|(name, value)| {
            let column = M::column(&name)?;
            Ok((
                M::core_field_name(&column).unwrap_or(&name).to_owned(),
                value,
            ))
        })
        .collect::<AuthResult<FieldMap>>()?;
    crate::reference_id::prepare_core_fields(
        &mut core,
        policy,
        Some(config),
        M::column,
        M::is_id_reference,
    )?;
    let fields = config
        .organization_storage_fields_with_binding(
            core,
            input,
            create,
            |storage_name, field, value| {
                let column = M::column(storage_name)?;
                let native_json = matches!(
                    column.def().get_column_type(),
                    sea_orm::ColumnType::Json | sea_orm::ColumnType::JsonBinary
                );
                crate::reference_id::input_binding(
                    storage_name,
                    field,
                    value,
                    policy,
                    M::column,
                    |_| native_json,
                    backend,
                )
            },
        )
        .await?;
    let mut active = super::record_write::RecordWrite::<Entity<M>>::default();
    for (name, value) in fields {
        let configured = config.fields().iter().any(|(logical, field)| {
            resolve_field_name(field.field_name.as_deref(), logical) == name
        });
        let column = M::column(&name)?;
        if configured {
            active.field(column, value);
        } else {
            active.native_field(column, value);
        }
    }
    Ok(active)
}

pub(super) async fn insert<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    scope: super::create_readback::ReadbackScope<'_>,
    core: FieldMap,
    input: FieldMap,
    config: &UserConfig,
    policy: &better_auth_core::id::IdGeneration,
) -> AuthResult<M::Record> {
    active::<M>(
        core,
        input,
        config,
        true,
        conn.get_database_backend(),
        policy,
    )
    .await?
    .insert(
        conn,
        super::create_readback::CreateReadback {
            schema: config,
            policy,
            scope,
            column: M::column,
        },
    )
    .await?
    .ok_or_else(|| AuthError::internal("Organization record creation returned no record"))?
    .record(config, conn.get_database_backend())
    .await
}

pub(super) async fn find<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    id: &str,
    policy: &better_auth_core::id::IdGeneration,
) -> AuthResult<Option<M>> {
    Entity::<M>::find()
        .filter(M::column("id")?.eq_id(id, policy)?)
        .one(conn)
        .await
        .map_err(super::map_db_err)
}

pub(super) async fn update<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    id: &str,
    core: FieldMap,
    input: FieldMap,
    config: &UserConfig,
    policy: &better_auth_core::id::IdGeneration,
) -> AuthResult<M::Record> {
    let active = active::<M>(
        core,
        input,
        config,
        false,
        conn.get_database_backend(),
        policy,
    )
    .await?;
    let _ = active
        .update(conn.get_database_backend())?
        .filter(M::column("id")?.eq_id(id, policy)?)
        .exec(conn)
        .await
        .map_err(super::map_db_err)?;
    find::<M, _>(conn, id, policy)
        .await?
        .ok_or_else(|| better_auth_core::AuthError::not_found("Organization record not found"))?
        .record(config, conn.get_database_backend())
        .await
}

pub(super) async fn project<M: SeaOrmOrganizationModel>(
    rows: Vec<M>,
    config: &UserConfig,
    backend: DbBackend,
) -> AuthResult<Vec<M::Record>> {
    M::records(&rows, config, backend).await
}

pub(super) async fn project_then<M: SeaOrmOrganizationModel, R: Send, F>(
    rows: &[M],
    config: &UserConfig,
    backend: DbBackend,
    complete: impl Fn(usize, M::Record) -> F + Sync,
) -> AuthResult<Vec<R>>
where
    M::Record: Send,
    F: Future<Output = AuthResult<R>> + Send,
{
    let records = rows
        .iter()
        .map(|row| record_fields(row, config, backend))
        .collect::<AuthResult<Vec<_>>>()?;
    config
        .organization_output_records_then(
            records,
            backend == DbBackend::Postgres,
            |index, fields| {
                let complete = &complete;
                async move {
                    let row = rows.get(index).ok_or_else(|| {
                        AuthError::internal("Organization projection lost its stored row index")
                    })?;
                    complete(index, row.record_from_fields(config, fields)?).await
                }
            },
        )
        .await
}

pub(super) async fn project_batches_then<M: SeaOrmOrganizationModel, R: Send, F>(
    rows: &[M],
    config: &UserConfig,
    backend: DbBackend,
    complete: impl Fn(Vec<(usize, M::Record)>) -> F + Sync,
) -> AuthResult<Vec<R>>
where
    M::Record: Send,
    F: Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
{
    let records = rows
        .iter()
        .map(|row| record_fields(row, config, backend))
        .collect::<AuthResult<Vec<_>>>()?;
    config
        .organization_output_records_batches_then(
            records,
            backend == DbBackend::Postgres,
            |index, fields| {
                rows.get(index)
                    .ok_or_else(|| {
                        AuthError::internal("Organization projection lost its stored row index")
                    })?
                    .record_from_fields(config, fields)
            },
            complete,
        )
        .await
}

/// Resolve every configured field before accepting writes through this model.
pub(super) fn validate_fields<M: SeaOrmOrganizationModel>(
    entity: &str,
    fields: &UserConfig,
) -> AuthResult<()> {
    super::plugin_models::validate_field_columns(
        &format!("Organization schema {entity}"),
        fields,
        M::column,
        M::core_field_name,
    )
}

/// Read a stored join key before output policies can replace its public value.
pub(super) fn join_value<M: SeaOrmOrganizationModel>(
    model: &M,
    name: &str,
) -> AuthResult<sea_orm::Value> {
    model
        .clone()
        .into_active_model()
        .get(M::column(name)?)
        .into_value()
        .ok_or_else(|| AuthError::internal("Stored organization join key is unavailable"))
}
