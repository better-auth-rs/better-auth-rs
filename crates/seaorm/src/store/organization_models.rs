use super::id_filter::IdColumn;
use crate::SeaOrmOrganizationModel;
use better_auth_core::{AuthError, AuthResult, user_fields::UserConfig};
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use serde_json::{Map, Value};

pub(super) type Entity<M> = <M as SeaOrmOrganizationModel>::Entity;

pub(super) fn values<const N: usize>(fields: [(&str, Value); N]) -> Map<String, Value> {
    fields
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
}

pub(super) async fn active<M: SeaOrmOrganizationModel>(
    core: Map<String, Value>,
    input: Map<String, Value>,
    config: &UserConfig,
    create: bool,
    backend: sea_orm::DbBackend,
    policy: &better_auth_core::id::IdGeneration,
) -> AuthResult<M::ActiveModel> {
    let core = core
        .into_iter()
        .map(|(name, value)| {
            let column = M::column(&name)?;
            Ok((
                M::core_field_name(&column).unwrap_or(&name).to_owned(),
                value,
            ))
        })
        .collect::<AuthResult<Map<_, _>>>()?;
    let mut fields = config
        .organization_storage_fields(core, input, create)
        .await?;
    for (name, field) in config.fields() {
        if name == "id" {
            continue;
        }
        let storage_name = field.field_name.as_deref().unwrap_or(name);
        if let Some(value) = fields.get_mut(storage_name) {
            let column = M::column(storage_name)?;
            let native_json = matches!(
                column.def().get_column_type(),
                sea_orm::ColumnType::Json | sea_orm::ColumnType::JsonBinary
            );
            *value = field.adapter_input(
                std::mem::take(value),
                backend == sea_orm::DbBackend::Postgres,
                native_json,
            );
        }
    }
    crate::reference_id::prepare_fields(
        &mut fields,
        policy,
        Some(config),
        M::column,
        M::is_id_reference,
    )?;
    let mut active = M::active(fields)?;
    crate::reference_id::apply_bindings(&mut active, config, backend, M::column)?;
    Ok(active)
}

pub(super) async fn insert<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    core: Map<String, Value>,
    input: Map<String, Value>,
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
    .insert(conn)
    .await
    .map_err(super::map_db_err)?
    .record(
        config,
        conn.get_database_backend() == sea_orm::DbBackend::Postgres,
    )
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
    core: Map<String, Value>,
    input: Map<String, Value>,
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
    let _ = Entity::<M>::update_many()
        .set(active)
        .filter(M::column("id")?.eq_id(id, policy)?)
        .exec(conn)
        .await
        .map_err(super::map_db_err)?;
    find::<M, _>(conn, id, policy)
        .await?
        .ok_or_else(|| better_auth_core::AuthError::not_found("Organization record not found"))?
        .record(
            config,
            conn.get_database_backend() == sea_orm::DbBackend::Postgres,
        )
        .await
}

pub(super) async fn project<M: SeaOrmOrganizationModel>(
    rows: Vec<M>,
    config: &UserConfig,
    supports_native_json: bool,
) -> AuthResult<Vec<M::Record>> {
    M::records(&rows, config, supports_native_json).await
}

pub(super) async fn project_then<M: SeaOrmOrganizationModel, R: Send, F>(
    rows: &[M],
    config: &UserConfig,
    supports_native_json: bool,
    complete: impl Fn(usize, M::Record) -> F + Sync,
) -> AuthResult<Vec<R>>
where
    M::Record: Send,
    F: Future<Output = AuthResult<R>> + Send,
{
    let records = rows
        .iter()
        .map(|row| row.record_fields(config))
        .collect::<AuthResult<Vec<_>>>()?;
    config
        .organization_output_records_then(records, supports_native_json, |index, fields| {
            let complete = &complete;
            async move {
                let row = rows.get(index).ok_or_else(|| {
                    AuthError::internal("Organization projection lost its stored row index")
                })?;
                complete(index, row.record_from_fields(config, fields)?).await
            }
        })
        .await
}

pub(super) async fn project_batches_then<M: SeaOrmOrganizationModel, R: Send, F>(
    rows: &[M],
    config: &UserConfig,
    supports_native_json: bool,
    complete: impl Fn(Vec<(usize, M::Record)>) -> F + Sync,
) -> AuthResult<Vec<R>>
where
    M::Record: Send,
    F: Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
{
    let records = rows
        .iter()
        .map(|row| row.record_fields(config))
        .collect::<AuthResult<Vec<_>>>()?;
    config
        .organization_output_records_batches_then(
            records,
            supports_native_json,
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
