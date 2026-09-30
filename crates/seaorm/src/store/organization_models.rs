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

pub(super) fn active<M: SeaOrmOrganizationModel>(
    core: Map<String, Value>,
    input: Map<String, Value>,
    config: &UserConfig,
    create: bool,
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
    M::active(config.organization_storage_fields(core, input, create)?)
}

pub(super) async fn insert<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    core: Map<String, Value>,
    input: Map<String, Value>,
    config: &UserConfig,
) -> AuthResult<M::Record> {
    active::<M>(core, input, config, true)?
        .insert(conn)
        .await
        .map_err(super::map_db_err)?
        .record(config)
}

pub(super) async fn find<M: SeaOrmOrganizationModel, C: ConnectionTrait>(
    conn: &C,
    id: &str,
) -> AuthResult<Option<M>> {
    Entity::<M>::find()
        .filter(M::column("id")?.eq(id))
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
) -> AuthResult<M::Record> {
    let active = active::<M>(core, input, config, false)?;
    let _ = Entity::<M>::update_many()
        .set(active)
        .filter(M::column("id")?.eq(id))
        .exec(conn)
        .await
        .map_err(super::map_db_err)?;
    find::<M, _>(conn, id)
        .await?
        .ok_or_else(|| better_auth_core::AuthError::not_found("Organization record not found"))?
        .record(config)
}

pub(super) fn project<M: SeaOrmOrganizationModel>(
    rows: Vec<M>,
    config: &UserConfig,
) -> AuthResult<Vec<M::Record>> {
    rows.iter().map(|row| row.record(config)).collect()
}

/// Resolve every configured field before accepting writes through this model.
pub(super) fn validate_fields<M: SeaOrmOrganizationModel>(
    entity: &str,
    fields: &UserConfig,
) -> AuthResult<()> {
    for (name, field) in &fields.additional_fields {
        if name == "id" {
            continue;
        }
        let storage_name = field.field_name.as_deref().unwrap_or(name);
        let column = M::column(storage_name)?;
        let logical = M::column(name)
            .ok()
            .and_then(|column| M::core_field_name(&column));
        let stored = M::core_field_name(&column);
        if logical.is_some_and(|public| public != name)
            || ((logical.is_some() || stored.is_some()) && logical != stored)
        {
            return Err(AuthError::config(format!(
                "Organization schema {entity}.{name} maps to a different typed field {storage_name}; built-in policies must use the same column"
            )));
        }
    }
    Ok(())
}
