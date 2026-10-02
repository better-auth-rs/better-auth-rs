use crate::SeaOrmPluginModel;
use better_auth_core::{AuthResult, id::IdGeneration};
use serde::Serialize;
use serde_json::Map;

pub(super) type Entity<M> = <M as SeaOrmPluginModel>::Entity;

pub(super) fn set<M: SeaOrmPluginModel>(
    active: &mut M::ActiveModel,
    name: &str,
    value: impl Serialize,
    policy: &IdGeneration,
) -> AuthResult<()> {
    let fields = Map::from_iter([(name.to_owned(), serde_json::to_value(value)?)]);
    apply::<M>(active, fields, policy)
}

pub(super) fn apply<M: SeaOrmPluginModel>(
    active: &mut M::ActiveModel,
    mut fields: Map<String, serde_json::Value>,
    policy: &IdGeneration,
) -> AuthResult<()> {
    crate::reference_id::prepare_fields(&mut fields, policy, None, M::column, M::is_id_reference)?;
    M::apply_fields(active, fields)
}

pub(super) fn active<M: SeaOrmPluginModel>(
    mut fields: Map<String, serde_json::Value>,
    policy: &IdGeneration,
) -> AuthResult<M::ActiveModel> {
    crate::reference_id::prepare_fields(&mut fields, policy, None, M::column, M::is_id_reference)?;
    M::active(fields)
}

/// Resolve configured policies before accepting writes to typed columns.
pub(super) fn validate_field_columns<C: sea_orm::ColumnTrait>(
    entity: &str,
    fields: &better_auth_core::user_fields::UserConfig,
    column: impl Fn(&str) -> AuthResult<C>,
    core_field_name: impl Fn(&C) -> Option<&'static str>,
) -> AuthResult<()> {
    for (name, field) in fields.fields() {
        if name == "id" {
            continue;
        }
        let storage_name = field.field_name.as_deref().unwrap_or(name);
        let stored_column = column(storage_name)?;
        let logical = column(name)
            .ok()
            .and_then(|column| core_field_name(&column));
        let stored = core_field_name(&stored_column);
        if logical.is_some_and(|public| public != name)
            || ((logical.is_some() || stored.is_some()) && logical != stored)
        {
            return Err(better_auth_core::AuthError::config(format!(
                "{entity}.{name} maps to a different typed field {storage_name}; built-in policies must use the same column"
            )));
        }
    }
    Ok(())
}
