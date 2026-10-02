use crate::SeaOrmPluginModel;
use better_auth_core::store::schema::{EntityRole, core_fields, resolve_field_name};
use better_auth_core::{AuthError, AuthResult, id::IdGeneration, user_fields::UserConfig};
use sea_orm::{ColumnTrait, DbBackend, IdenStatic};
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

pub(super) async fn additional_fields<M: SeaOrmPluginModel>(
    config: &UserConfig,
    input: Map<String, serde_json::Value>,
    policy: &IdGeneration,
    backend: DbBackend,
) -> AuthResult<M::ActiveModel> {
    let fields = config
        .storage_fields_with_binding(input, true, |name, field, value| {
            crate::reference_id::input_binding(
                name,
                field,
                value,
                policy,
                M::column,
                |name| {
                    M::column(name).is_ok_and(|column| {
                        matches!(
                            column.def().get_column_type(),
                            sea_orm::ColumnType::Json | sea_orm::ColumnType::JsonBinary
                        )
                    })
                },
                backend,
            )
        })
        .await?;
    let mut active = M::active(fields)?;
    crate::reference_id::apply_bindings(&mut active, config, backend, M::column)?;
    Ok(active)
}

pub(super) fn validate_additional_field_columns<M: SeaOrmPluginModel>(
    role: EntityRole,
    fields: &UserConfig,
) -> AuthResult<()> {
    validate_field_columns(
        &format!("{role:?} schema"),
        fields,
        M::column,
        M::core_field_name,
    )?;
    for (name, field) in fields.fields() {
        let storage = resolve_field_name(field.field_name.as_deref(), name);
        for core in core_fields(role) {
            let column = M::column(core.name)?;
            if [name.as_str(), storage].contains(&column.as_str()) {
                return Err(AuthError::config(format!(
                    "{role:?} additional field {name} cannot replace native column {storage}"
                )));
            }
        }
    }
    Ok(())
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
        let storage_name = resolve_field_name(field.field_name.as_deref(), name);
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
