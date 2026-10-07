use crate::SeaOrmPluginModel;
use better_auth_core::store::schema::{EntityRole, core_fields, resolve_field_name};
use better_auth_core::{AuthError, AuthResult, id::IdGeneration, user_fields::UserConfig};
use better_auth_core::{FieldMap, SchemaField};
use sea_orm::{ColumnTrait, DbBackend, IdenStatic};

pub(super) type Write<M> = super::record_write::RecordWrite<Entity<M>>;

pub(super) type Entity<M> = <M as SeaOrmPluginModel>::Entity;

pub(super) fn record_fields<M: SeaOrmPluginModel>(
    model: &M,
    fields: &UserConfig,
    backend: DbBackend,
) -> AuthResult<better_auth_core::user_fields::AdapterRecord> {
    let mut record = model.record_fields(fields)?;
    record.map_storage_fields(fields, |name, field| {
        super::field_output::plugin_field_output(
            super::field_output::column_value::<M::Entity>(model, M::column(name)?),
            field,
            backend,
        )
    })?;
    Ok(record)
}

pub(super) fn set<M: SeaOrmPluginModel>(
    active: &mut Write<M>,
    name: &str,
    value: impl SchemaField,
    policy: &IdGeneration,
) -> AuthResult<()> {
    let fields = FieldMap::from_iter([(name.to_owned(), value.into_field())]);
    apply::<M>(active, fields, policy)
}

pub(super) fn apply<M: SeaOrmPluginModel>(
    active: &mut Write<M>,
    mut fields: FieldMap,
    policy: &IdGeneration,
) -> AuthResult<()> {
    crate::reference_id::prepare_fields(&mut fields, policy, None, M::column, M::is_id_reference)?;
    for (name, value) in fields {
        active.native_field(M::column(&name)?, value);
    }
    Ok(())
}

pub(super) fn active<M: SeaOrmPluginModel>(
    fields: FieldMap,
    policy: &IdGeneration,
) -> AuthResult<Write<M>> {
    let mut active = Write::<M>::default();
    apply::<M>(&mut active, fields, policy)?;
    Ok(active)
}

pub(super) async fn additional_fields<M: SeaOrmPluginModel>(
    config: &UserConfig,
    input: FieldMap,
    policy: &IdGeneration,
    backend: DbBackend,
    create: bool,
) -> AuthResult<Write<M>> {
    let fields = config
        .storage_fields_with_binding(input, create, |name, field, value| {
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
    let mut active = Write::<M>::default();
    for (name, value) in fields {
        active.field(M::column(&name)?, value);
    }
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
        for core in core_fields(role).iter().filter(|field| {
            !(role == EntityRole::TwoFactor
                && M::two_factor_storage() == better_auth_core::TwoFactorStorage::Native
                && matches!(field.name, "created_at" | "updated_at"))
                && !(role == EntityRole::Passkey
                    && M::passkey_storage() == better_auth_core::PasskeyStorage::Native
                    && matches!(field.name, "credential" | "updated_at"))
        }) {
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
