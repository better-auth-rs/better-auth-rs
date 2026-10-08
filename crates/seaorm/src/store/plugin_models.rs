use crate::{SeaOrmPluginModel, schema::AuthSchema};
use better_auth_core::store::schema::{EntityRole, core_fields, resolve_field_name};
use better_auth_core::{AuthError, AuthResult, id::IdGeneration, user_fields::UserConfig};
use better_auth_core::{FieldMap, FromFieldMap, SchemaField};
use sea_orm::{ColumnTrait, DbBackend, ExprTrait, IdenStatic, QueryResult};

pub(super) type Write<M> = super::record_write::RecordWrite<Entity<M>>;

pub(super) type Entity<M> = <M as SeaOrmPluginModel>::Entity;

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    super::SeaOrmStore<S, O, P>
{
    pub(super) fn plugin_column<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        name: &str,
    ) -> AuthResult<M::Column> {
        if name == "id" {
            return M::column("id");
        }
        let fields = self.model_fields.plugin_fields(role);
        let storage = fields.fields().get(name).map_or(name, |field| {
            resolve_field_name(field.field_name.as_deref(), name)
        });
        M::column(storage)
    }

    pub(super) fn validate_plugin_fields<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
    ) -> AuthResult<()> {
        for name in self.model_fields.plugin_fields(role).fields().keys() {
            let _ = self.plugin_column::<M>(role, name)?;
        }
        let _ = M::column("id")?;
        Ok(())
    }

    fn plugin_query_value(
        &self,
        role: EntityRole,
        name: &str,
        value: better_auth_core::FieldValue,
    ) -> AuthResult<better_auth_core::FieldValue> {
        self.model_fields.begin_id_query(role)?;
        let fields = self.model_fields.plugin_fields(role);
        let backend = self.connection().get_database_backend();
        let field = fields
            .fields()
            .get(name)
            .ok_or_else(|| AuthError::config(format!("Unknown plugin field {role:?}.{name}")))?;
        let original = value.clone();
        let value = if name == "id" || field.references_id() {
            self.config()
                .advanced
                .database
                .generate_id()
                .adapter_id_query(value)?
        } else {
            value
        };
        let value = better_auth_core::user_query::bind_filter(field, &value)?;
        super::value_filter::adapter_query_value(value, &original, field, backend)
    }

    pub(super) fn plugin_parameter(
        &self,
        role: EntityRole,
        name: &str,
        value: better_auth_core::FieldValue,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        super::record_bindings::parameter(
            self.plugin_query_value(role, name, value)?,
            self.connection().get_database_backend(),
        )
    }

    pub(super) fn plugin_equals<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        name: &str,
        value: better_auth_core::FieldValue,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        let column = self.plugin_column::<M>(role, name)?;
        let value = self.plugin_query_value(role, name, value)?;
        if value.is_null() || value.is_undefined() {
            return Ok(column.is_null());
        }
        let value =
            super::record_bindings::parameter(value, self.connection().get_database_backend())?;
        Ok(column.into_expr().eq(column.save_as(value)))
    }

    pub(super) fn plugin_id_filter<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        id: &better_auth_core::SchemaValue<String>,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        self.model_fields.begin_id_query(role)?;
        let policy = self.config().advanced.database.generate_id();
        super::value_filter::equals_id(
            M::column("id")?,
            &policy.adapter_id_query(id.field_value())?,
            policy,
            self.connection().get_database_backend(),
        )
    }

    pub(super) async fn prepare_plugin_fields<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        model: &str,
        input: FieldMap,
        create: bool,
    ) -> AuthResult<Write<M>> {
        let fields = self.model_fields.plugin_fields(role);
        let backend = self.connection().get_database_backend();
        let policy = self.config().advanced.database.generate_id();
        let id_policy = better_auth_core::id::AdapterIdInput {
            force_allow_id: create,
            supports_native_uuid: backend == DbBackend::Postgres,
        };
        self.model_fields.begin_id_input(role, id_policy)?;
        let mut supplied_id = input.get("id").cloned();
        let stored = fields
            .storage_fields_with_bound_id(
                input,
                create,
                || {
                    let supplied = supplied_id.take();
                    let Some(current) = self.model_fields.id_input_policy(role)? else {
                        return Ok(supplied.filter(|value| !value.is_undefined()));
                    };
                    if create {
                        policy.adapter_create_id_input(model, supplied, current)
                    } else {
                        supplied
                            .map(|value| policy.adapter_id_input(value, current))
                            .transpose()
                            .map(Option::flatten)
                    }
                },
                |name, field, value| {
                    additional_field_input::<M>(name, field, value, policy, backend)
                },
            )
            .await?;
        Write::<M>::from_fields(stored, M::column)
    }

    pub(super) async fn project_plugin_rows<M: SeaOrmPluginModel, T: FromFieldMap>(
        &self,
        role: EntityRole,
        rows: Vec<QueryResult>,
    ) -> AuthResult<Vec<T>> {
        let backend = self.connection().get_database_backend();
        let fields = self.model_fields.plugin_fields(role);
        let records = rows
            .iter()
            .map(|row| super::plugin_rows::record::<M>(row, &fields, backend))
            .collect::<AuthResult<Vec<_>>>()?;
        self.model_fields
            .project_plugin_records(
                role,
                records,
                super::field_output::capabilities(backend),
                backend != DbBackend::Sqlite,
            )
            .await
    }
}

pub(super) fn record_fields<M: SeaOrmPluginModel>(
    model: &M,
    fields: &UserConfig,
    backend: DbBackend,
) -> AuthResult<better_auth_core::user_fields::AdapterRecord> {
    let mut record = model.record_fields(fields)?;
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
    crate::reference_id::prepare_core_fields(
        &mut fields,
        policy,
        None,
        M::column,
        M::is_id_reference,
    )?;
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
            additional_field_input::<M>(name, field, value, policy, backend)
        })
        .await?;
    additional_field_write::<M>(fields)
}

pub(super) async fn create_additional_fields<M: SeaOrmPluginModel>(
    config: &UserConfig,
    input: FieldMap,
    policy: &IdGeneration,
    backend: DbBackend,
    generate_id: impl FnMut() -> AuthResult<Option<String>>,
) -> AuthResult<(Write<M>, Option<String>)> {
    let (fields, id) = config
        .create_adapter_storage_fields(input, generate_id, |name, field, value| {
            additional_field_input::<M>(name, field, value, policy, backend)
        })
        .await?;
    Ok((additional_field_write::<M>(fields)?, id))
}

fn additional_field_input<M: SeaOrmPluginModel>(
    name: &str,
    field: &better_auth_core::user_fields::UserFieldConfig,
    value: better_auth_core::FieldValue,
    policy: &IdGeneration,
    backend: DbBackend,
) -> AuthResult<better_auth_core::FieldValue> {
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
}

fn additional_field_write<M: SeaOrmPluginModel>(fields: FieldMap) -> AuthResult<Write<M>> {
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
        if name == "id" {
            continue;
        }
        let storage = resolve_field_name(field.field_name.as_deref(), name);
        for core in core_fields(role).iter().filter(|field| {
            !(role == EntityRole::Passkey && matches!(field.name, "name" | "aaguid"))
                && !(role == EntityRole::TwoFactor
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
