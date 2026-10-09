use better_auth_core::{
    AuthError, AuthResult, FieldValue,
    store::schema::{EntityRole, resolve_field_name},
    user_fields::{UserConfig, UserFieldConfig, UserFieldType},
};
use sea_orm::{
    ColumnTrait, DbBackend,
    sea_query::{ExprTrait, SimpleExpr},
};

use super::id_filter::IdColumn;

pub(super) fn query_field_name<'a>(
    role: EntityRole,
    fields: &'a UserConfig,
    name: &str,
) -> AuthResult<(&'a str, &'a str)> {
    if matches!(name, "id" | "_id") {
        return Ok((
            "id",
            resolve_field_name(
                fields
                    .fields()
                    .get("id")
                    .and_then(|field| field.field_name.as_deref()),
                "id",
            ),
        ));
    }
    let (logical, field) = fields
        .fields()
        .get_key_value(name)
        .or_else(|| {
            fields
                .fields()
                .iter()
                .find(|(_, field)| field.field_name.as_deref() == Some(name))
        })
        .ok_or_else(|| unknown_query_field(role, name))?;
    Ok((
        logical,
        resolve_field_name(field.field_name.as_deref(), logical),
    ))
}

fn unknown_query_field(role: EntityRole, name: &str) -> AuthError {
    let model = match role {
        EntityRole::User => "user",
        EntityRole::Session => "session",
        EntityRole::Account => "account",
        EntityRole::Verification => "verification",
        EntityRole::Organization => "organization",
        EntityRole::Member => "member",
        EntityRole::Invitation => "invitation",
        EntityRole::Team => "team",
        EntityRole::TeamMember => "teamMember",
        EntityRole::OrganizationRole => "organizationRole",
        EntityRole::ApiKey => "apikey",
        EntityRole::DeviceCode => "deviceCode",
        EntityRole::Passkey => "passkey",
        EntityRole::TwoFactor => "twoFactor",
        EntityRole::Jwk => "jwks",
        EntityRole::WalletAddress => "walletAddress",
        EntityRole::RateLimit => "rateLimit",
    };
    AuthError::config(format!("Field {name} not found in model {model}"))
}

pub(super) struct BoundQueryField {
    mapped_name: String,
    value: FieldValue,
}

impl BoundQueryField {
    pub(super) fn resolve(
        self,
        role: EntityRole,
        configured: &UserConfig,
    ) -> AuthResult<(String, FieldValue)> {
        // Kysely resolves names after the factory binds every operand and runs input callbacks.
        let fields = configured.adapter_fields(&[]);
        let (_, column) = query_field_name(role, &fields, &self.mapped_name)?;
        Ok((column.to_owned(), self.value))
    }
}

fn bind_factory_query_field(
    runtime: &better_auth_core::plugin_runtime::ModelFields,
    role: EntityRole,
    configured: &UserConfig,
    name: &str,
    original: &FieldValue,
    policy: &better_auth_core::id::IdGeneration,
    backend: DbBackend,
) -> AuthResult<BoundQueryField> {
    let before = runtime.runtime_fields(role, configured)?;
    let (logical, mapped) = query_field_name(role, &before, name)?;
    runtime.begin_id_query(role)?;
    let fields = before.adapter_fields(&[]);
    let field = fields
        .fields()
        .get(logical)
        .ok_or_else(|| unknown_query_field(role, logical))?;
    let value = if logical == "id" || field.references_id() {
        policy.adapter_id_query(original.clone())?
    } else {
        original.clone()
    };
    let value = better_auth_core::user_query::bind_filter(field, &value)?;
    let value = adapter_query_value(value, original, field, backend)?;
    Ok(BoundQueryField {
        mapped_name: mapped.to_owned(),
        value,
    })
}

pub(super) fn bind_query_field(
    runtime: &better_auth_core::plugin_runtime::ModelFields,
    role: EntityRole,
    configured: &UserConfig,
    name: &str,
    original: &FieldValue,
    policy: &better_auth_core::id::IdGeneration,
    backend: DbBackend,
) -> AuthResult<(String, FieldValue)> {
    bind_factory_query_field(runtime, role, configured, name, original, policy, backend)?
        .resolve(role, configured)
}

impl<S: crate::schema::AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    super::SeaOrmStore<S, O, P>
{
    pub(super) fn bind_query_field(
        &self,
        role: EntityRole,
        configured: &UserConfig,
        name: &str,
        original: &FieldValue,
        backend: DbBackend,
    ) -> AuthResult<BoundQueryField> {
        bind_factory_query_field(
            &self.model_fields,
            role,
            configured,
            name,
            original,
            self.config().advanced.database.generate_id(),
            backend,
        )
    }

    pub(super) fn query_field_binding(
        &self,
        role: EntityRole,
        configured: &UserConfig,
        name: &str,
        original: &FieldValue,
        backend: DbBackend,
    ) -> AuthResult<(String, FieldValue)> {
        bind_query_field(
            &self.model_fields,
            role,
            configured,
            name,
            original,
            self.config().advanced.database.generate_id(),
            backend,
        )
    }
}

pub(super) fn adapter_query_value(
    mut value: FieldValue,
    original: &FieldValue,
    field: &UserFieldConfig,
    backend: DbBackend,
) -> AuthResult<FieldValue> {
    if backend == DbBackend::Sqlite
        && matches!(field.field_type, UserFieldType::Date)
        && let FieldValue::Date(date) = original
    {
        value = super::record_bindings::sqlite_date(date.clone())?;
    }
    if backend != DbBackend::Postgres
        && matches!(field.field_type, UserFieldType::Json)
        && matches!(
            original,
            FieldValue::Null | FieldValue::Date(_) | FieldValue::Array(_) | FieldValue::Object(_)
        )
    {
        value = original
            .stringify()?
            .map(FieldValue::String)
            .unwrap_or_default();
    }
    if backend != DbBackend::Postgres
        && matches!(field.field_type, UserFieldType::Boolean)
        && let FieldValue::Bool(boolean) = value
    {
        value = FieldValue::Number(f64::from(u8::from(boolean)));
    }
    Ok(value)
}

pub(super) fn like_pattern(
    value: &FieldValue,
    prefix: &str,
    suffix: &str,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    let text = value.display_utf16()?;
    let units = prefix
        .encode_utf16()
        .chain(text.as_utf16().iter().copied())
        .chain(suffix.encode_utf16())
        .collect();
    super::record_bindings::parameter(
        better_auth_core::Utf16String::from_units(units).into(),
        backend,
    )
}

pub(super) fn equals_id(
    column: impl ColumnTrait,
    value: &FieldValue,
    policy: &better_auth_core::id::IdGeneration,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    let value = policy.adapter_id_query(value.clone())?;
    match &value {
        FieldValue::String(value) => column.eq_id(value, policy, backend),
        value => equals(column, value, backend),
    }
}

pub(super) fn equals(
    column: impl ColumnTrait,
    value: &FieldValue,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    if value.is_null() {
        return Ok(column.is_null());
    }
    let value = if let FieldValue::Array(values) = value {
        SimpleExpr::Tuple(
            values
                .iter()
                .cloned()
                .map(|value| super::record_bindings::parameter(value, backend))
                .collect::<AuthResult<Vec<_>>>()?,
        )
    } else {
        super::record_bindings::parameter(value.clone(), backend)?
    };
    Ok(column.into_expr().eq(column.save_as(value)))
}

pub(super) fn equals_native(
    column: impl ColumnTrait,
    value: impl Into<sea_orm::Value>,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    let value = super::record_bindings::Binding::Native(value.into()).bind(backend)?;
    Ok(column.into_expr().eq(column.save_as(value)))
}

pub(super) fn is_in(
    column: impl ColumnTrait,
    value: &FieldValue,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    let values = value
        .as_array()
        .unwrap_or_else(|| std::slice::from_ref(value));
    in_bindings(
        column,
        values
            .iter()
            .cloned()
            .map(super::record_bindings::Binding::Raw)
            .collect(),
        backend,
    )
}

pub(super) fn is_in_native(
    column: impl ColumnTrait,
    values: impl IntoIterator<Item = impl Into<sea_orm::Value>>,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    in_bindings(
        column,
        values
            .into_iter()
            .map(|value| super::record_bindings::Binding::Native(value.into()))
            .collect(),
        backend,
    )
}

fn in_bindings(
    column: impl ColumnTrait,
    values: Vec<super::record_bindings::Binding>,
    backend: DbBackend,
) -> AuthResult<SimpleExpr> {
    let values = super::record_bindings::bind(backend, values)?;
    Ok(column
        .into_expr()
        .is_in(values.into_iter().map(|value| column.save_as(value))))
}

#[cfg(test)]
#[path = "core_query_binding_tests.rs"]
mod core_query_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::entities::api_key;
    use sea_orm::{QueryFilter, QueryTrait};

    #[test]
    fn query_aliases_keep_original_types_and_primary_key_history() -> AuthResult<()> {
        use better_auth_core::{id::IdGeneration, plugin_runtime::ModelFields};

        let fields = UserConfig {
            additional_fields: Some(
                [
                    (
                        "id".into(),
                        UserFieldConfig {
                            field_name: Some("old_id".into()),
                            ..Default::default()
                        },
                    ),
                    (
                        "source".into(),
                        UserFieldConfig {
                            field_name: Some("target".into()),
                            field_type: UserFieldType::Number,
                            ..Default::default()
                        },
                    ),
                    (
                        "target".into(),
                        UserFieldConfig {
                            field_name: Some("stored".into()),
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
            ),
        };
        let runtime = ModelFields::default();
        let role = EntityRole::Verification;
        let bind = |name: &str, value: FieldValue| {
            bind_query_field(
                &runtime,
                role,
                &fields,
                name,
                &value,
                &IdGeneration::Serial,
                DbBackend::Sqlite,
            )
        };
        assert!(
            matches!(bind("missing", "1".into()), Err(AuthError::Config(message)) if message == "Field missing not found in model verification")
        );
        assert!(runtime.id_input_policy(role)?.is_none());
        assert!(
            matches!(bind("_id", "1".into()), Err(AuthError::Config(message)) if message == "Field old_id not found in model verification")
        );
        assert!(runtime.id_input_policy(role)?.is_some());
        assert_eq!(
            bind("_id", "01".into())?,
            ("id".into(), FieldValue::Number(1.0))
        );
        assert_eq!(
            bind("source", "0x10".into())?,
            ("stored".into(), FieldValue::Number(16.0))
        );
        assert_eq!(
            bind("stored", "0x10".into())?,
            ("stored".into(), "0x10".into())
        );
        Ok(())
    }

    #[test]
    fn undefined_equality_keeps_the_driver_binding_instead_of_testing_for_null() -> AuthResult<()> {
        use sea_orm::EntityTrait;

        for backend in [DbBackend::Sqlite, DbBackend::Postgres, DbBackend::MySql] {
            let undefined = api_key::Entity::find()
                .filter(equals(
                    api_key::Column::LastRefillAt,
                    &FieldValue::Undefined,
                    backend,
                )?)
                .build(backend)
                .to_string();
            let null = api_key::Entity::find()
                .filter(equals(
                    api_key::Column::LastRefillAt,
                    &FieldValue::Null,
                    backend,
                )?)
                .build(backend)
                .to_string();
            assert!(undefined.ends_with(" = NULL"), "{backend:?}: {undefined}");
            assert!(null.ends_with(" IS NULL"), "{backend:?}: {null}");
        }
        Ok(())
    }
}
