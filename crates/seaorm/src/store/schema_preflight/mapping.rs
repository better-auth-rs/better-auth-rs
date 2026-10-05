use crate::{
    SeaOrmAccountModel, SeaOrmOrganizationModel, SeaOrmPluginModel, SeaOrmSessionModel,
    SeaOrmUserModel, SeaOrmVerificationModel,
};
use better_auth_core::store::schema::resolve_field_name;
use better_auth_core::{
    AuthResult, AuthSchema, AuthSession, AuthUser,
    organization_fields::OrganizationFields,
    store::schema::{EntityRole, SchemaConfiguration, SchemaTable, core_fields},
    user_fields::UserConfig,
};
use sea_orm::{ColumnTrait, EntityTrait};

fn model<E: EntityTrait>(columns: Vec<String>) -> SchemaTable {
    let entity = E::default();
    SchemaTable {
        name: entity.table_name().to_owned(),
        schema: entity.schema_name().map(str::to_owned),
        columns,
        disable_migrations: false,
    }
}

fn columns<C: ColumnTrait>(
    required: impl IntoIterator<Item = &'static str>,
    policies: &UserConfig,
    column: impl Fn(&str) -> AuthResult<C>,
    declared_plugin_fields: &[&str],
    extra_insert_columns: Vec<C>,
) -> AuthResult<Vec<String>> {
    let mut names = Vec::new();
    for field in required {
        let name = column(field)?.as_str().to_owned();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    // Typed plugin columns are assigned by AuthEntity's insert. LastLoginMethod uses field policies.
    // Unconfigured application fields are NotSet and must not enter the written set.
    for field in declared_plugin_fields
        .iter()
        .filter(|field| **field != "last_login_method")
    {
        let name = column(field)?.as_str().to_owned();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    for column in extra_insert_columns {
        let name = column.as_str().to_owned();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    for (name, field) in policies.fields() {
        if name == "id" {
            continue;
        }
        let name = column(resolve_field_name(field.field_name.as_deref(), name))?
            .as_str()
            .to_owned();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    Ok(names)
}

fn organization<M: SeaOrmOrganizationModel>(
    role: EntityRole,
    fields: &UserConfig,
) -> AuthResult<SchemaTable> {
    Ok(model::<M::Entity>(columns(
        core_fields(role).iter().map(|field| field.name),
        fields,
        M::column,
        &[],
        Vec::new(),
    )?))
}

fn plugin<M: SeaOrmPluginModel>(role: EntityRole, fields: &UserConfig) -> AuthResult<SchemaTable> {
    Ok(model::<M::Entity>(columns(
        core_fields(role)
            .iter()
            .filter(|field| {
                !(role == EntityRole::Passkey
                    && M::passkey_storage() == better_auth_core::PasskeyStorage::Native
                    && matches!(field.name, "credential" | "updated_at"))
            })
            .map(|field| field.name),
        fields,
        M::column,
        &[],
        Vec::new(),
    )?))
}

pub(super) fn tables<S, O, P>(
    settings: &SchemaConfiguration,
    organization_fields: &OrganizationFields,
    model_fields: &better_auth_core::plugin_runtime::ModelFields,
) -> AuthResult<Vec<SchemaTable>>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
{
    let config = &settings.config;
    let mut expected = vec![model::<<S::User as SeaOrmUserModel>::Entity>(columns(
        core_fields(EntityRole::User).iter().map(|field| field.name),
        &config.user,
        S::User::field_column,
        S::User::PLUGIN_FIELDS,
        S::User::extra_insert_columns(),
    )?)];
    if settings.database_sessions() {
        let fields = UserConfig {
            additional_fields: config.session.additional_fields.clone(),
        };
        expected.push(model::<<S::Session as SeaOrmSessionModel>::Entity>(
            columns(
                core_fields(EntityRole::Session)
                    .iter()
                    .map(|field| field.name)
                    .filter(|name| *name != "active" || S::Session::active_column().is_some()),
                &fields,
                S::Session::field_column,
                S::Session::PLUGIN_FIELDS,
                S::Session::extra_insert_columns(),
            )?,
        ));
    }
    let fields = UserConfig {
        additional_fields: Some(config.account.additional_fields.clone()),
    };
    expected.push(model::<<S::Account as SeaOrmAccountModel>::Entity>(
        columns(
            core_fields(EntityRole::Account)
                .iter()
                .map(|field| field.name),
            &fields,
            S::Account::field_column,
            &[],
            S::Account::extra_insert_columns(),
        )?,
    ));
    if settings.database_verifications() {
        let fields = UserConfig {
            additional_fields: Some(config.verification.additional_fields.clone()),
        };
        expected.push(
            model::<<S::Verification as SeaOrmVerificationModel>::Entity>(columns(
                core_fields(EntityRole::Verification)
                    .iter()
                    .map(|field| field.name),
                &fields,
                S::Verification::field_column,
                &[],
                S::Verification::extra_insert_columns(),
            )?),
        );
    }
    for name in &settings.plugins {
        match *name {
            "organization" => {
                expected.push(organization::<O::Organization>(
                    EntityRole::Organization,
                    &organization_fields.organization,
                )?);
                expected.push(organization::<O::Member>(
                    EntityRole::Member,
                    &organization_fields.member,
                )?);
                expected.push(organization::<O::Invitation>(
                    EntityRole::Invitation,
                    &organization_fields.invitation,
                )?);
                if settings.metadata_flag("organization.teams_enabled") {
                    expected.push(organization::<O::Team>(
                        EntityRole::Team,
                        &organization_fields.team,
                    )?);
                    expected.push(organization::<O::TeamMember>(
                        EntityRole::TeamMember,
                        &UserConfig::default(),
                    )?);
                }
                if settings.metadata_flag("organization.dynamic_access_control") {
                    expected.push(organization::<O::OrganizationRole>(
                        EntityRole::OrganizationRole,
                        &organization_fields.organization_role,
                    )?);
                }
            }
            "api-key" => expected.push(plugin::<P::ApiKey>(
                EntityRole::ApiKey,
                model_fields.fields(EntityRole::ApiKey),
            )?),
            "device-authorization" => expected.push(plugin::<P::DeviceCode>(
                EntityRole::DeviceCode,
                model_fields.fields(EntityRole::DeviceCode),
            )?),
            "passkey" => expected.push(plugin::<P::Passkey>(
                EntityRole::Passkey,
                model_fields.fields(EntityRole::Passkey),
            )?),
            "two-factor" => expected.push(plugin::<P::TwoFactor>(
                EntityRole::TwoFactor,
                model_fields.fields(EntityRole::TwoFactor),
            )?),
            "jwt" => expected.push(plugin::<P::Jwk>(
                EntityRole::Jwk,
                model_fields.fields(EntityRole::Jwk),
            )?),
            "siwe" => expected.push(plugin::<P::WalletAddress>(
                EntityRole::WalletAddress,
                model_fields.fields(EntityRole::WalletAddress),
            )?),
            _ => {}
        }
    }
    if settings.database_rate_limit {
        expected.push(plugin::<P::RateLimit>(
            EntityRole::RateLimit,
            model_fields.fields(EntityRole::RateLimit),
        )?);
    }
    Ok(expected)
}
