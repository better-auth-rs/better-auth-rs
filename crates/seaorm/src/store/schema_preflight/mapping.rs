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
                    && !(role == EntityRole::TwoFactor
                        && M::two_factor_storage() == better_auth_core::TwoFactorStorage::Native
                        && matches!(field.name, "created_at" | "updated_at"))
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
    settings
        .models()
        .into_iter()
        .map(|(role, _)| match role {
            EntityRole::User => Ok(model::<<S::User as SeaOrmUserModel>::Entity>(columns(
                core_fields(role).iter().map(|field| field.name),
                &config.user,
                S::User::field_column,
                S::User::PLUGIN_FIELDS,
                S::User::extra_insert_columns(),
            )?)),
            EntityRole::Session => Ok(model::<<S::Session as SeaOrmSessionModel>::Entity>(
                columns(
                    core_fields(role)
                        .iter()
                        .map(|field| field.name)
                        .filter(|name| *name != "active" || S::Session::active_column().is_some()),
                    &UserConfig {
                        additional_fields: config.session.additional_fields.clone(),
                    },
                    S::Session::field_column,
                    S::Session::PLUGIN_FIELDS,
                    S::Session::extra_insert_columns(),
                )?,
            )),
            EntityRole::Account => Ok(model::<<S::Account as SeaOrmAccountModel>::Entity>(
                columns(
                    core_fields(role).iter().map(|field| field.name),
                    &UserConfig {
                        additional_fields: Some(config.account.additional_fields.clone()),
                    },
                    S::Account::field_column,
                    &[],
                    S::Account::extra_insert_columns(),
                )?,
            )),
            EntityRole::Verification => Ok(model::<
                <S::Verification as SeaOrmVerificationModel>::Entity,
            >(columns(
                core_fields(role).iter().map(|field| field.name),
                &UserConfig {
                    additional_fields: Some(config.verification.additional_fields.clone()),
                },
                S::Verification::field_column,
                &[],
                S::Verification::extra_insert_columns(),
            )?)),
            EntityRole::Organization => {
                organization::<O::Organization>(role, &organization_fields.organization)
            }
            EntityRole::Member => organization::<O::Member>(role, &organization_fields.member),
            EntityRole::Invitation => {
                organization::<O::Invitation>(role, &organization_fields.invitation)
            }
            EntityRole::Team => organization::<O::Team>(role, &organization_fields.team),
            EntityRole::TeamMember => organization::<O::TeamMember>(role, &UserConfig::default()),
            EntityRole::OrganizationRole => {
                organization::<O::OrganizationRole>(role, &organization_fields.organization_role)
            }
            EntityRole::ApiKey => plugin::<P::ApiKey>(role, model_fields.fields(role)),
            EntityRole::DeviceCode => plugin::<P::DeviceCode>(role, model_fields.fields(role)),
            EntityRole::Passkey => plugin::<P::Passkey>(role, model_fields.fields(role)),
            EntityRole::TwoFactor => plugin::<P::TwoFactor>(role, model_fields.fields(role)),
            EntityRole::Jwk => plugin::<P::Jwk>(role, model_fields.fields(role)),
            EntityRole::WalletAddress => {
                plugin::<P::WalletAddress>(role, model_fields.fields(role))
            }
            EntityRole::RateLimit => plugin::<P::RateLimit>(role, model_fields.fields(role)),
        })
        .collect()
}
