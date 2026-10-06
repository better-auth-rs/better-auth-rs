use better_auth_core::{AuthSchema, store::schema::EntityRole};
use sea_orm::EntityName;

use crate::{
    SeaOrmAccountModel, SeaOrmOrganizationModel, SeaOrmOrganizationSchema, SeaOrmPluginModel,
    SeaOrmPluginSchema, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};

pub(super) fn table_matches<S, O, P>(role: EntityRole, candidate: &str) -> bool
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
    O: SeaOrmOrganizationSchema,
    P: SeaOrmPluginSchema,
{
    match role {
        EntityRole::User => {
            <S::User as SeaOrmUserModel>::Entity::default().table_name() == candidate
        }
        EntityRole::Session => {
            <S::Session as SeaOrmSessionModel>::Entity::default().table_name() == candidate
        }
        EntityRole::Account => {
            <S::Account as SeaOrmAccountModel>::Entity::default().table_name() == candidate
        }
        EntityRole::Verification => {
            <S::Verification as SeaOrmVerificationModel>::Entity::default().table_name()
                == candidate
        }
        EntityRole::Organization => {
            <O::Organization as SeaOrmOrganizationModel>::Entity::default().table_name()
                == candidate
        }
        EntityRole::Member => {
            <O::Member as SeaOrmOrganizationModel>::Entity::default().table_name() == candidate
        }
        EntityRole::Invitation => {
            <O::Invitation as SeaOrmOrganizationModel>::Entity::default().table_name() == candidate
        }
        EntityRole::Team => {
            <O::Team as SeaOrmOrganizationModel>::Entity::default().table_name() == candidate
        }
        EntityRole::TeamMember => {
            <O::TeamMember as SeaOrmOrganizationModel>::Entity::default().table_name() == candidate
        }
        EntityRole::OrganizationRole => {
            <O::OrganizationRole as SeaOrmOrganizationModel>::Entity::default().table_name()
                == candidate
        }
        EntityRole::ApiKey => {
            <P::ApiKey as SeaOrmPluginModel>::Entity::default().table_name() == candidate
        }
        EntityRole::DeviceCode => {
            <P::DeviceCode as SeaOrmPluginModel>::Entity::default().table_name() == candidate
        }
        EntityRole::Passkey => {
            <P::Passkey as SeaOrmPluginModel>::Entity::default().table_name() == candidate
        }
        EntityRole::TwoFactor => {
            <P::TwoFactor as SeaOrmPluginModel>::Entity::default().table_name() == candidate
        }
        EntityRole::Jwk => {
            <P::Jwk as SeaOrmPluginModel>::Entity::default().table_name() == candidate
        }
        EntityRole::WalletAddress => {
            <P::WalletAddress as SeaOrmPluginModel>::Entity::default().table_name() == candidate
        }
        EntityRole::RateLimit => {
            <P::RateLimit as SeaOrmPluginModel>::Entity::default().table_name() == candidate
        }
    }
}
