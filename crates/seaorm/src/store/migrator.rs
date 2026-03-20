//! Shared auth schema migrations using sea-orm-migration.

use sea_orm::EntityName;
use sea_orm::sea_query::IntoIden;
use sea_orm_migration::prelude::*;

use super::entities::{
    account, api_key, invitation, member, organization, passkey, session, two_factor, user,
    verification,
};

pub struct AuthMigrator;

#[async_trait::async_trait]
impl MigratorTrait for AuthMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(InitialAuthSchema)]
    }

    fn migration_table_name() -> sea_orm::DynIden {
        "better_auth_migrations".into_iden()
    }
}

pub async fn run_migrations(db: &sea_orm::DatabaseConnection) -> Result<(), DbErr> {
    AuthMigrator::up(db, None).await
}

#[derive(DeriveMigrationName)]
struct InitialAuthSchema;

#[async_trait::async_trait]
impl MigrationTrait for InitialAuthSchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_users(manager).await?;
        create_sessions(manager).await?;
        create_accounts(manager).await?;
        create_verifications(manager).await?;
        create_organizations(manager).await?;
        create_members(manager).await?;
        create_invitations(manager).await?;
        create_two_factor(manager).await?;
        create_api_keys(manager).await?;
        create_passkeys(manager).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in [
            passkey::Entity.table_ref(),
            api_key::Entity.table_ref(),
            two_factor::Entity.table_ref(),
            invitation::Entity.table_ref(),
            member::Entity.table_ref(),
            organization::Entity.table_ref(),
            verification::Entity.table_ref(),
            account::Entity.table_ref(),
            session::Entity.table_ref(),
            user::Entity.table_ref(),
        ] {
            manager
                .drop_table(Table::drop().table(table).if_exists().to_owned())
                .await?;
        }
        Ok(())
    }
}

async fn create_users(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(user::Entity)
                .if_not_exists()
                .col(
                    ColumnDef::new(user::Column::Id)
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(user::Column::Name).string())
                .col(ColumnDef::new(user::Column::Email).string().unique_key())
                .col(
                    ColumnDef::new(user::Column::EmailVerified)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(ColumnDef::new(user::Column::Image).string())
                .col(ColumnDef::new(user::Column::Username).string().unique_key())
                .col(ColumnDef::new(user::Column::DisplayUsername).string())
                .col(
                    ColumnDef::new(user::Column::TwoFactorEnabled)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(ColumnDef::new(user::Column::Role).string())
                .col(
                    ColumnDef::new(user::Column::Banned)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(ColumnDef::new(user::Column::BanReason).string())
                .col(ColumnDef::new(user::Column::BanExpires).timestamp_with_time_zone())
                .col(
                    ColumnDef::new(user::Column::Metadata)
                        .json_binary()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(user::Column::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(user::Column::UpdatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("idx_users_email")
                .table(user::Entity)
                .col(user::Column::Email)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_users_username")
                .table(user::Entity)
                .col(user::Column::Username)
                .to_owned(),
        )
        .await?;
    Ok(())
}

async fn create_sessions(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(session::Entity)
                .if_not_exists()
                .col(
                    ColumnDef::new(session::Column::Id)
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(session::Column::ExpiresAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(session::Column::Token)
                        .string()
                        .not_null()
                        .unique_key(),
                )
                .col(ColumnDef::new(session::Column::IpAddress).string())
                .col(ColumnDef::new(session::Column::UserAgent).string())
                .col(ColumnDef::new(session::Column::UserId).string().not_null())
                .col(ColumnDef::new(session::Column::ImpersonatedBy).string())
                .col(ColumnDef::new(session::Column::ActiveOrganizationId).string())
                .col(
                    ColumnDef::new(session::Column::Active)
                        .boolean()
                        .not_null()
                        .default(true),
                )
                .col(
                    ColumnDef::new(session::Column::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(session::Column::UpdatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_sessions_user_id")
                        .from(session::Entity, session::Column::UserId)
                        .to(user::Entity, user::Column::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    for (name, column) in [
        ("idx_sessions_token", session::Column::Token),
        ("idx_sessions_user_id", session::Column::UserId),
        ("idx_sessions_expires_at", session::Column::ExpiresAt),
    ] {
        manager
            .create_index(
                Index::create()
                    .name(name)
                    .table(session::Entity)
                    .col(column)
                    .to_owned(),
            )
            .await?;
    }

    Ok(())
}

async fn create_accounts(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(account::Entity)
                .if_not_exists()
                .col(
                    ColumnDef::new(account::Column::Id)
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(account::Column::AccountId)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(account::Column::ProviderId)
                        .string()
                        .not_null(),
                )
                .col(ColumnDef::new(account::Column::UserId).string().not_null())
                .col(ColumnDef::new(account::Column::AccessToken).string())
                .col(ColumnDef::new(account::Column::RefreshToken).string())
                .col(ColumnDef::new(account::Column::IdToken).string())
                .col(
                    ColumnDef::new(account::Column::AccessTokenExpiresAt)
                        .timestamp_with_time_zone(),
                )
                .col(
                    ColumnDef::new(account::Column::RefreshTokenExpiresAt)
                        .timestamp_with_time_zone(),
                )
                .col(ColumnDef::new(account::Column::Scope).string())
                .col(ColumnDef::new(account::Column::Password).string())
                .col(
                    ColumnDef::new(account::Column::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(account::Column::UpdatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_accounts_user_id")
                        .from(account::Entity, account::Column::UserId)
                        .to(user::Entity, user::Column::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("idx_accounts_user_id")
                .table(account::Entity)
                .col(account::Column::UserId)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_accounts_provider_account")
                .table(account::Entity)
                .col(account::Column::ProviderId)
                .col(account::Column::AccountId)
                .unique()
                .to_owned(),
        )
        .await?;

    Ok(())
}

async fn create_verifications(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(verification::Entity)
                .if_not_exists()
                .col(
                    ColumnDef::new(verification::Column::Id)
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(verification::Column::Identifier)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(verification::Column::Value)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(verification::Column::ExpiresAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(verification::Column::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(verification::Column::UpdatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("idx_verifications_identifier")
                .table(verification::Entity)
                .col(verification::Column::Identifier)
                .to_owned(),
        )
        .await?;
    Ok(())
}

async fn create_organizations(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(organization::Entity)
                .if_not_exists()
                .col(
                    ColumnDef::new(organization::Column::Id)
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(organization::Column::Name)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(organization::Column::Slug)
                        .string()
                        .not_null()
                        .unique_key(),
                )
                .col(ColumnDef::new(organization::Column::Logo).string())
                .col(
                    ColumnDef::new(organization::Column::Metadata)
                        .json_binary()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(organization::Column::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(organization::Column::UpdatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("idx_organization_slug")
                .table(organization::Entity)
                .col(organization::Column::Slug)
                .to_owned(),
        )
        .await?;
    Ok(())
}

async fn create_members(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(member::Entity)
                .if_not_exists()
                .col(
                    ColumnDef::new(member::Column::Id)
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(member::Column::OrganizationId)
                        .string()
                        .not_null(),
                )
                .col(ColumnDef::new(member::Column::UserId).string().not_null())
                .col(ColumnDef::new(member::Column::Role).string().not_null())
                .col(
                    ColumnDef::new(member::Column::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_member_organization_id")
                        .from(member::Entity, member::Column::OrganizationId)
                        .to(organization::Entity, organization::Column::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_member_user_id")
                        .from(member::Entity, member::Column::UserId)
                        .to(user::Entity, user::Column::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("idx_member_organization_id")
                .table(member::Entity)
                .col(member::Column::OrganizationId)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_member_user_id")
                .table(member::Entity)
                .col(member::Column::UserId)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_member_org_user_unique")
                .table(member::Entity)
                .col(member::Column::OrganizationId)
                .col(member::Column::UserId)
                .unique()
                .to_owned(),
        )
        .await?;
    Ok(())
}

async fn create_invitations(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(invitation::Entity)
                .if_not_exists()
                .col(
                    ColumnDef::new(invitation::Column::Id)
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(invitation::Column::OrganizationId)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(invitation::Column::Email)
                        .string()
                        .not_null(),
                )
                .col(ColumnDef::new(invitation::Column::Role).string().not_null())
                .col(
                    ColumnDef::new(invitation::Column::Status)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(invitation::Column::InviterId)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(invitation::Column::ExpiresAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(invitation::Column::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_invitation_organization_id")
                        .from(invitation::Entity, invitation::Column::OrganizationId)
                        .to(organization::Entity, organization::Column::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_invitation_inviter_id")
                        .from(invitation::Entity, invitation::Column::InviterId)
                        .to(user::Entity, user::Column::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    for (name, column) in [
        (
            "idx_invitation_organization_id",
            invitation::Column::OrganizationId,
        ),
        ("idx_invitation_email", invitation::Column::Email),
        ("idx_invitation_status", invitation::Column::Status),
    ] {
        manager
            .create_index(
                Index::create()
                    .name(name)
                    .table(invitation::Entity)
                    .col(column)
                    .to_owned(),
            )
            .await?;
    }
    Ok(())
}

async fn create_two_factor(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(two_factor::Entity)
                .if_not_exists()
                .col(
                    ColumnDef::new(two_factor::Column::Id)
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(two_factor::Column::Secret)
                        .string()
                        .not_null(),
                )
                .col(ColumnDef::new(two_factor::Column::BackupCodes).string())
                .col(
                    ColumnDef::new(two_factor::Column::UserId)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(two_factor::Column::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(two_factor::Column::UpdatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_two_factor_user_id")
                        .from(two_factor::Entity, two_factor::Column::UserId)
                        .to(user::Entity, user::Column::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("idx_two_factor_user_id")
                .table(two_factor::Entity)
                .col(two_factor::Column::UserId)
                .unique()
                .to_owned(),
        )
        .await?;
    Ok(())
}

async fn create_api_keys(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(api_key::Entity)
                .if_not_exists()
                .col(
                    ColumnDef::new(api_key::Column::Id)
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(api_key::Column::Name).string())
                .col(ColumnDef::new(api_key::Column::Start).string())
                .col(ColumnDef::new(api_key::Column::Prefix).string())
                .col(
                    ColumnDef::new(api_key::Column::KeyHash)
                        .string()
                        .not_null()
                        .unique_key(),
                )
                .col(ColumnDef::new(api_key::Column::UserId).string().not_null())
                .col(ColumnDef::new(api_key::Column::RefillInterval).integer())
                .col(ColumnDef::new(api_key::Column::RefillAmount).integer())
                .col(ColumnDef::new(api_key::Column::LastRefillAt).timestamp_with_time_zone())
                .col(
                    ColumnDef::new(api_key::Column::Enabled)
                        .boolean()
                        .not_null()
                        .default(true),
                )
                .col(
                    ColumnDef::new(api_key::Column::RateLimitEnabled)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(ColumnDef::new(api_key::Column::RateLimitTimeWindow).integer())
                .col(ColumnDef::new(api_key::Column::RateLimitMax).integer())
                .col(ColumnDef::new(api_key::Column::RequestCount).integer())
                .col(ColumnDef::new(api_key::Column::Remaining).integer())
                .col(ColumnDef::new(api_key::Column::LastRequest).timestamp_with_time_zone())
                .col(ColumnDef::new(api_key::Column::ExpiresAt).timestamp_with_time_zone())
                .col(
                    ColumnDef::new(api_key::Column::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(api_key::Column::UpdatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(ColumnDef::new(api_key::Column::Permissions).string())
                .col(ColumnDef::new(api_key::Column::Metadata).string())
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_api_keys_user_id")
                        .from(api_key::Entity, api_key::Column::UserId)
                        .to(user::Entity, user::Column::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("idx_api_keys_user_id")
                .table(api_key::Entity)
                .col(api_key::Column::UserId)
                .to_owned(),
        )
        .await?;
    Ok(())
}

async fn create_passkeys(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(passkey::Entity)
                .if_not_exists()
                .col(
                    ColumnDef::new(passkey::Column::Id)
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(passkey::Column::Name).string().not_null())
                .col(
                    ColumnDef::new(passkey::Column::PublicKey)
                        .string()
                        .not_null(),
                )
                .col(ColumnDef::new(passkey::Column::UserId).string().not_null())
                .col(
                    ColumnDef::new(passkey::Column::CredentialId)
                        .string()
                        .not_null()
                        .unique_key(),
                )
                .col(
                    ColumnDef::new(passkey::Column::Counter)
                        .big_integer()
                        .not_null()
                        .default(0),
                )
                .col(
                    ColumnDef::new(passkey::Column::DeviceType)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(passkey::Column::BackedUp)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(ColumnDef::new(passkey::Column::Transports).string())
                .col(
                    ColumnDef::new(passkey::Column::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_passkeys_user_id")
                        .from(passkey::Entity, passkey::Column::UserId)
                        .to(user::Entity, user::Column::Id)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("idx_passkeys_user_id")
                .table(passkey::Entity)
                .col(passkey::Column::UserId)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_passkeys_credential_id")
                .table(passkey::Entity)
                .col(passkey::Column::CredentialId)
                .to_owned(),
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;

    #[derive(DeriveIden)]
    enum Todo {
        Table,
        Id,
        Title,
    }

    #[derive(DeriveMigrationName)]
    struct CreateTodoTable;

    #[async_trait::async_trait]
    impl MigrationTrait for CreateTodoTable {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .create_table(
                    Table::create()
                        .table(Todo::Table)
                        .if_not_exists()
                        .col(ColumnDef::new(Todo::Id).integer().not_null().primary_key())
                        .col(ColumnDef::new(Todo::Title).string().not_null())
                        .to_owned(),
                )
                .await
        }

        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .drop_table(Table::drop().table(Todo::Table).if_exists().to_owned())
                .await
        }
    }

    struct AppMigrator;

    #[async_trait::async_trait]
    impl MigratorTrait for AppMigrator {
        fn migrations() -> Vec<Box<dyn MigrationTrait>> {
            vec![Box::new(CreateTodoTable)]
        }
    }

    // Rust-specific surface: Better Auth owns a separate SeaORM migration table so app migrators can keep the default `seaql_migrations`.
    #[tokio::test]
    async fn auth_migrator_uses_namespaced_history_table() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        run_migrations(&database).await.unwrap();

        let manager = SchemaManager::new(&database);
        assert!(manager.has_table("better_auth_migrations").await.unwrap());
        assert!(!manager.has_table("seaql_migrations").await.unwrap());
    }

    // Rust-specific surface: Better Auth migration composition with app-owned SeaORM migrations is a Rust integration concern with no direct TS analogue.
    #[tokio::test]
    async fn auth_and_app_migrators_can_run_against_the_same_database() {
        let database = Database::connect("sqlite::memory:").await.unwrap();

        AppMigrator::up(&database, None).await.unwrap();
        AuthMigrator::up(&database, None).await.unwrap();

        let manager = SchemaManager::new(&database);
        assert!(manager.has_table("seaql_migrations").await.unwrap());
        assert!(manager.has_table("better_auth_migrations").await.unwrap());
        assert!(manager.has_table("todo").await.unwrap());
        assert!(manager.has_table(user::Entity.table_name()).await.unwrap());
    }
}
