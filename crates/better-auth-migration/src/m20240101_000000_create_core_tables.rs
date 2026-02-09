use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Users table
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Users::Id)
                            .string_len(255)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Users::Email).string_len(255).unique_key())
                    .col(ColumnDef::new(Users::Name).string_len(255))
                    .col(ColumnDef::new(Users::Username).string_len(255).unique_key())
                    .col(ColumnDef::new(Users::DisplayUsername).string_len(255))
                    .col(ColumnDef::new(Users::Image).text())
                    .col(
                        ColumnDef::new(Users::EmailVerified)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(Users::TwoFactorEnabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(Users::Role).string_len(255))
                    .col(
                        ColumnDef::new(Users::Banned)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(Users::BanReason).text())
                    .col(ColumnDef::new(Users::BanExpires).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(Users::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Users::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Users::Metadata)
                            .json_binary()
                            .not_null()
                            .default("{}"),
                    )
                    .to_owned(),
            )
            .await?;

        // Users indexes
        manager
            .create_index(
                Index::create()
                    .name("idx_users_email")
                    .table(Users::Table)
                    .col(Users::Email)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_users_username")
                    .table(Users::Table)
                    .col(Users::Username)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_users_created_at")
                    .table(Users::Table)
                    .col(Users::CreatedAt)
                    .to_owned(),
            )
            .await?;

        // Sessions table
        manager
            .create_table(
                Table::create()
                    .table(Sessions::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Sessions::Id)
                            .string_len(255)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Sessions::UserId).string_len(255).not_null())
                    .col(
                        ColumnDef::new(Sessions::Token)
                            .string_len(255)
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Sessions::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Sessions::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Sessions::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(Sessions::IpAddress).string_len(45))
                    .col(ColumnDef::new(Sessions::UserAgent).text())
                    .col(
                        ColumnDef::new(Sessions::Active)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(Sessions::ImpersonatedBy).string_len(255))
                    .col(ColumnDef::new(Sessions::ActiveOrganizationId).string_len(255))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_sessions_user")
                            .from(Sessions::Table, Sessions::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Sessions indexes
        manager
            .create_index(
                Index::create()
                    .name("idx_sessions_token")
                    .table(Sessions::Table)
                    .col(Sessions::Token)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_sessions_user_id")
                    .table(Sessions::Table)
                    .col(Sessions::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_sessions_expires_at")
                    .table(Sessions::Table)
                    .col(Sessions::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_sessions_active")
                    .table(Sessions::Table)
                    .col(Sessions::Active)
                    .to_owned(),
            )
            .await?;

        // Accounts table (OAuth providers and credentials)
        manager
            .create_table(
                Table::create()
                    .table(Accounts::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Accounts::Id)
                            .string_len(255)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Accounts::AccountId)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Accounts::ProviderId)
                            .string_len(255)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Accounts::UserId).string_len(255).not_null())
                    .col(ColumnDef::new(Accounts::AccessToken).text())
                    .col(ColumnDef::new(Accounts::RefreshToken).text())
                    .col(ColumnDef::new(Accounts::IdToken).text())
                    .col(ColumnDef::new(Accounts::AccessTokenExpiresAt).timestamp_with_time_zone())
                    .col(ColumnDef::new(Accounts::RefreshTokenExpiresAt).timestamp_with_time_zone())
                    .col(ColumnDef::new(Accounts::Scope).text())
                    .col(ColumnDef::new(Accounts::Password).text())
                    .col(
                        ColumnDef::new(Accounts::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Accounts::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_accounts_user")
                            .from(Accounts::Table, Accounts::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Accounts indexes
        manager
            .create_index(
                Index::create()
                    .name("idx_accounts_provider_account_unique")
                    .table(Accounts::Table)
                    .col(Accounts::ProviderId)
                    .col(Accounts::AccountId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_accounts_user_id")
                    .table(Accounts::Table)
                    .col(Accounts::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_accounts_provider_id")
                    .table(Accounts::Table)
                    .col(Accounts::ProviderId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop tables in reverse order (due to foreign key constraints)
        manager
            .drop_table(Table::drop().table(Accounts::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Sessions::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await?;

        Ok(())
    }
}

/// Users table columns
#[derive(DeriveIden)]
pub enum Users {
    Table,
    Id,
    Email,
    Name,
    Username,
    DisplayUsername,
    Image,
    EmailVerified,
    TwoFactorEnabled,
    Role,
    Banned,
    BanReason,
    BanExpires,
    CreatedAt,
    UpdatedAt,
    Metadata,
}

/// Sessions table columns
#[derive(DeriveIden)]
pub enum Sessions {
    Table,
    Id,
    UserId,
    Token,
    ExpiresAt,
    CreatedAt,
    UpdatedAt,
    IpAddress,
    UserAgent,
    Active,
    ImpersonatedBy,
    ActiveOrganizationId,
}

/// Accounts table columns
#[derive(DeriveIden)]
pub enum Accounts {
    Table,
    Id,
    AccountId,
    ProviderId,
    UserId,
    AccessToken,
    RefreshToken,
    IdToken,
    AccessTokenExpiresAt,
    RefreshTokenExpiresAt,
    Scope,
    Password,
    CreatedAt,
    UpdatedAt,
}
