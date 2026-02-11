use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Users
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Users::Id).text().not_null().primary_key())
                    .col(ColumnDef::new(Users::Name).text())
                    .col(ColumnDef::new(Users::Email).text().unique_key())
                    .col(
                        ColumnDef::new(Users::EmailVerified)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(Users::Image).text())
                    .col(ColumnDef::new(Users::Username).text().unique_key())
                    .col(ColumnDef::new(Users::DisplayUsername).text())
                    .col(
                        ColumnDef::new(Users::TwoFactorEnabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(Users::Role).text())
                    .col(
                        ColumnDef::new(Users::Banned)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(Users::BanReason).text())
                    .col(ColumnDef::new(Users::BanExpires).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(Users::Metadata)
                            .json_binary()
                            .not_null()
                            .default(Expr::cust("'{}'::jsonb")),
                    )
                    .col(
                        ColumnDef::new(Users::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    .col(
                        ColumnDef::new(Users::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    // SaaS custom columns
                    .col(
                        ColumnDef::new(Users::Plan)
                            .text()
                            .not_null()
                            .default("free"),
                    )
                    .col(ColumnDef::new(Users::StripeCustomerId).text())
                    .col(ColumnDef::new(Users::Phone).text())
                    .to_owned(),
            )
            .await?;

        // Sessions
        manager
            .create_table(
                Table::create()
                    .table(Sessions::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Sessions::Id).text().not_null().primary_key())
                    .col(
                        ColumnDef::new(Sessions::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Sessions::Token)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Sessions::IpAddress).text())
                    .col(ColumnDef::new(Sessions::UserAgent).text())
                    .col(ColumnDef::new(Sessions::UserId).text().not_null())
                    .col(ColumnDef::new(Sessions::ImpersonatedBy).text())
                    .col(ColumnDef::new(Sessions::ActiveOrganizationId).text())
                    .col(
                        ColumnDef::new(Sessions::Active)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(Sessions::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    .col(
                        ColumnDef::new(Sessions::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    // SaaS custom columns
                    .col(ColumnDef::new(Sessions::DeviceId).text())
                    .col(ColumnDef::new(Sessions::Country).text())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Sessions::Table, Sessions::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Accounts
        manager
            .create_table(
                Table::create()
                    .table(Accounts::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Accounts::Id).text().not_null().primary_key())
                    .col(ColumnDef::new(Accounts::AccountId).text().not_null())
                    .col(ColumnDef::new(Accounts::ProviderId).text().not_null())
                    .col(ColumnDef::new(Accounts::UserId).text().not_null())
                    .col(ColumnDef::new(Accounts::AccessToken).text())
                    .col(ColumnDef::new(Accounts::RefreshToken).text())
                    .col(ColumnDef::new(Accounts::IdToken).text())
                    .col(
                        ColumnDef::new(Accounts::AccessTokenExpiresAt)
                            .timestamp_with_time_zone(),
                    )
                    .col(
                        ColumnDef::new(Accounts::RefreshTokenExpiresAt)
                            .timestamp_with_time_zone(),
                    )
                    .col(ColumnDef::new(Accounts::Scope).text())
                    .col(ColumnDef::new(Accounts::Password).text())
                    .col(
                        ColumnDef::new(Accounts::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    .col(
                        ColumnDef::new(Accounts::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Accounts::Table, Accounts::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Unique constraint on (provider_id, account_id)
        manager
            .create_index(
                Index::create()
                    .name("idx_accounts_provider_account")
                    .table(Accounts::Table)
                    .col(Accounts::ProviderId)
                    .col(Accounts::AccountId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Verifications
        manager
            .create_table(
                Table::create()
                    .table(Verifications::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Verifications::Id)
                            .text()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Verifications::Identifier).text().not_null())
                    .col(ColumnDef::new(Verifications::Value).text().not_null())
                    .col(
                        ColumnDef::new(Verifications::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Verifications::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    .col(
                        ColumnDef::new(Verifications::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    .to_owned(),
            )
            .await?;

        // Organization
        manager
            .create_table(
                Table::create()
                    .table(Organization::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Organization::Id)
                            .text()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Organization::Name).text().not_null())
                    .col(
                        ColumnDef::new(Organization::Slug)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Organization::Logo).text())
                    .col(
                        ColumnDef::new(Organization::Metadata)
                            .json_binary()
                            .not_null()
                            .default(Expr::cust("'{}'::jsonb")),
                    )
                    .col(
                        ColumnDef::new(Organization::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    .col(
                        ColumnDef::new(Organization::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    // SaaS custom columns
                    .col(ColumnDef::new(Organization::BillingEmail).text())
                    .col(
                        ColumnDef::new(Organization::Plan)
                            .text()
                            .not_null()
                            .default("free"),
                    )
                    .to_owned(),
            )
            .await?;

        // Member
        manager
            .create_table(
                Table::create()
                    .table(Member::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Member::Id).text().not_null().primary_key())
                    .col(ColumnDef::new(Member::OrganizationId).text().not_null())
                    .col(ColumnDef::new(Member::UserId).text().not_null())
                    .col(
                        ColumnDef::new(Member::Role)
                            .text()
                            .not_null()
                            .default("member"),
                    )
                    .col(
                        ColumnDef::new(Member::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Member::Table, Member::OrganizationId)
                            .to(Organization::Table, Organization::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Member::Table, Member::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Unique constraint on (organization_id, user_id)
        manager
            .create_index(
                Index::create()
                    .name("idx_member_org_user")
                    .table(Member::Table)
                    .col(Member::OrganizationId)
                    .col(Member::UserId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Invitation
        manager
            .create_table(
                Table::create()
                    .table(Invitation::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Invitation::Id)
                            .text()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Invitation::OrganizationId).text().not_null())
                    .col(ColumnDef::new(Invitation::Email).text().not_null())
                    .col(
                        ColumnDef::new(Invitation::Role)
                            .text()
                            .not_null()
                            .default("member"),
                    )
                    .col(
                        ColumnDef::new(Invitation::Status)
                            .text()
                            .not_null()
                            .default("pending"),
                    )
                    .col(ColumnDef::new(Invitation::InviterId).text().not_null())
                    .col(
                        ColumnDef::new(Invitation::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Invitation::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Invitation::Table, Invitation::OrganizationId)
                            .to(Organization::Table, Organization::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Invitation::Table, Invitation::InviterId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Indexes
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
                    .name("idx_accounts_user_id")
                    .table(Accounts::Table)
                    .col(Accounts::UserId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_organization_slug")
                    .table(Organization::Table)
                    .col(Organization::Slug)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_invitation_org")
                    .table(Invitation::Table)
                    .col(Invitation::OrganizationId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Invitation::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Member::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Organization::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Verifications::Table).to_owned())
            .await?;
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

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Name,
    Email,
    EmailVerified,
    Image,
    Username,
    DisplayUsername,
    TwoFactorEnabled,
    Role,
    Banned,
    BanReason,
    BanExpires,
    Metadata,
    CreatedAt,
    UpdatedAt,
    Plan,
    StripeCustomerId,
    Phone,
}

#[derive(DeriveIden)]
enum Sessions {
    Table,
    Id,
    ExpiresAt,
    Token,
    IpAddress,
    UserAgent,
    UserId,
    ImpersonatedBy,
    ActiveOrganizationId,
    Active,
    CreatedAt,
    UpdatedAt,
    DeviceId,
    Country,
}

#[derive(DeriveIden)]
enum Accounts {
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

#[derive(DeriveIden)]
enum Verifications {
    Table,
    Id,
    Identifier,
    Value,
    ExpiresAt,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Organization {
    Table,
    Id,
    Name,
    Slug,
    Logo,
    Metadata,
    CreatedAt,
    UpdatedAt,
    BillingEmail,
    Plan,
}

#[derive(DeriveIden)]
enum Member {
    Table,
    Id,
    OrganizationId,
    UserId,
    Role,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Invitation {
    Table,
    Id,
    OrganizationId,
    Email,
    Role,
    Status,
    InviterId,
    ExpiresAt,
    CreatedAt,
}
