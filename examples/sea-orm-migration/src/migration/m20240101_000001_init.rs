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
                    .table(User::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(User::Id).text().not_null().primary_key())
                    .col(ColumnDef::new(User::Name).text())
                    .col(ColumnDef::new(User::Email).text().unique_key())
                    .col(
                        ColumnDef::new(User::EmailVerified)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(User::Image).text())
                    .col(ColumnDef::new(User::Username).text().unique_key())
                    .col(ColumnDef::new(User::DisplayUsername).text())
                    .col(
                        ColumnDef::new(User::TwoFactorEnabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(User::Role).text())
                    .col(
                        ColumnDef::new(User::Banned)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(User::BanReason).text())
                    .col(ColumnDef::new(User::BanExpires).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(User::Metadata)
                            .json_binary()
                            .not_null()
                            .default(Expr::cust("'{}'::jsonb")),
                    )
                    .col(
                        ColumnDef::new(User::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    .col(
                        ColumnDef::new(User::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    // SaaS custom columns
                    .col(
                        ColumnDef::new(User::Plan)
                            .text()
                            .not_null()
                            .default("free"),
                    )
                    .col(ColumnDef::new(User::StripeCustomerId).text())
                    .col(ColumnDef::new(User::Phone).text())
                    .to_owned(),
            )
            .await?;

        // Sessions
        manager
            .create_table(
                Table::create()
                    .table(Session::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Session::Id).text().not_null().primary_key())
                    .col(
                        ColumnDef::new(Session::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Session::Token)
                            .text()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Session::IpAddress).text())
                    .col(ColumnDef::new(Session::UserAgent).text())
                    .col(ColumnDef::new(Session::UserId).text().not_null())
                    .col(ColumnDef::new(Session::ImpersonatedBy).text())
                    .col(ColumnDef::new(Session::ActiveOrganizationId).text())
                    .col(
                        ColumnDef::new(Session::Active)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(Session::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    .col(
                        ColumnDef::new(Session::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    // SaaS custom columns
                    .col(ColumnDef::new(Session::DeviceId).text())
                    .col(ColumnDef::new(Session::Country).text())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Session::Table, Session::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Accounts
        manager
            .create_table(
                Table::create()
                    .table(Account::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Account::Id).text().not_null().primary_key())
                    .col(ColumnDef::new(Account::AccountId).text().not_null())
                    .col(ColumnDef::new(Account::ProviderId).text().not_null())
                    .col(ColumnDef::new(Account::UserId).text().not_null())
                    .col(ColumnDef::new(Account::AccessToken).text())
                    .col(ColumnDef::new(Account::RefreshToken).text())
                    .col(ColumnDef::new(Account::IdToken).text())
                    .col(
                        ColumnDef::new(Account::AccessTokenExpiresAt)
                            .timestamp_with_time_zone(),
                    )
                    .col(
                        ColumnDef::new(Account::RefreshTokenExpiresAt)
                            .timestamp_with_time_zone(),
                    )
                    .col(ColumnDef::new(Account::Scope).text())
                    .col(ColumnDef::new(Account::Password).text())
                    .col(
                        ColumnDef::new(Account::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    .col(
                        ColumnDef::new(Account::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Account::Table, Account::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Unique constraint on (provider_id, account_id)
        manager
            .create_index(
                Index::create()
                    .name("idx_account_provider_account")
                    .table(Account::Table)
                    .col(Account::ProviderId)
                    .col(Account::AccountId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Verifications
        manager
            .create_table(
                Table::create()
                    .table(Verification::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Verification::Id)
                            .text()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Verification::Identifier).text().not_null())
                    .col(ColumnDef::new(Verification::Value).text().not_null())
                    .col(
                        ColumnDef::new(Verification::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Verification::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::cust("NOW()")),
                    )
                    .col(
                        ColumnDef::new(Verification::UpdatedAt)
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
                            .to(User::Table, User::Id)
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
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Indexes
        manager
            .create_index(
                Index::create()
                    .name("idx_user_email")
                    .table(User::Table)
                    .col(User::Email)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_session_token")
                    .table(Session::Table)
                    .col(Session::Token)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_session_user_id")
                    .table(Session::Table)
                    .col(Session::UserId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_account_user_id")
                    .table(Account::Table)
                    .col(Account::UserId)
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
            .drop_table(Table::drop().table(Verification::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Account::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Session::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(User::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum User {
    Table,
    Id,
    Name,
    Email,
    #[sea_orm(iden = "emailVerified")]
    EmailVerified,
    Image,
    Username,
    #[sea_orm(iden = "displayUsername")]
    DisplayUsername,
    #[sea_orm(iden = "twoFactorEnabled")]
    TwoFactorEnabled,
    Role,
    Banned,
    #[sea_orm(iden = "banReason")]
    BanReason,
    #[sea_orm(iden = "banExpires")]
    BanExpires,
    Metadata,
    #[sea_orm(iden = "createdAt")]
    CreatedAt,
    #[sea_orm(iden = "updatedAt")]
    UpdatedAt,
    Plan,
    StripeCustomerId,
    Phone,
}

#[derive(DeriveIden)]
enum Session {
    Table,
    Id,
    #[sea_orm(iden = "expiresAt")]
    ExpiresAt,
    Token,
    #[sea_orm(iden = "ipAddress")]
    IpAddress,
    #[sea_orm(iden = "userAgent")]
    UserAgent,
    #[sea_orm(iden = "userId")]
    UserId,
    #[sea_orm(iden = "impersonatedBy")]
    ImpersonatedBy,
    #[sea_orm(iden = "activeOrganizationId")]
    ActiveOrganizationId,
    Active,
    #[sea_orm(iden = "createdAt")]
    CreatedAt,
    #[sea_orm(iden = "updatedAt")]
    UpdatedAt,
    DeviceId,
    Country,
}

#[derive(DeriveIden)]
enum Account {
    Table,
    Id,
    #[sea_orm(iden = "accountId")]
    AccountId,
    #[sea_orm(iden = "providerId")]
    ProviderId,
    #[sea_orm(iden = "userId")]
    UserId,
    #[sea_orm(iden = "accessToken")]
    AccessToken,
    #[sea_orm(iden = "refreshToken")]
    RefreshToken,
    #[sea_orm(iden = "idToken")]
    IdToken,
    #[sea_orm(iden = "accessTokenExpiresAt")]
    AccessTokenExpiresAt,
    #[sea_orm(iden = "refreshTokenExpiresAt")]
    RefreshTokenExpiresAt,
    Scope,
    Password,
    #[sea_orm(iden = "createdAt")]
    CreatedAt,
    #[sea_orm(iden = "updatedAt")]
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Verification {
    Table,
    Id,
    Identifier,
    Value,
    #[sea_orm(iden = "expiresAt")]
    ExpiresAt,
    #[sea_orm(iden = "createdAt")]
    CreatedAt,
    #[sea_orm(iden = "updatedAt")]
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
    #[sea_orm(iden = "createdAt")]
    CreatedAt,
    #[sea_orm(iden = "updatedAt")]
    UpdatedAt,
    BillingEmail,
    Plan,
}

#[derive(DeriveIden)]
enum Member {
    Table,
    Id,
    #[sea_orm(iden = "organizationId")]
    OrganizationId,
    #[sea_orm(iden = "userId")]
    UserId,
    Role,
    #[sea_orm(iden = "createdAt")]
    CreatedAt,
}

#[derive(DeriveIden)]
enum Invitation {
    Table,
    Id,
    #[sea_orm(iden = "organizationId")]
    OrganizationId,
    Email,
    Role,
    Status,
    #[sea_orm(iden = "inviterId")]
    InviterId,
    #[sea_orm(iden = "expiresAt")]
    ExpiresAt,
    #[sea_orm(iden = "createdAt")]
    CreatedAt,
}
