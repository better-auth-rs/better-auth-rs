use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Organizations table
        manager
            .create_table(
                Table::create()
                    .table(Organization::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Organization::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Organization::Name).string().not_null())
                    .col(
                        ColumnDef::new(Organization::Slug)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(Organization::Logo).text())
                    .col(
                        ColumnDef::new(Organization::Metadata)
                            .json_binary()
                            .not_null()
                            .default("{}"),
                    )
                    .col(
                        ColumnDef::new(Organization::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Organization::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // Members table
        manager
            .create_table(
                Table::create()
                    .table(Member::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Member::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Member::OrganizationId).uuid().not_null())
                    .col(ColumnDef::new(Member::UserId).uuid().not_null())
                    .col(
                        ColumnDef::new(Member::Role)
                            .string()
                            .not_null()
                            .default("member"),
                    )
                    .col(
                        ColumnDef::new(Member::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_member_organization")
                            .from(Member::Table, Member::OrganizationId)
                            .to(Organization::Table, Organization::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_member_user")
                            .from(Member::Table, Member::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Unique constraint for member (organization_id, user_id)
        manager
            .create_index(
                Index::create()
                    .name("idx_member_org_user_unique")
                    .table(Member::Table)
                    .col(Member::OrganizationId)
                    .col(Member::UserId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Invitations table
        manager
            .create_table(
                Table::create()
                    .table(Invitation::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Invitation::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Invitation::OrganizationId).uuid().not_null())
                    .col(ColumnDef::new(Invitation::Email).string().not_null())
                    .col(
                        ColumnDef::new(Invitation::Role)
                            .string()
                            .not_null()
                            .default("member"),
                    )
                    .col(
                        ColumnDef::new(Invitation::Status)
                            .string()
                            .not_null()
                            .default("pending"),
                    )
                    .col(ColumnDef::new(Invitation::InviterId).uuid().not_null())
                    .col(
                        ColumnDef::new(Invitation::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Invitation::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_invitation_organization")
                            .from(Invitation::Table, Invitation::OrganizationId)
                            .to(Organization::Table, Organization::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_invitation_inviter")
                            .from(Invitation::Table, Invitation::InviterId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Indexes for better query performance
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
                    .name("idx_member_organization_id")
                    .table(Member::Table)
                    .col(Member::OrganizationId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_member_user_id")
                    .table(Member::Table)
                    .col(Member::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_invitation_organization_id")
                    .table(Invitation::Table)
                    .col(Invitation::OrganizationId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_invitation_email")
                    .table(Invitation::Table)
                    .col(Invitation::Email)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_invitation_status")
                    .table(Invitation::Table)
                    .col(Invitation::Status)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop indexes first
        manager
            .drop_index(Index::drop().name("idx_invitation_status").to_owned())
            .await?;
        manager
            .drop_index(Index::drop().name("idx_invitation_email").to_owned())
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_invitation_organization_id")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(Index::drop().name("idx_member_user_id").to_owned())
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_member_organization_id")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(Index::drop().name("idx_organization_slug").to_owned())
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_member_org_user_unique")
                    .to_owned(),
            )
            .await?;

        // Drop tables in reverse order (due to foreign key constraints)
        manager
            .drop_table(Table::drop().table(Invitation::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Member::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Organization::Table).to_owned())
            .await?;

        Ok(())
    }
}

/// Organization table columns
#[derive(DeriveIden)]
pub enum Organization {
    Table,
    Id,
    Name,
    Slug,
    Logo,
    Metadata,
    CreatedAt,
    UpdatedAt,
}

/// Member table columns
#[derive(DeriveIden)]
pub enum Member {
    Table,
    Id,
    OrganizationId,
    UserId,
    Role,
    CreatedAt,
}

/// Invitation table columns
#[derive(DeriveIden)]
pub enum Invitation {
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

/// Reference to users table (assumed to exist)
#[derive(DeriveIden)]
pub enum Users {
    Table,
    Id,
}
