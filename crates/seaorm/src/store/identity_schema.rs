use sea_orm_migration::prelude::*;

use super::entities::{user, wallet_address};

pub(super) struct IdentitySchema;
impl MigrationName for IdentitySchema {
    fn name(&self) -> &str {
        "m20260930_000004_identity_plugins"
    }
}
#[async_trait::async_trait]
impl MigrationTrait for IdentitySchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in [
            ColumnDef::new(user::Column::IsAnonymous)
                .boolean()
                .null()
                .to_owned(),
            ColumnDef::new(user::Column::PhoneNumber)
                .string()
                .null()
                .to_owned(),
            ColumnDef::new(user::Column::PhoneNumberVerified)
                .boolean()
                .null()
                .to_owned(),
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(user::Entity)
                        .add_column(column)
                        .to_owned(),
                )
                .await?;
        }
        manager
            .create_index(
                Index::create()
                    .name("idx_users_phone_number")
                    .table(user::Entity)
                    .col(user::Column::PhoneNumber)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(wallet_address::Entity)
                    .col(
                        ColumnDef::new(wallet_address::Column::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(wallet_address::Column::UserId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(wallet_address::Column::Address)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(wallet_address::Column::ChainId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(wallet_address::Column::IsPrimary)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(wallet_address::Column::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_wallet_address_user")
                            .from(wallet_address::Entity, wallet_address::Column::UserId)
                            .to(user::Entity, user::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_wallet_address_user")
                    .table(wallet_address::Entity)
                    .col(wallet_address::Column::UserId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(wallet_address::Entity).to_owned())
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .table(user::Entity)
                    .name("idx_users_phone_number")
                    .to_owned(),
            )
            .await?;
        for column in [
            user::Column::IsAnonymous,
            user::Column::PhoneNumber,
            user::Column::PhoneNumberVerified,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(user::Entity)
                        .drop_column(column)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
