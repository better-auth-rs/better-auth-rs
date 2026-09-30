use super::entities::{organization_role, team, team_member};
use sea_orm::sea_query::{Alias, ColumnDef, ForeignKey, ForeignKeyAction, Index, Table};
use sea_orm_migration::prelude::*;

pub(super) struct OrganizationExtensions;
impl MigrationName for OrganizationExtensions {
    fn name(&self) -> &str {
        "m20260930_000002_organization_extensions"
    }
}
#[async_trait::async_trait]
impl MigrationTrait for OrganizationExtensions {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = sea_orm::Schema::new(manager.get_database_backend());
        for (mut table, name, references) in [
            (
                schema.create_table_from_entity(team::Entity),
                "team",
                vec![("organization_id", "organization")],
            ),
            (
                schema.create_table_from_entity(team_member::Entity),
                "team_member",
                vec![("team_id", "team"), ("user_id", "users")],
            ),
            (
                schema.create_table_from_entity(organization_role::Entity),
                "organization_role",
                vec![("organization_id", "organization")],
            ),
        ] {
            for (column, target) in references {
                let _ = table.foreign_key(
                    ForeignKey::create()
                        .name(format!("fk_{name}_{column}"))
                        .from(Alias::new(name), Alias::new(column))
                        .to(Alias::new(target), Alias::new("id"))
                        .on_delete(ForeignKeyAction::Cascade),
                );
            }
            manager.create_table(table.to_owned()).await?;
        }
        for (table, columns) in [("team_member", ["team_id", "user_id"])] {
            manager
                .create_index(
                    Index::create()
                        .name(format!("idx_{table}_identity"))
                        .table(Alias::new(table))
                        .col(Alias::new(columns[0]))
                        .col(Alias::new(columns[1]))
                        .unique()
                        .to_owned(),
                )
                .await?;
        }
        for (table, column) in [
            ("team", "organization_id"),
            ("team_member", "user_id"),
            ("organization_role", "organization_id"),
            ("organization_role", "role"),
        ] {
            manager
                .create_index(
                    Index::create()
                        .name(format!("idx_{table}_{column}"))
                        .table(Alias::new(table))
                        .col(Alias::new(column))
                        .to_owned(),
                )
                .await?;
        }
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sessions"))
                    .add_column(ColumnDef::new(Alias::new("active_team_id")).string())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("invitation"))
                    .add_column(ColumnDef::new(Alias::new("team_id")).string())
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
