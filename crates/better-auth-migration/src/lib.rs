pub use sea_orm_migration::prelude::*;

mod m20240101_000000_create_core_tables;
mod m20240101_000001_create_organization_tables;

pub use m20240101_000000_create_core_tables::{Accounts, Sessions, Users};
pub use m20240101_000001_create_organization_tables::{Invitation, Member, Organization};

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20240101_000000_create_core_tables::Migration),
            Box::new(m20240101_000001_create_organization_tables::Migration),
        ]
    }
}
