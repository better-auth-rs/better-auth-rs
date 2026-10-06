use sea_orm_migration::prelude::*;

use super::entities::two_factor::{Column, Entity};

pub(super) struct TwoFactorSecurity;

impl MigrationName for TwoFactorSecurity {
    fn name(&self) -> &str {
        "m20260930_000002_two_factor_security"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for TwoFactorSecurity {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in [
            ColumnDef::new(Column::Verified)
                .boolean()
                .not_null()
                .default(true)
                .to_owned(),
            ColumnDef::new(Column::FailedVerificationCount)
                .big_integer()
                .not_null()
                .default(0)
                .to_owned(),
            ColumnDef::new(Column::LockedUntil)
                .timestamp_with_time_zone()
                .null()
                .to_owned(),
        ] {
            manager
                .alter_table(Table::alter().table(Entity).add_column(column).to_owned())
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in [
            Column::LockedUntil,
            Column::FailedVerificationCount,
            Column::Verified,
        ] {
            manager
                .alter_table(Table::alter().table(Entity).drop_column(column).to_owned())
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{SeaOrmStore, bundled_schema::BundledSchema};
    use better_auth_core::{AuthConfig, store::TwoFactorStore};
    use sea_orm::{ConnectionTrait, Database};

    #[tokio::test]
    async fn existing_authenticators_remain_verified_and_gain_failure_tracking() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let _ = database.execute_unprepared(
            "CREATE TABLE two_factor (
                id TEXT PRIMARY KEY, secret TEXT NOT NULL, backup_codes TEXT NOT NULL,
                user_id TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            INSERT INTO two_factor VALUES ('existing', 'encrypted-secret', 'encrypted-codes', 'owner',
                '2026-09-30T00:00:00Z', '2026-09-30T00:00:00Z')",
        ).await.unwrap();
        TwoFactorSecurity
            .up(&SchemaManager::new(&database))
            .await
            .unwrap();
        let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::new("test-secret"), database);
        let factor = store
            .get_two_factor_by_user_id("owner")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(factor.verified, Some(true));
        assert_eq!(factor.secret, "encrypted-secret");
        assert_eq!(factor.backup_codes, "encrypted-codes");
        assert_eq!(factor.failed_verification_count, Some(0));
        assert!(factor.locked_until.is_none());
        store
            .record_two_factor_failure(&factor.id, 1, &|| {
                Ok(chrono::Utc::now() + chrono::Duration::minutes(15))
            })
            .await
            .unwrap();
        let factor = store
            .get_two_factor_by_user_id("owner")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(factor.failed_verification_count, Some(1));
        assert!(factor.locked_until.is_some());
    }
}
