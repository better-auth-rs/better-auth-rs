use sea_orm::{ConnectionTrait, DatabaseBackend};
use sea_orm_migration::prelude::*;

use super::entities::api_key;

pub(super) struct ApiKeyNumbers;

impl MigrationName for ApiKeyNumbers {
    fn name(&self) -> &str {
        "m20260930_000001_api_key_numbers"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for ApiKeyNumbers {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            return rebuild_sqlite(manager).await;
        }

        for column in [
            api_key::Column::RefillInterval,
            api_key::Column::RefillAmount,
            api_key::Column::RateLimitTimeWindow,
            api_key::Column::RateLimitMax,
            api_key::Column::RequestCount,
            api_key::Column::Remaining,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(api_key::Entity)
                        .modify_column(ColumnDef::new(column).double())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

async fn rebuild_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let transaction = manager.begin().await?;
    let database = transaction.get_connection();
    // REAL affinity converts existing integer values before SQLx decodes them as f64.
    for statement in [
        "DROP INDEX IF EXISTS idx_api_keys_reference_id",
        "DROP INDEX IF EXISTS idx_api_keys_config_id",
        "ALTER TABLE api_keys RENAME TO api_keys_integer",
    ] {
        let _ = database.execute_unprepared(statement).await?;
    }
    super::migrator::create_api_keys(&transaction).await?;
    let _ = database
        .execute_unprepared(
            "INSERT INTO api_keys (id, name, start, prefix, key, reference_id, config_id,
            refill_interval, refill_amount, last_refill_at, enabled, rate_limit_enabled,
            rate_limit_time_window, rate_limit_max, request_count, remaining, last_request,
            expires_at, created_at, updated_at, permissions, metadata)
         SELECT id, name, start, prefix, key, reference_id, config_id,
            refill_interval, refill_amount, last_refill_at, enabled, rate_limit_enabled,
            rate_limit_time_window, rate_limit_max, request_count, remaining, last_request,
            expires_at, created_at, updated_at, permissions, metadata FROM api_keys_integer",
        )
        .await?;
    let _ = database
        .execute_unprepared("DROP TABLE api_keys_integer")
        .await?;
    transaction.commit().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{SeaOrmStore, bundled_schema::BundledSchema};
    use better_auth_core::store::{ApiKeyStore, ConsumeApiKeyResult};
    use better_auth_core::{AuthConfig, UpdateApiKey};
    use sea_orm::{ConnectionTrait, Database};

    #[tokio::test]
    async fn existing_integer_columns_preserve_fractional_usage() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let _ = database
            .execute_unprepared(
                "CREATE TABLE api_keys (
                id TEXT PRIMARY KEY, name TEXT, start TEXT, prefix TEXT,
                key TEXT NOT NULL UNIQUE, reference_id TEXT NOT NULL, config_id TEXT NOT NULL,
                refill_interval INTEGER, refill_amount INTEGER, last_refill_at TEXT,
                enabled BOOLEAN NOT NULL, rate_limit_enabled BOOLEAN NOT NULL,
                rate_limit_time_window INTEGER, rate_limit_max INTEGER, request_count INTEGER,
                remaining INTEGER, last_request TEXT, expires_at TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, permissions TEXT, metadata TEXT
            );
            INSERT INTO api_keys (id, key, reference_id, config_id, enabled, rate_limit_enabled,
                remaining, created_at, updated_at)
            VALUES ('existing', 'hash', 'user', 'default', 1, 0, 2147483648,
                '2026-09-30T00:00:00Z', '2026-09-30T00:00:00Z')",
            )
            .await
            .unwrap();
        ApiKeyNumbers
            .up(&SchemaManager::new(&database))
            .await
            .unwrap();
        let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::new("test-secret"), database);
        let existing = store.get_api_key_by_id("existing").await.unwrap().unwrap();
        assert_eq!(existing.remaining, Some(2147483648.0));
        let updated = store
            .update_api_key(
                &"existing".into(),
                UpdateApiKey {
                    remaining: Some(2.5),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let result = store.consume_api_key_usage(&updated, false).await.unwrap();
        let ConsumeApiKeyResult::Allowed(key) = result else {
            panic!("key must remain usable after migration")
        };
        assert_eq!(key.remaining, Some(1.5));
        let persisted = store.get_api_key_by_id("existing").await.unwrap().unwrap();
        assert_eq!(persisted.remaining, Some(1.5));
        assert_eq!(persisted.key_hash, "hash");
        assert_eq!(persisted.reference_id, "user");
    }
}
