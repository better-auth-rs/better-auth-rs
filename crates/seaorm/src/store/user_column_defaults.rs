use sea_orm::{ConnectionTrait, DatabaseBackend};
use sea_orm_migration::prelude::*;

use super::entities::user;

pub(super) struct UserColumnDefaults;

impl MigrationName for UserColumnDefaults {
    fn name(&self) -> &str {
        "m20261009_000001_user_column_defaults"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for UserColumnDefaults {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            let transaction = manager.begin().await?;
            // Replacing only metadata preserves the users table and its incoming foreign keys.
            for statement in [
                "ALTER TABLE users ADD COLUMN _auth_metadata JSONB NOT NULL DEFAULT '{}'",
                "UPDATE users SET _auth_metadata = metadata",
                "ALTER TABLE users DROP COLUMN metadata",
                "ALTER TABLE users RENAME COLUMN _auth_metadata TO metadata",
            ] {
                let _ = transaction
                    .get_connection()
                    .execute_unprepared(statement)
                    .await?;
            }
            return transaction.commit().await;
        }

        manager
            .alter_table(
                Table::alter()
                    .table(user::Entity)
                    .modify_column(
                        ColumnDef::new(user::Column::Metadata)
                            .json_binary()
                            .not_null()
                            .default(Expr::cust("('{}')")),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;

    #[tokio::test]
    async fn metadata_default_upgrade_preserves_rows_and_incoming_foreign_keys() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let _ = database
            .execute_unprepared(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE users (id TEXT PRIMARY KEY, metadata JSONB NOT NULL, marker TEXT);
                 CREATE INDEX idx_users_marker ON users(marker);
                 CREATE TABLE sessions (
                     id TEXT PRIMARY KEY,
                     user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE
                 );
                 INSERT INTO users VALUES ('old', '{\"keep\":1}', 'custom');
                 INSERT INTO sessions VALUES ('session', 'old');",
            )
            .await
            .unwrap();
        UserColumnDefaults
            .up(&SchemaManager::new(&database))
            .await
            .unwrap();
        let _ = database
            .execute_unprepared("INSERT INTO users (id, marker) VALUES ('new', 'default')")
            .await
            .unwrap();
        let rows = database
            .query_all_raw(sea_orm::Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT users.id, metadata, marker, sessions.id AS session_id
                 FROM users LEFT JOIN sessions ON sessions.user_id = users.id ORDER BY users.id",
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].try_get::<String>("", "id").unwrap(), "new");
        assert_eq!(rows[0].try_get::<String>("", "metadata").unwrap(), "{}");
        assert_eq!(rows[1].try_get::<String>("", "id").unwrap(), "old");
        assert_eq!(
            rows[1].try_get::<String>("", "metadata").unwrap(),
            "{\"keep\":1}"
        );
        assert_eq!(rows[1].try_get::<String>("", "marker").unwrap(), "custom");
        assert_eq!(
            rows[1].try_get::<String>("", "session_id").unwrap(),
            "session"
        );
        let _ = database
            .execute_unprepared("DELETE FROM users WHERE id = 'old'")
            .await
            .unwrap();
        let row = database
            .query_one_raw(sea_orm::Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS count FROM sessions",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<i64>("", "count").unwrap(), 0);
    }
}
