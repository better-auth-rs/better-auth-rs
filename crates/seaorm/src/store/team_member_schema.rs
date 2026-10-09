use sea_orm::{ConnectionTrait, DatabaseBackend};
use sea_orm_migration::prelude::*;

use super::entities::team_member;

pub(super) struct TeamMemberSchema;

impl MigrationName for TeamMemberSchema {
    fn name(&self) -> &str {
        "m20261009_000002_team_member_schema"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for TeamMemberSchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        if backend == DatabaseBackend::Sqlite {
            let transaction = manager.begin().await?;
            let add = Table::alter()
                .table(team_member::Entity)
                .add_column(
                    ColumnDef::new(Alias::new("_auth_created_at"))
                        .timestamp_with_time_zone()
                        .null(),
                )
                .to_owned();
            // Replacing the timestamp column preserves membership rows and incoming foreign keys.
            for statement in [
                backend.build(&add).to_string(),
                "UPDATE team_member SET _auth_created_at = created_at".to_owned(),
                "ALTER TABLE team_member DROP COLUMN created_at".to_owned(),
                "ALTER TABLE team_member RENAME COLUMN _auth_created_at TO created_at".to_owned(),
                "DROP INDEX IF EXISTS idx_team_member_identity".to_owned(),
                "CREATE INDEX IF NOT EXISTS idx_team_member_team_id ON team_member(team_id)"
                    .to_owned(),
            ] {
                let _ = transaction
                    .get_connection()
                    .execute_unprepared(&statement)
                    .await?;
            }
            return transaction.commit().await;
        }

        if backend == DatabaseBackend::Postgres {
            let _ = manager
                .get_connection()
                .execute_unprepared("ALTER TABLE team_member ALTER COLUMN created_at DROP NOT NULL")
                .await?;
        } else {
            let row = manager.get_connection().query_one_raw(sea_orm::Statement::from_string(
                backend,
                "SELECT COLUMN_TYPE AS column_type FROM information_schema.COLUMNS
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'team_member' AND COLUMN_NAME = 'created_at'",
            )).await?.ok_or_else(|| DbErr::RecordNotFound("Missing team_member.created_at column".into()))?;
            let column_type = row.try_get::<String>("", "column_type")?;
            manager
                .alter_table(
                    Table::alter()
                        .table(team_member::Entity)
                        .modify_column(
                            ColumnDef::new(team_member::Column::CreatedAt)
                                .custom(Alias::new(column_type))
                                .null(),
                        )
                        .to_owned(),
                )
                .await?;
        }
        // MySQL requires an index for the Team foreign key before the old composite index is removed.
        if !manager
            .has_index("team_member", "idx_team_member_team_id")
            .await?
        {
            manager
                .create_index(
                    Index::create()
                        .name("idx_team_member_team_id")
                        .table(team_member::Entity)
                        .col(team_member::Column::TeamId)
                        .to_owned(),
                )
                .await?;
        }
        if manager
            .has_index("team_member", "idx_team_member_identity")
            .await?
        {
            manager
                .drop_index(
                    Index::drop()
                        .name("idx_team_member_identity")
                        .table(team_member::Entity)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod server_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{Database, Statement};

    #[tokio::test]
    async fn upgrade_preserves_memberships_and_foreign_keys_without_pair_uniqueness() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let _ = database.execute_unprepared(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE users (id TEXT PRIMARY KEY);
             CREATE TABLE team (id TEXT PRIMARY KEY);
             CREATE TABLE team_member (
                 id TEXT PRIMARY KEY,
                 team_id TEXT NOT NULL REFERENCES team(id) ON DELETE CASCADE,
                 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                 membership_key TEXT UNIQUE,
                 created_at TEXT NOT NULL,
                 marker TEXT
             );
             CREATE UNIQUE INDEX idx_team_member_identity ON team_member(team_id, user_id);
             CREATE INDEX idx_team_member_user_id ON team_member(user_id);
             CREATE TABLE membership_audit (membership_id TEXT REFERENCES team_member(id) ON DELETE CASCADE);
             INSERT INTO users VALUES ('owner');
             INSERT INTO team VALUES ('team');
             INSERT INTO team_member VALUES ('old', 'team', 'owner', 'old-key', '2026-10-01T00:00:00.000Z', 'retained');
             INSERT INTO membership_audit VALUES ('old');"
        ).await.unwrap();
        TeamMemberSchema
            .up(&SchemaManager::new(&database))
            .await
            .unwrap();
        let row = database.query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT team_member.id, team_id, user_id, membership_key, created_at, marker, membership_id
             FROM team_member JOIN membership_audit ON membership_id = id",
        )).await.unwrap().unwrap();
        for (column, expected) in [
            ("id", "old"),
            ("team_id", "team"),
            ("user_id", "owner"),
            ("membership_key", "old-key"),
            ("created_at", "2026-10-01T00:00:00.000Z"),
            ("marker", "retained"),
            ("membership_id", "old"),
        ] {
            assert_eq!(row.try_get::<String>("", column).unwrap(), expected);
        }
        let _ = database.execute_unprepared(
            "INSERT INTO team_member (id, team_id, user_id, membership_key) VALUES ('new', 'team', 'owner', 'new-key');
             UPDATE team_member SET created_at = NULL WHERE id = 'old';"
        ).await.unwrap();
        for statement in [
            "INSERT INTO team_member (id, team_id, user_id, membership_key) VALUES ('old', 'team', 'owner', 'third-key')",
            "INSERT INTO team_member (id, team_id, user_id, membership_key) VALUES ('third', 'team', 'owner', 'old-key')",
        ] {
            let error = database.execute_unprepared(statement).await.unwrap_err();
            assert!(
                error.to_string().contains("UNIQUE constraint failed"),
                "{error}"
            );
        }
        let manager = SchemaManager::new(&database);
        assert!(
            manager
                .has_index("team_member", "idx_team_member_team_id")
                .await
                .unwrap()
        );
        assert!(
            manager
                .has_index("team_member", "idx_team_member_user_id")
                .await
                .unwrap()
        );
        assert!(
            !manager
                .has_index("team_member", "idx_team_member_identity")
                .await
                .unwrap()
        );
        let _ = database
            .execute_unprepared("DELETE FROM team WHERE id = 'team'")
            .await
            .unwrap();
        for table in ["team_member", "membership_audit"] {
            let row = database
                .query_one_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    format!("SELECT COUNT(*) AS count FROM {table}"),
                ))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.try_get::<i64>("", "count").unwrap(), 0);
        }
    }
}
