use super::*;
use sea_orm::{ConnectOptions, Database, DatabaseConnection, Statement};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

async fn upgrade(database: &DatabaseConnection) -> TestResult {
    let backend = database.get_database_backend();
    let timestamp = if backend == DatabaseBackend::Postgres {
        "TIMESTAMP(3) WITH TIME ZONE"
    } else {
        "TIMESTAMP(3)"
    };
    for statement in [
        "CREATE TABLE users (id VARCHAR(36) PRIMARY KEY)".to_owned(),
        "CREATE TABLE team (id VARCHAR(36) PRIMARY KEY)".to_owned(),
        format!("CREATE TABLE team_member (
            id VARCHAR(36) PRIMARY KEY,
            team_id VARCHAR(36) NOT NULL,
            user_id VARCHAR(36) NOT NULL,
            membership_key VARCHAR(255) UNIQUE,
            created_at {timestamp} NOT NULL,
            marker VARCHAR(36),
            FOREIGN KEY (team_id) REFERENCES team(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )"),
        "CREATE UNIQUE INDEX idx_team_member_identity ON team_member(team_id, user_id)".to_owned(),
        "CREATE INDEX idx_team_member_user_id ON team_member(user_id)".to_owned(),
        "CREATE TABLE membership_audit (membership_id VARCHAR(36), FOREIGN KEY (membership_id) REFERENCES team_member(id) ON DELETE CASCADE)".to_owned(),
        "INSERT INTO users VALUES ('owner')".to_owned(),
        "INSERT INTO team VALUES ('team')".to_owned(),
        "INSERT INTO team_member VALUES ('old', 'team', 'owner', 'old-key', '2026-10-01 00:00:00.123', 'retained')".to_owned(),
        "INSERT INTO membership_audit VALUES ('old')".to_owned(),
    ] {
        let _ = database.execute_unprepared(&statement).await?;
    }
    let snapshot = async {
        let row = database.query_one_raw(Statement::from_string(
            backend,
            "SELECT team_member.id, team_id, user_id, membership_key, created_at, marker, membership_id
             FROM team_member JOIN membership_audit ON membership_id = id",
        )).await?.ok_or("Missing old membership")?;
        let strings = [
            "id",
            "team_id",
            "user_id",
            "membership_key",
            "marker",
            "membership_id",
        ]
        .into_iter()
        .map(|column| row.try_get::<String>("", column))
        .collect::<Result<Vec<_>, _>>()?;
        let created_at = row.try_get::<chrono::DateTime<chrono::Utc>>("", "created_at")?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((strings, created_at))
    };
    let before = snapshot.await?;
    TeamMemberSchema.up(&SchemaManager::new(database)).await?;
    let row = database.query_one_raw(Statement::from_string(
        backend,
        "SELECT team_member.id, team_id, user_id, membership_key, created_at, marker, membership_id
         FROM team_member JOIN membership_audit ON membership_id = id",
    )).await?.ok_or("Missing migrated membership")?;
    let strings = [
        "id",
        "team_id",
        "user_id",
        "membership_key",
        "marker",
        "membership_id",
    ]
    .into_iter()
    .map(|column| row.try_get::<String>("", column))
    .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(strings, before.0);
    assert_eq!(
        row.try_get::<chrono::DateTime<chrono::Utc>>("", "created_at")?,
        before.1
    );
    for statement in [
        "INSERT INTO team_member (id, team_id, user_id, membership_key) VALUES ('new', 'team', 'owner', 'new-key')",
        "UPDATE team_member SET created_at = NULL WHERE id = 'old'",
    ] {
        let _ = database.execute_unprepared(statement).await?;
    }
    for statement in [
        "INSERT INTO team_member (id, team_id, user_id, membership_key) VALUES ('old', 'team', 'owner', 'third-key')",
        "INSERT INTO team_member (id, team_id, user_id, membership_key) VALUES ('third', 'team', 'owner', 'old-key')",
    ] {
        let error = database
            .execute_unprepared(statement)
            .await
            .expect_err("A unique key must remain enforced");
        assert!(
            matches!(
                error.sql_err(),
                Some(sea_orm::SqlErr::UniqueConstraintViolation(_))
            ),
            "{error}"
        );
    }
    let manager = SchemaManager::new(database);
    assert!(
        manager
            .has_index("team_member", "idx_team_member_team_id")
            .await?
    );
    assert!(
        manager
            .has_index("team_member", "idx_team_member_user_id")
            .await?
    );
    assert!(
        !manager
            .has_index("team_member", "idx_team_member_identity")
            .await?
    );
    let _ = database
        .execute_unprepared("DELETE FROM team WHERE id = 'team'")
        .await?;
    for table in ["team_member", "membership_audit"] {
        let row = database
            .query_one_raw(Statement::from_string(
                backend,
                format!("SELECT COUNT(*) AS count FROM {table}"),
            ))
            .await?
            .ok_or("Missing cascade count")?;
        if backend == DatabaseBackend::MySql {
            assert_eq!(row.try_get::<u64>("", "count")?, 0);
        } else {
            assert_eq!(row.try_get::<i64>("", "count")?, 0);
        }
    }
    Ok(())
}

async fn isolated_server(backend: DatabaseBackend, variable: &str) -> TestResult {
    let mut options = ConnectOptions::new(std::env::var(variable)?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let name = format!("ba_team_member_upgrade_{}", uuid::Uuid::new_v4().simple());
    let (create, select, drop) = if backend == DatabaseBackend::Postgres {
        (
            format!("CREATE SCHEMA {name}"),
            format!("SET search_path TO {name}"),
            format!("DROP SCHEMA {name} CASCADE"),
        )
    } else {
        (
            format!("CREATE DATABASE `{name}`"),
            format!("USE `{name}`"),
            format!("DROP DATABASE `{name}`"),
        )
    };
    let _ = database.execute_unprepared(&create).await?;
    let result = async {
        let _ = database.execute_unprepared(&select).await?;
        let worker = database.clone();
        tokio::spawn(async move { upgrade(&worker).await }).await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    let cleanup = database.execute_unprepared(&drop).await;
    let closed = database.close().await;
    let _ = cleanup?;
    closed?;
    result
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and permission to create a test schema"]
async fn live_postgres_team_member_schema_upgrade_preserves_rows() -> TestResult {
    isolated_server(DatabaseBackend::Postgres, "BETTER_AUTH_TEST_POSTGRES_URL").await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and permission to create a test database"]
async fn live_mysql_team_member_schema_upgrade_preserves_rows() -> TestResult {
    isolated_server(DatabaseBackend::MySql, "BETTER_AUTH_TEST_MYSQL_URL").await
}
