use super::*;
use better_auth_seaorm::sea_orm::{ConnectOptions, ConnectionTrait};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

async fn isolated(backend: &'static str, model: Model, patch: Patch) -> TestResult {
    let variable = if backend == "postgres" {
        "BETTER_AUTH_TEST_POSTGRES_URL"
    } else {
        "BETTER_AUTH_TEST_MYSQL_URL"
    };
    let mut options = ConnectOptions::new(std::env::var(variable)?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let name = format!("ba_update_fields_{}", uuid::Uuid::new_v4().simple());
    let (create, select, drop) = if backend == "postgres" {
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
    let worker = database.clone();
    // A separate task preserves database cleanup when a contract assertion panics.
    let result = tokio::spawn(async move {
        let _ = worker.execute_unprepared(&select).await?;
        migrator::run_migrations(&worker).await?;
        check(
            Arc::new(SeaOrmStore::<BundledSchema>::new(
                AuthConfig::default(),
                worker,
            )),
            true,
            model,
            patch,
        )
        .await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;
    let cleanup = database.execute_unprepared(&drop).await;
    database.close().await?;
    let _ = cleanup?;
    result??;
    Ok(())
}

async fn server(backend: &'static str) -> TestResult {
    for model in [
        Model::Account,
        Model::AccountMany,
        Model::Verification,
        Model::Session,
    ] {
        for patch in [Patch::Values, Patch::Empty, Patch::Continue] {
            isolated(backend, model, patch).await?;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and isolated schema permissions"]
async fn live_postgres_updates_preserve_complete_results_and_original_hooks() -> TestResult {
    server("postgres").await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and isolated database permissions"]
async fn live_mysql_updates_preserve_complete_results_and_original_hooks() -> TestResult {
    server("mysql").await
}
