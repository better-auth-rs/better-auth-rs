use super::*;
use better_auth_seaorm::sea_orm::ConnectOptions;

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and permission to create isolated test databases"]
async fn live_mysql_preflight_tracks_migrations_defaults_and_auto_increment()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut url = reqwest::Url::parse(&std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?)?;
    let mut options = ConnectOptions::new(url.as_str());
    let _ = options.max_connections(1).sqlx_logging(false);
    let admin = Database::connect(options).await?;
    let name = format!("ba_mysql_preflight_{}", uuid::Uuid::new_v4().simple());
    let _ = admin
        .execute_unprepared(&format!("CREATE DATABASE `{name}`"))
        .await?;

    url.set_path(&name);
    let result = async {
        let mut options = ConnectOptions::new(url.as_str());
        let _ = options.max_connections(1).sqlx_logging(false);
        let database = Database::connect(options).await?;
        let worker = database.clone();
        let result = tokio::spawn(async move {
            check_preflight(&worker).await;
        })
        .await;
        let closed = database.close().await;
        result?;
        closed?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    let cleanup = admin
        .execute_unprepared(&format!("DROP DATABASE `{name}`"))
        .await;
    let closed = admin.close().await;
    let _ = cleanup?;
    closed?;
    result
}

async fn check_preflight(database: &DatabaseConnection) {
    let store = SeaOrmStore::new(config(), database.clone());
    let auth = build(store.clone(), config(), Observe(Default::default())).await;
    let missing = mismatch(http(&auth).await.unwrap_err());
    assert_eq!(findings(&missing).len(), 4);

    migrator::run_migrations(database).await.unwrap();
    assert!(Arc::ptr_eq(
        &missing,
        &mismatch(http(&auth).await.unwrap_err())
    ));
    store.invalidate_schema_check();
    assert_eq!(http(&auth).await.unwrap().status, 200);
    assert_eq!(
        auth.call_endpoint(HttpMethod::Get, "/ok", EndpointInput::default())
            .await
            .unwrap()
            .status,
        200
    );

    execute(
        database,
        "ALTER TABLE accounts ADD COLUMN legacy VARCHAR(255) NOT NULL",
    )
    .await;
    assert_eq!(http(&auth).await.unwrap().status, 200);
    store.invalidate_schema_check();
    assert_eq!(
        findings(&mismatch(http(&auth).await.unwrap_err())),
        &[SchemaFinding::UnexpectedRequiredColumn {
            table: "accounts".into(),
            column: "legacy".into(),
        }]
    );

    execute(
        database,
        "ALTER TABLE accounts ALTER COLUMN legacy SET DEFAULT ''",
    )
    .await;
    store.invalidate_schema_check();
    assert_eq!(http(&auth).await.unwrap().status, 200);

    execute(
        database,
        "ALTER TABLE accounts ADD COLUMN sequence_value BIGINT NOT NULL AUTO_INCREMENT UNIQUE",
    )
    .await;
    store.invalidate_schema_check();
    assert_eq!(http(&auth).await.unwrap().status, 200);
}
