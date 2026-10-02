use super::*;
use better_auth_seaorm::sea_orm::ConnectOptions;

async fn check_snapshot(db: DatabaseConnection, fixture: &Value) {
    let case = Case::new(db, fixture, fixture["limit"].as_f64());
    seed(&case.store, &["A"], 1).await;
    case.state.enabled.store(true, Ordering::Relaxed);
    let path = fixture["path"].as_str().unwrap();
    let result = query(&case.store, path).await.unwrap();
    let mut expected = fixture["result"].clone();
    if path == "accounts" {
        // One child proves typed decoding without depending on an unspecified SQL row order.
        expected["accounts"] = json!([fixture["result"]["accounts"][0]]);
    }
    assert_eq!(result, expected);
    let user = entities::user::Entity::find()
        .one(case.store.connection())
        .await
        .unwrap()
        .unwrap();
    let account = account::Entity::find()
        .one(case.store.connection())
        .await
        .unwrap()
        .unwrap();
    if path == "accounts" {
        assert_eq!(user.name.as_deref(), Some("A"));
        assert_eq!(account.display_label.as_deref(), Some("A-label-0-after"));
    } else {
        assert_eq!(user.name.as_deref(), Some("A-after"));
        assert_eq!(account.display_label.as_deref(), Some("A-label-0"));
    }
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and permission to create isolated test schemas"]
async fn live_postgres_native_core_joins_preserve_typed_profiles_and_optional_children()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/native-core-joins-1.7.6.json"))?;
    for row in fixture["cases"].as_array().unwrap().iter().filter(|row| {
        row["backend"] == "sqlite" && row["joins"] == true && row["mode"] == "parent-read"
    }) {
        let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_POSTGRES_URL")?);
        let _ = options.max_connections(1).sqlx_logging(false);
        let database = Database::connect(options).await?;
        let schema = format!("ba_native_core_{}", uuid::Uuid::new_v4().simple());
        let _ = database
            .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
            .await?;
        let worker = database.clone();
        let worker_schema = schema.clone();
        let row = row.clone();
        let result = tokio::spawn(async move {
            let _ = worker
                .execute_unprepared(&format!("SET search_path TO {worker_schema}"))
                .await?;
            create_tables(&worker).await;
            check_snapshot(worker.clone(), &row).await;
            check_optional_account(worker).await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await;
        let cleanup = database
            .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
            .await;
        database.close().await?;
        let _ = cleanup?;
        result??;
    }
    Ok(())
}
