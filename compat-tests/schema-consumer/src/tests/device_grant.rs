use super::server_catalog_support::{self as server_catalog, TestResult};
use better_auth::{
    __private_core::{AuthSchema, AuthStore, AuthUser, CreateUser, store::transaction},
    BetterAuth,
    plugins::DeviceAuthorizationPlugin,
    seaorm::{
        __private_chrono as contract_chrono, Database, DatabaseConnection, SeaOrmStore,
        sea_orm::{DbBackend, EntityTrait, QueryOrder},
    },
};
use serde_json::{Value, json};
use std::sync::Arc;

#[path = "../../../../tests/support/device_grant_contract.rs"]
mod contract;
#[path = "device_grant_failures.rs"]
mod failures;
#[path = "../../../../tests/support/device_redemption_contract.rs"]
mod redemption;

mod sqlite {
    include!(env!("BETTER_AUTH_DEVICE_GRANT_SQLITE_SCHEMA"));
}
mod postgres {
    include!(env!("BETTER_AUTH_DEVICE_GRANT_POSTGRES_SCHEMA"));
}
mod mysql {
    include!(env!("BETTER_AUTH_DEVICE_GRANT_MYSQL_SCHEMA"));
}

enum Case {
    Grant(Value),
    Redemption(Value),
    Failure(Value),
}

fn cases(backend: &str) -> TestResult<Vec<Case>> {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/device-grant-sql-{backend}-1.7.6.json",
        env!("CARGO_MANIFEST_DIR"),
    ))?)?;
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    assert_eq!(fixture.get("backend"), Some(&json!(backend)));
    let grant = fixture
        .get("grant")
        .ok_or("Missing Device grant observations")?;
    let mut cases = contract::cases(grant)?
        .iter()
        .cloned()
        .map(Case::Grant)
        .collect::<Vec<_>>();
    let redemption = fixture
        .get("redemption")
        .ok_or("Missing Device redemption observations")?;
    assert_eq!(redemption.get("backend"), Some(&json!(backend)));
    let redemption = redemption
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("Missing Device redemption cases")?;
    assert_eq!(redemption.len(), 3);
    cases.push(Case::Redemption(json!(redemption)));
    let failures = fixture
        .get("failures")
        .and_then(Value::as_array)
        .ok_or("Missing Device callback failure observations")?;
    assert_eq!(failures.len(), 6);
    cases.extend(failures.iter().cloned().map(Case::Failure));
    Ok(cases)
}

async fn check_redemption<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    expected: &Value,
) -> TestResult {
    let auth = BetterAuth::new(contract::config())
        .store_arc(raw)
        .plugin(DeviceAuthorizationPlugin::new())
        .build()
        .await?;
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Owner")
                .with_email("owner@device-redemption.test"),
        )
        .await?;
    let owner = owner.id().typed()?.clone();
    let mut cases = Vec::new();
    for mode in ["success", "authorization error", "preparation error"] {
        cases.push(redemption::observe(auth.context(), None, mode, &owner).await?);
    }
    assert_eq!(
        &json!(cases),
        expected,
        "Complete server Device redemption observations"
    );
    let context = auth.context().clone();
    let observed = transaction(auth.store().as_ref(), move |transaction| {
        Box::pin(async move {
            redemption::observe(&context, Some(transaction), "success", &owner).await
        })
    })
    .await?;
    assert_eq!(Some(&observed), cases.first());
    assert!(
        auth.store()
            .get_device_code_by_device_code("ordinary-device:success")
            .await?
            .is_none()
    );
    Ok(())
}

async fn check(database: &DatabaseConnection, backend: DbBackend, case: &Case) -> TestResult {
    macro_rules! generated {
        ($schema:ident) => {{
            $schema::create_auth_tables(database).await?;
            let store = Arc::new(SeaOrmStore::<$schema::AppAuthSchema>::new(
                contract::config(), database.clone(),
            ).with_plugin_schema::<$schema::AppPluginSchema>());
            match case {
                Case::Grant(expected) => contract::check(store, expected).await?,
                Case::Redemption(expected) => check_redemption(store, expected).await?,
                Case::Failure(expected) => failures::check(store, expected, || async {
                    Ok(json!({
                        "user": $schema::user::Entity::find().order_by_asc($schema::user::Column::Id).all(database).await?,
                        "session": $schema::session::Entity::find().order_by_asc($schema::session::Column::Id).all(database).await?,
                        "account": $schema::account::Entity::find().order_by_asc($schema::account::Column::Id).all(database).await?,
                        "verification": $schema::verification::Entity::find().order_by_asc($schema::verification::Column::Id).all(database).await?,
                        "deviceCode": $schema::device_code::Entity::find().order_by_asc($schema::device_code::Column::Id).all(database).await?,
                    }))
                }).await?,
            }
        }};
    }
    match backend {
        DbBackend::Sqlite => generated!(sqlite),
        DbBackend::Postgres => generated!(postgres),
        DbBackend::MySql => generated!(mysql),
    }
    Ok(())
}

#[tokio::test]
async fn generated_sqlite_device_grant_and_redemption_match_upstream() -> TestResult {
    for case in cases("sqlite")? {
        let database = Database::connect("sqlite::memory:").await?;
        let result = check(&database, DbBackend::Sqlite, &case).await;
        database.close().await?;
        result?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and the CI upstream Device grant fixture"]
async fn live_postgres_device_grant_and_redemption_match_upstream() -> TestResult {
    for case in cases("postgres")? {
        server_catalog::in_postgres_catalog(|database| async move {
            check(&database, DbBackend::Postgres, &case).await
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_MYSQL_URL and the CI upstream Device grant fixture"]
async fn live_mysql_device_grant_and_redemption_match_upstream() -> TestResult {
    for case in cases("mysql")? {
        server_catalog::in_mysql_catalog(|database| async move {
            check(&database, DbBackend::MySql, &case).await
        })
        .await?;
    }
    Ok(())
}
