#![cfg(feature = "seaorm2")]

#[path = "support/device_field_contract.rs"]
mod contract;
#[path = "device_additional_fields_tests/empty_field_name.rs"]
mod empty_field_name;
#[path = "support/device_fields.rs"]
mod fixture;
#[path = "device_additional_fields_tests/live_reads.rs"]
mod live_reads;
#[path = "device_additional_fields_tests/live_writes.rs"]
mod live_writes;

use better_auth::{
    __private_core::{
        AuthError, AuthResult,
        id::IdGeneration,
        store::{
            EphemeralStore,
            schema::{SchemaCheckError, SchemaFinding},
        },
        user_fields::{FieldTransforms, UserFieldConfig, UserFieldReference, UserFieldTransform},
    },
    BetterAuth,
    plugins::DeviceAuthorizationPlugin,
    seaorm::sea_orm::ConnectionTrait,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn memory_declared_device_fields_match_pinned_storage_and_projection() -> AuthResult<()> {
    contract::contract(
        Arc::new(EphemeralStore::new(Arc::new(contract::config()))),
        "memory",
    )
    .await
}

#[tokio::test]
async fn sqlite_declared_device_fields_match_pinned_storage_and_projection() -> AuthResult<()> {
    let (store, _) = fixture::sqlite(contract::config()).await;
    contract::contract(Arc::new(store), "sqlite").await
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and permission to create isolated test schemas"]
async fn live_postgres_declared_device_fields_match_pinned_sqlite_contract()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use better_auth::seaorm::sea_orm::{ConnectOptions, Database};

    let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_POSTGRES_URL")?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let schema = format!("ba_device_fields_{}", uuid::Uuid::new_v4().simple());
    let _ = database
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await?;
    let worker = database.clone();
    let worker_schema = schema.clone();
    let result = tokio::spawn(async move {
        let _ = worker
            .execute_unprepared(&format!("SET search_path TO {worker_schema}"))
            .await?;
        let (store, _) = fixture::setup(contract::config(), worker).await;
        contract::contract(Arc::new(store), "sqlite").await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;
    let cleanup = database
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await;
    database.close().await?;
    let _ = cleanup?;
    result??;
    Ok(())
}

#[tokio::test]
async fn memory_serial_device_reference_reaches_output_as_a_number() -> AuthResult<()> {
    let mut config = contract::config();
    config.advanced.database.generate_id = Some(IdGeneration::Serial);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let output = observed.clone();
    let fields = better_auth::config::UserConfig {
        additional_fields: Some(
            [(
                "target".into(),
                UserFieldConfig {
                    required: Some(false),
                    references: Some(UserFieldReference {
                        model: "user".into(),
                        field: "id".into(),
                    }),
                    transform: Some(FieldTransforms {
                        output: Some(UserFieldTransform::new(move |value| {
                            output
                                .lock()
                                .expect("ordinary output trace lock")
                                .push(value.clone());
                            Ok(value)
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    let auth = BetterAuth::new(config.clone())
        .store(EphemeralStore::new(Arc::new(config)))
        .plugin(contract::Fields(fields))
        .build()
        .await?;
    let mut input = contract::input("serial-reference");
    let _ = input
        .additional_fields
        .insert("target".into(), json!("002"));
    let created = auth.store().create_device_code(input).await?;
    let read = auth
        .store()
        .get_device_code_by_device_code(&created.device_code)
        .await?
        .expect("ordinary reference record exists");
    let expected: Value =
        serde_json::from_str(include_str!("fixtures/device-additional-fields-1.7.6.json"))?;
    let actual = json!({
        "created":created.additional_fields["target"],
        "read":read.additional_fields["target"],
        "outputInputs":*observed.lock().expect("ordinary output trace lock"),
    });
    assert_eq!(actual, expected["serialReference"]);
    assert_eq!(actual["outputInputs"], json!([2, 2]));
    assert_eq!(actual["created"], "2");
    Ok(())
}

#[tokio::test]
async fn device_field_preflight_tracks_only_declared_columns() -> AuthResult<()> {
    let (store, database) = fixture::sqlite(contract::config()).await;
    let _ = database
        .execute_unprepared("ALTER TABLE ordinary_device_fields DROP COLUMN stored_label")
        .await
        .expect("ordinary fixture schema omits the configured column");
    let fields = better_auth::config::UserConfig {
        additional_fields: Some(
            [(
                "label".into(),
                UserFieldConfig {
                    field_name: Some("stored_label".into()),
                    required: Some(false),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    let auth = BetterAuth::new(contract::config())
        .store(store.clone())
        .plugin(DeviceAuthorizationPlugin::new())
        .plugin(contract::Fields(fields))
        .build()
        .await?;
    let check = &auth
        .context()
        .database
        .schema_validation()
        .expect("SQL store exposes schema validation")
        .check;
    let error = check
        .check()
        .await
        .expect_err("declared column must be present");
    let AuthError::SchemaCheck(error) = error else {
        panic!("expected schema mismatch");
    };
    let SchemaCheckError::Mismatch(error) = error.as_ref() else {
        panic!("expected physical schema mismatch");
    };
    assert_eq!(
        error.findings,
        [SchemaFinding::MissingColumn {
            table: "ordinary_device_fields".into(),
            column: "stored_label".into()
        }]
    );
    let _ = database
        .execute_unprepared("ALTER TABLE ordinary_device_fields ADD COLUMN stored_label TEXT")
        .await
        .expect("ordinary fixture schema adds the configured column");
    store.invalidate_schema_check();
    check.check().await?;
    Ok(())
}

#[tokio::test]
async fn device_registration_rejects_a_native_physical_column_alias() {
    let (store, _) = fixture::sqlite(contract::config()).await;
    let fields = better_auth::config::UserConfig {
        additional_fields: Some(
            [(
                "label".into(),
                UserFieldConfig {
                    field_name: Some("stored_client_id".into()),
                    required: Some(false),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    let result = BetterAuth::new(contract::config())
        .store(store)
        .plugin(contract::Fields(fields))
        .build()
        .await;
    assert!(matches!(result, Err(AuthError::Config(_))));
}
