use better_auth::{
    AuthConfig, AuthSchema,
    prelude::CreateDeviceCode,
    seaorm::{
        __private_chrono as chrono, Database, SeaOrmStore,
        sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement},
    },
    store::AuthStore,
};

use super::generated;

mod mapped {
    include!(env!("BETTER_AUTH_PLUGIN_SCHEMA"));
}

async fn check<S: AuthSchema>(
    store: impl AuthStore<S>,
    database: &DatabaseConnection,
    table: &str,
    column: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let declaration = database
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT type, [notnull] AS required FROM pragma_table_info(?) WHERE name = ?",
            [table.into(), column.into()],
        ))
        .await?
        .unwrap();
    assert_eq!(declaration.try_get::<String>("", "type")?, "INTEGER");
    assert_eq!(declaration.try_get::<i64>("", "required")?, 0);
    let created = store
        .create_device_code(CreateDeviceCode {
            additional_fields: Default::default(),
            device_code: "ordinary-generated-device".into(),
            user_code: "ORDINARY".into(),
            user_id: None,
            expires_at: "2030-01-01T00:00:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()?
                .into(),
            status: "pending".into(),
            last_polled_at: None,
            polling_interval: Some(1.5),
            client_id: Some("ordinary-client".into()),
            scope: Default::default(),
        })
        .await?;
    assert_eq!(created.polling_interval, Some(1.5));
    let stored = store
        .get_device_code_by_device_code("ordinary-generated-device")
        .await?
        .unwrap();
    assert_eq!(stored.polling_interval, Some(1.5));
    Ok(())
}

#[tokio::test]
async fn generated_device_interval_preserves_integer_ddl_and_fractional_value()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    generated::create_auth_tables(&database).await?;
    check(
        SeaOrmStore::<generated::AppAuthSchema>::new(AuthConfig::default(), database.clone())
            .with_organization_schema::<generated::AppOrganizationSchema>()
            .with_plugin_schema::<generated::AppPluginSchema>(),
        &database,
        "device_code",
        "polling_interval",
    )
    .await
}

#[tokio::test]
async fn mapped_device_interval_preserves_integer_ddl_and_fractional_value()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    mapped::create_auth_tables(&database).await?;
    check(
        SeaOrmStore::<mapped::AppAuthSchema>::new(AuthConfig::default(), database.clone())
            .with_organization_schema::<mapped::AppOrganizationSchema>()
            .with_plugin_schema::<mapped::AppPluginSchema>(),
        &database,
        "mapped_device_code",
        "stored_polling_interval",
    )
    .await
}
