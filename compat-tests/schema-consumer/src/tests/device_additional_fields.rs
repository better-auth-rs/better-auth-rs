#[path = "../../../../tests/support/device_field_contract.rs"]
mod contract;

use better_auth::seaorm::{
    Database, SeaOrmStore,
    sea_orm::{ColumnTrait, EntityTrait, QueryFilter},
};
use serde_json::json;
use std::sync::Arc;

mod mapped {
    include!(env!("BETTER_AUTH_PLUGIN_SCHEMA"));
}

#[tokio::test]
async fn generated_device_columns_preserve_declared_field_policies()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    mapped::create_auth_tables(&database).await?;
    let store = SeaOrmStore::<mapped::AppAuthSchema>::new(contract::config(), database.clone())
        .with_organization_schema::<mapped::AppOrganizationSchema>()
        .with_plugin_schema::<mapped::AppPluginSchema>();
    contract::contract(Arc::new(store), "sqlite").await?;
    let persisted = mapped::device_code::Entity::find()
        .filter(mapped::device_code::Column::DeviceCode.eq("ordinary-device:output-error"))
        .one(&database)
        .await?
        .expect("output error occurs after the physical insert");
    assert_eq!(persisted.label.as_deref(), Some("Default"));
    assert_eq!(
        persisted.activated_at,
        Some("2029-01-02T03:04:05Z".parse()?)
    );
    assert_eq!(
        persisted.details,
        Some(json!({"channel":"ordinary","enabled":true}))
    );
    assert_eq!(persisted.revision.map(f64::from), Some(1.5));
    assert_eq!(persisted.client_id.as_deref(), Some("ordinary-client"));
    assert_eq!(persisted.status, "pending");
    Ok(())
}
