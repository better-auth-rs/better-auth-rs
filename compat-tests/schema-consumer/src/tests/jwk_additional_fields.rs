#[path = "../../../../tests/support/jwk_field_contract.rs"]
mod contract;

use better_auth::seaorm::{Database, SeaOrmStore};
use std::sync::Arc;

mod mapped {
    include!(env!("BETTER_AUTH_JWK_FIELDS_SCHEMA"));
}

#[tokio::test]
async fn generated_jwk_columns_preserve_display_policies_and_error_phases()
-> Result<(), Box<dyn std::error::Error>> {
    for scenario in contract::Scenario::ALL {
        let database = Database::connect("sqlite::memory:").await?;
        mapped::create_auth_tables(&database).await?;
        let store = SeaOrmStore::<mapped::AppAuthSchema>::new(contract::config(), database.clone())
            .with_plugin_schema::<mapped::AppPluginSchema>();
        contract::contract(Arc::new(store), "sqlite", scenario).await?;
        database.close().await?;
    }
    Ok(())
}
