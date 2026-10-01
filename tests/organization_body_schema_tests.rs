use std::{collections::HashMap, sync::Arc};

use better_auth::{
    AuthBuilder, AuthConfig, BetterAuth,
    plugins::{OrganizationConfig, OrganizationPlugin},
    server_api::EndpointInput,
};
use better_auth_core::{
    HttpMethod,
    store::{EphemeralStore, StatelessSchema},
    user_fields::{UserFieldConfig, UserFieldType},
};
use serde_json::{Value, json};

#[tokio::test]
async fn shared_store_keeps_each_route_schema_bound_to_its_auth_instance() {
    let store = Arc::new(EphemeralStore::default());
    async fn build(
        store: Arc<EphemeralStore>,
        field_type: UserFieldType,
    ) -> BetterAuth<StatelessSchema> {
        let mut plugin = OrganizationConfig::default();
        let _ = plugin.schema.organization.fields_mut().insert(
            "name".into(),
            UserFieldConfig {
                field_type,
                ..Default::default()
            },
        );
        AuthBuilder::new(
            AuthConfig::new("organization-schema-isolation-secret-32-characters")
                .base_url("http://localhost:3000"),
        )
        .store_arc(store)
        .plugin(OrganizationPlugin::with_config(plugin))
        .build()
        .await
        .unwrap()
    }
    let number = build(store.clone(), UserFieldType::Number).await;
    let text = build(store, UserFieldType::String).await;
    for (auth, name, status, message) in [
        (&number, json!(7), 401, None),
        (
            &text,
            json!(7),
            400,
            Some("[body.name] Invalid input: expected string, received number"),
        ),
        (
            &number,
            json!("name"),
            400,
            Some("[body.name] Invalid input: expected number, received string"),
        ),
        (&text, json!("name"), 401, None),
    ] {
        let response = auth
            .call_endpoint(
                HttpMethod::Post,
                "/organization/create",
                EndpointInput {
                    headers: Some(HashMap::new()),
                    body: Some(json!({"name":name,"slug":"isolated"})),
                    ..Default::default()
                },
            )
            .await
            .unwrap_or_else(|error| error.to_auth_response());
        assert_eq!(response.status, status);
        if let Some(message) = message {
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(body, json!({"code":"VALIDATION_ERROR","message":message}));
        }
    }
}
