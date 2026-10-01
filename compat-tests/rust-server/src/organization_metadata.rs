use std::sync::Arc;

use better_auth::plugins::{OrganizationPlugin, TestUtilsPlugin, test_utils::TestAuthOptions};
use better_auth::server_api::EndpointInput;
use better_auth::{AuthBuilder, AuthConfig, AuthResult, AuthSchema, BetterAuth};
use better_auth_core::{
    CreateUser, HttpMethod, Organization, SchemaValue, middleware::RateLimitConfig,
};
use better_auth_seaorm::{
    Database, SeaOrmStore,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};

async fn observe<S: AuthSchema>(auth: BetterAuth<S>, sql: bool) -> AuthResult<Value> {
    let helper = auth.test()?;
    let organization = helper.organization().unwrap();
    let mut raw = Vec::new();
    for metadata in [
        json!(null),
        json!("plain"),
        json!("{\"key\":\"value\"}"),
        json!("null"),
        json!({"key":"value"}),
    ] {
        let draft = organization.create_organization(Organization {
            metadata: SchemaValue::Dynamic(metadata.clone()),
            ..Default::default()
        })?;
        let draft_value = serde_json::to_value(&draft)?;
        let id = draft.id.typed()?.clone();
        let saved = match organization.save_organization(draft).await {
            Ok(saved) => saved,
            Err(_) if sql && metadata.is_object() => {
                let persisted = auth.store().get_organization_by_id(&id).await?.is_some();
                raw.push(
                    json!({"draft":draft_value["metadata"],"rejected":true,"persisted":persisted}),
                );
                continue;
            }
            Err(error) => return Err(error),
        };
        let read = auth
            .store()
            .get_organization_by_id(saved.id.typed()?)
            .await?
            .unwrap();
        raw.push(json!({"draft":draft_value["metadata"],"saved":serde_json::to_value(saved)?["metadata"],"read":serde_json::to_value(read)?["metadata"]}));
    }
    let user = helper
        .save_user(helper.create_user(CreateUser::default())?)
        .await?
        .unwrap();
    let headers = helper
        .get_auth_headers(TestAuthOptions::new(user.id.typed()?.clone()))
        .await?;
    let created = auth.call_endpoint(HttpMethod::Post, "/organization/create", EndpointInput {
        headers: Some(headers.clone()),
        body: Some(json!({"name":"Route metadata","slug":"route-metadata","metadata":{"nested":{"value":1}}})),
        ..Default::default()
    }).await?;
    let created: Value = serde_json::from_slice(&created.body)?;
    let id = created["id"].as_str().unwrap();
    let read = |headers| EndpointInput {
        headers: Some(headers),
        query: Some(json!({"organizationId":id})),
        ..Default::default()
    };
    let created_read = auth
        .call_endpoint(
            HttpMethod::Get,
            "/organization/get-full-organization",
            read(headers.clone()),
        )
        .await?;
    let created_read: Value = serde_json::from_slice(&created_read.body)?;
    let updated = auth
        .call_endpoint(
            HttpMethod::Post,
            "/organization/update",
            EndpointInput {
                headers: Some(headers.clone()),
                body: Some(json!({"organizationId":id,"data":{"metadata":{}}})),
                ..Default::default()
            },
        )
        .await?;
    let updated: Value = serde_json::from_slice(&updated.body)?;
    let updated_read = auth
        .call_endpoint(
            HttpMethod::Get,
            "/organization/get-full-organization",
            read(headers),
        )
        .await?;
    let updated_read: Value = serde_json::from_slice(&updated_read.body)?;
    Ok(
        json!({"raw":raw,"route":{"created":created["metadata"],"createdRead":created_read["metadata"],"updated":updated["metadata"],"updatedRead":updated_read["metadata"]}}),
    )
}

pub async fn run(input: Value) -> AuthResult<Value> {
    let config = AuthConfig::new("organization-metadata-secret-at-least-thirty-two-characters")
        .base_url("https://metadata.example");
    if input["database"] == "sqlite" {
        let connection = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&connection).await.unwrap();
        let store = SeaOrmStore::<BundledSchema>::new(Arc::new(config.clone()), connection);
        observe(
            AuthBuilder::new(config)
                .store(store)
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(OrganizationPlugin::new())
                .plugin(TestUtilsPlugin::default())
                .build()
                .await?,
            true,
        )
        .await
    } else {
        observe(
            BetterAuth::stateless(config)
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(OrganizationPlugin::new())
                .plugin(TestUtilsPlugin::default())
                .build()
                .await?,
            false,
        )
        .await
    }
}
