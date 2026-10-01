#![cfg(feature = "seaorm2")]

use std::collections::HashMap;

use better_auth::plugins::organization::{OrganizationConfig, OrganizationPlugin};
use better_auth::server_api::EndpointInput;
use better_auth::{AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_core::store::EphemeralStore;
use better_auth_core::{
    AuthUser, CreateMember, CreateOrganization, CreateSession, CreateUser, HttpMethod,
};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{SeaOrmStore, sea_orm::Database};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

async fn check<S: AuthSchema>(
    auth: BetterAuth<S>,
    membership_limit: Option<usize>,
    database_limit: Option<f64>,
) -> AuthResult<()> {
    let store = auth.store();
    let mut users = Vec::new();
    for name in ["Second", "First"] {
        users.push(
            store
                .create_user(
                    CreateUser::new()
                        .with_name(name)
                        .with_email(format!("{name}@example.test")),
                )
                .await?,
        );
    }
    let organization = store
        .create_organization(CreateOrganization::new("Organization", "organization"))
        .await?;
    for user in users.iter().rev() {
        let _ = store
            .create_member(CreateMember::new(
                organization.id.typed()?,
                user.id.typed()?,
                "owner",
            ))
            .await?;
    }
    let first = users
        .last()
        .ok_or_else(|| AuthError::internal("fixture requires two users"))?;
    let session = store
        .create_session(CreateSession {
            additional_fields: Default::default(),
            user_id: first.id().into_owned(),
            expires_at: Utc::now() + Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let cookie = format!(
        "better-auth.session_token={}",
        better_auth_core::utils::cookie_utils::sign_cookie_value(
            &session.token,
            &auth.config().secret
        )
    );
    let headers = HashMap::from([("cookie".to_owned(), cookie)]);
    let call = |path, query| {
        auth.call_endpoint(
            HttpMethod::Get,
            path,
            EndpointInput {
                headers: Some(headers.clone()),
                query: Some(query),
                ..Default::default()
            },
        )
    };
    let response = call(
        "/organization/list-members",
        json!({"organizationId":organization.id,"limit":2}),
    )
    .await?;
    let body: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(body["total"], 2);
    assert_eq!(body["members"].as_array().map(Vec::len), Some(2));
    let response = call(
        "/organization/list-members",
        json!({"organizationId":organization.id,"limit":0}),
    )
    .await?;
    let body: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(body["total"], 2);
    assert_eq!(
        body["members"].as_array().map(Vec::len),
        Some(membership_limit.unwrap_or(2))
    );

    let full = call(
        "/organization/get-full-organization",
        json!({"organizationId":organization.id}),
    )
    .await;
    if database_limit == Some(0.0) {
        let body: Value = serde_json::from_slice(&full?.body)?;
        assert_eq!(body["members"], json!([]));
    } else if membership_limit == Some(1) {
        let Err(error) = full else {
            return Err(AuthError::internal(
                "full organization accepted a missing member user",
            ));
        };
        assert_eq!(
            error.instrumentation_message(),
            "Unexpected error: User not found for member"
        );
    } else {
        let body: Value = serde_json::from_slice(&full?.body)?;
        assert_eq!(body["members"].as_array().map(Vec::len), Some(2));
    }
    Ok(())
}

#[tokio::test]
async fn organization_user_pages_and_missing_users_match_upstream() -> AuthResult<()> {
    for sqlite in [false, true] {
        for (membership_limit, database_limit) in [(None, None), (Some(1), None), (None, Some(0.0))]
        {
            let mut config =
                AuthConfig::new("organization-query-limits-secret-at-least-32-characters")
                    .base_url("http://organization.test");
            config.logger.disabled = true;
            config.advanced.database.default_find_many_limit = database_limit;
            let plugin = OrganizationPlugin::with_config(OrganizationConfig {
                membership_limit,
                ..Default::default()
            });
            if sqlite {
                let database = Database::connect("sqlite::memory:")
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                migrator::run_migrations(&database)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                let auth = BetterAuth::<BundledSchema>::new(config.clone())
                    .store(SeaOrmStore::<BundledSchema>::new(config, database))
                    .plugin(plugin)
                    .build()
                    .await?;
                check(auth, membership_limit, database_limit).await?;
            } else {
                let auth = BetterAuth::new(config)
                    .store(EphemeralStore::default())
                    .plugin(plugin)
                    .build()
                    .await?;
                check(auth, membership_limit, database_limit).await?;
            }
        }
    }
    Ok(())
}
