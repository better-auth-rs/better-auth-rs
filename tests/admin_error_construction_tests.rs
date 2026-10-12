#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
#![cfg(feature = "seaorm2")]

#[path = "support/adapter_storage_snapshot.rs"]
mod adapter_storage_snapshot;

use adapter_storage_snapshot::Storage;
use std::{collections::HashMap, sync::Arc};

use better_auth::{AuthBuilder, BetterAuth, plugins::AdminPlugin, server_api::EndpointInput};
use better_auth_core::{
    ApiErrorClass, AuthConfig, AuthError, AuthSchema, AuthStore, CookieCacheConfig, CreateSession,
    CreateUser, FieldValue, HttpMethod,
    middleware::RateLimitConfig,
    store::{EphemeralStore, StatelessSchema, schema::EntityRole},
    utils::cookie_utils::sign_cookie_value,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

const ORIGIN: &str = "http://admin-errors.test";
const SECRET: &str = "admin-error-construction-contract-secret-at-least-32";
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    path: String,
    actor: String,
    method: String,
    status: String,
    http_status: u16,
    brand: String,
    body: Option<Value>,
    query: Option<Value>,
    expected_body: Option<Value>,
}

fn config() -> Result<AuthConfig> {
    let mut config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .disable_session_refresh(true)
        .session_cookie_cache(CookieCacheConfig {
            enabled: Some(false),
            ..Default::default()
        });
    config.logger = better_auth_core::LoggerConfig {
        disabled: Some(true),
        ..Default::default()
    }
    .into();
    Ok(config)
}

async fn snapshot<S: AuthSchema>(auth: &BetterAuth<S>) -> Result<Value> {
    let mut sessions = Vec::new();
    let mut accounts = Vec::new();
    for id in ["actor", "target"] {
        sessions.push(auth.store().get_user_sessions(id).await?);
        accounts.push(auth.store().get_user_accounts(id).await?);
    }
    Ok(json!({
        "users": auth.store().list_users(Default::default()).await?,
        "sessions": sessions,
        "accounts": accounts,
    }))
}

async fn check<S: AuthSchema>(store: impl AuthStore<S> + 'static, storage: Storage) -> Result<()> {
    let auth: BetterAuth<S> = AuthBuilder::new(config()?)
        .store(store)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let created_at: DateTime<Utc> = "2025-01-01T00:00:00Z".parse()?;
    let mut cookies = HashMap::new();
    for (id, role) in [("actor", "admin"), ("target", "user")] {
        let _ = auth
            .store()
            .create_user(CreateUser {
                id: Some(id.into()),
                name: Some(id.into()).into(),
                email: Some(format!("{id}@admin-errors.test")),
                email_verified: Some(true),
                role: Some(role.into()),
                banned: Some(false),
                created_at: Some(created_at.into()),
                updated_at: Some(created_at.into()),
                ..Default::default()
            })
            .await?;
        let session = auth
            .store()
            .create_session(CreateSession {
                user_id: id.into(),
                expires_at: "2099-01-01T00:00:00Z".parse::<DateTime<Utc>>()?.into(),
                inherited_fields: Default::default(),
                additional_fields: Default::default(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        let _ = cookies.insert(
            id,
            format!(
                "better-auth.session_token={}",
                sign_cookie_value(session.token.typed()?, SECRET)
            ),
        );
    }
    let stored = snapshot(&auth).await?;
    let tables = [
        ("user", "users", EntityRole::User),
        ("session", "sessions", EntityRole::Session),
        ("account", "accounts", EntityRole::Account),
        ("verification", "verifications", EntityRole::Verification),
    ];
    let raw_stored = storage.snapshot(&tables).await?;
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("fixtures/admin-error-construction-cases.json"))?;
    for case in cases {
        let headers = match case.actor.as_str() {
            "server" => None,
            "anonymous" => Some(HashMap::new()),
            actor => Some(HashMap::from([(
                "cookie".into(),
                cookies
                    .get(actor)
                    .ok_or("Unknown Admin contract actor")?
                    .clone(),
            )])),
        };
        let error = auth
            .call_endpoint(
                if case.method == "GET" {
                    HttpMethod::Get
                } else {
                    HttpMethod::Post
                },
                &case.path,
                EndpointInput {
                    headers,
                    body: case.body,
                    query: case.query,
                    ..Default::default()
                },
            )
            .await
            .err()
            .ok_or_else(|| {
                AuthError::internal(format!(
                    "Admin contract {} unexpectedly succeeded",
                    case.name
                ))
            })?;
        assert!(
            error.is_api_error_instance(ApiErrorClass::BetterCall),
            "{}",
            case.name
        );
        assert_eq!(
            error.is_api_error_instance(ApiErrorClass::BetterAuth),
            case.brand == "BetterAuth",
            "{}",
            case.name
        );
        assert_eq!(
            error.status_value()?,
            FieldValue::from(case.status),
            "{}",
            case.name
        );
        assert_eq!(error.status_code()?, case.http_status, "{}", case.name);
        let body = error.body_value()?;
        assert_eq!(body.json()?, case.expected_body, "{}", case.name);
        let expected_keys: Vec<_> = case
            .expected_body
            .as_ref()
            .and_then(Value::as_object)
            .map(|body| body.keys().cloned().collect())
            .unwrap_or_default();
        let actual_keys: Vec<_> = body.enumerable_fields()?.keys().cloned().collect();
        assert_eq!(actual_keys, expected_keys, "{}", case.name);
        if case.expected_body.is_none() {
            assert!(body.is_undefined(), "{}", case.name);
        }
        let response = error
            .to_auth_response()
            .expect("fixture response succeeds")
            .into_http_response()?;
        assert_eq!(response.status, case.http_status, "{}", case.name);
        let expected_bytes = case
            .expected_body
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()?
            .unwrap_or_default();
        assert_eq!(
            response.body.bytes()?.as_ref(),
            expected_bytes,
            "{}",
            case.name
        );
        assert_eq!(snapshot(&auth).await?, stored, "{}", case.name);
        assert_eq!(
            storage.snapshot(&tables).await?,
            raw_stored,
            "{}",
            case.name
        );
    }
    Ok(())
}

#[tokio::test]
async fn memory_admin_errors_preserve_constructor_provenance_and_storage() -> Result<()> {
    let store = EphemeralStore::new(Arc::new(config()?));
    check::<StatelessSchema>(store.clone(), Storage::Memory(Box::new(store))).await
}

#[cfg(feature = "seaorm2")]
#[tokio::test]
async fn sqlite_admin_errors_preserve_constructor_provenance_and_storage() -> Result<()> {
    use better_auth_seaorm::{
        SeaOrmStore,
        sea_orm::Database,
        store::__private_test_support::{bundled_schema::BundledSchema, migrator},
    };
    let database = Database::connect("sqlite::memory:").await?;
    migrator::run_migrations(&database).await?;
    check(
        SeaOrmStore::<BundledSchema>::new(config()?, database.clone()),
        Storage::Sqlite(database),
    )
    .await
}
