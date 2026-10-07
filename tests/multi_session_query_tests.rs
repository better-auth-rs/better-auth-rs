#![cfg(feature = "seaorm2")]

use std::{collections::HashMap, sync::Arc};

use better_auth::plugins::MultiSessionPlugin;
use better_auth::server_api::EndpointInput;
use better_auth::{AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_core::store::database_hooks::SessionUpdate;
use better_auth_core::store::{EphemeralStore, MemoryCacheAdapter, RuntimeStore, SecondaryStorage};
use better_auth_core::utils::cookie_utils::{sign_cookie_value, verify_cookie_value};
use better_auth_core::{AuthStore, CreateSession, CreateUser, HttpMethod};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{SeaOrmStore, sea_orm::Database};
use serde_json::{Value, json};

const SECRET: &str = "multi-session-query-secret-at-least-32-characters";

async fn run<S: AuthSchema>(
    config: AuthConfig,
    store: Arc<dyn AuthStore<S>>,
    case: &Value,
) -> AuthResult<Value> {
    let secondary = case["backend"] == "secondary";
    let expired = case["expired"] == true;
    let cache = Arc::new(MemoryCacheAdapter::new());
    let mut builder = BetterAuth::new(config)
        .store_arc(store.clone())
        .plugin(MultiSessionPlugin::new());
    if secondary {
        builder = builder.secondary_storage(cache.clone());
    }
    let auth = builder.build().await?;
    for name in ["c", "a", "b", "d"] {
        let user = store
            .create_user(
                CreateUser::new()
                    .with_name(name)
                    .with_email(format!("{name}@example.test")),
            )
            .await?;
        let session = store
            .create_session(CreateSession {
                additional_fields: Default::default(),
                user_id: user.id.clone(),
                expires_at: (if expired && name == "a" {
                    "2000-01-01T00:00:00Z"
                } else {
                    "2099-01-01T00:00:00Z"
                })
                .parse::<chrono::DateTime<chrono::Utc>>()
                .map_err(|error: chrono::ParseError| AuthError::internal(error.to_string()))?
                .into(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        let session = store
            .update_session_with_writer(
                &session.token,
                SessionUpdate {
                    token: Some(name.into()),
                    ..Default::default()
                },
                None,
            )
            .await?
            .ok_or_else(|| AuthError::internal("session fixture update returned null"))?;
        cache
            .set(
                name,
                &json!({"session":session,"user":user}).to_string(),
                None,
            )
            .await?;
    }
    if case["missing"] == true {
        let _ = store
            .update_session_with_writer(
                "c",
                SessionUpdate {
                    user_id: Some("missing".into()),
                    ..Default::default()
                },
                None,
            )
            .await?;
    }
    if secondary {
        cache.delete("c").await?;
        cache.set("b", "invalid json", None).await?;
    }
    let mut cookies: Vec<_> = ["b", "c", "a", "d"]
        .into_iter()
        .map(|token| {
            format!(
                "better-auth.session_token_multi-{token}={}",
                sign_cookie_value(token, SECRET)
            )
        })
        .collect();
    cookies.push(format!(
        "better-auth.session_token={}",
        sign_cookie_value("d", SECRET)
    ));
    let headers = HashMap::from([("cookie".into(), cookies.join("; "))]);
    let list = auth
        .call_endpoint(
            HttpMethod::Get,
            "/multi-session/list-device-sessions",
            EndpointInput {
                headers: Some(headers.clone()),
                ..Default::default()
            },
        )
        .await?;
    let list: Vec<Value> = serde_json::from_slice(&list.body.bytes()?)?;
    let response = auth
        .call_endpoint(
            HttpMethod::Post,
            "/multi-session/revoke",
            EndpointInput {
                headers: Some(headers),
                body: Some(json!({"sessionToken":"d"})),
                ..Default::default()
            },
        )
        .await?;
    let active = response.headers.get_all("set-cookie").find_map(|header| {
        let value = header
            .strip_prefix("better-auth.session_token=")?
            .split(';')
            .next()?;
        if value.is_empty() {
            Some(String::new())
        } else {
            verify_cookie_value(value, SECRET)
        }
    });
    Ok(
        json!({"backend":case["backend"],"limit":case["limit"],"expired":expired,"missing":case["missing"],
        "listed":list.iter().map(|entry| &entry["session"]["token"]).collect::<Vec<_>>(),
        "revoked":serde_json::from_slice::<Value>(&response.body.bytes()?)?,"active":active}),
    )
}

#[tokio::test]
async fn multi_session_query_order_limits_expiration_and_cache_match_upstream() -> AuthResult<()> {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/multi-session-query-upstream.json"))?;
    for case in cases {
        let mut config = AuthConfig::new(SECRET).base_url("http://multi.test");
        config.logger.disabled = Some(true);
        config.advanced.database.default_find_many_limit = case["limit"].as_f64();
        config.session.store_session_in_database = Some(true);
        let actual =
            if case["backend"] == "sqlite" {
                let database = Database::connect("sqlite::memory:")
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                migrator::run_migrations(&database)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                let store = SeaOrmStore::<BundledSchema>::new(config.clone(), database)
                    .with_runtime(Arc::new(config.clone()), Vec::new(), Default::default())?;
                run(config, store, &case).await?
            } else {
                let store = EphemeralStore::default().with_runtime(
                    Arc::new(config.clone()),
                    Vec::new(),
                    Default::default(),
                )?;
                run(config, store, &case).await?
            };
        assert_eq!(actual, case);
    }
    Ok(())
}
