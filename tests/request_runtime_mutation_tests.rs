//! Paired with contracts/request-runtime-mutation.test.ts.
#![expect(
    clippy::expect_used,
    clippy::panic_in_result_fn,
    reason = "Runtime contracts propagate setup errors and assert complete callback and storage observations"
)]

use async_trait::async_trait;
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    BeforeRequestAction, FieldMap, FieldValue, HttpMethod,
    observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks},
    store::{EphemeralStore, StatelessSchema as S, schema::EntityRole},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[path = "request_runtime_mutation_tests/http.rs"]
mod http;
#[path = "request_runtime_mutation_tests/routing.rs"]
mod routing;
#[path = "request_runtime_mutation_tests/scopes.rs"]
mod scopes;
#[path = "request_runtime_mutation_tests/shared.rs"]
mod shared;

const ORIGIN: &str = "https://preview.runtime.test";
const BASE_PATH: &str = "/api/runtime";
const INITIAL_URL: &str = "https://preview.runtime.test/api/runtime";

fn changed(phase: &str) -> String {
    format!("http://{phase}.runtime.test/changed")
}

fn config() -> AuthConfig {
    let mut config =
        AuthConfig::new("request-runtime-mutation-secret-at-least-32-characters").base_url(ORIGIN);
    config.base_path = BASE_PATH.into();
    config.logger = better_auth_core::LoggerConfig {
        disabled: Some(true),
        ..Default::default()
    }
    .into();
    config.telemetry.enabled = false;
    config
}

fn store(config: &AuthConfig) -> AuthResult<Arc<EphemeralStore>> {
    Ok(Arc::new(EphemeralStore::from_storage(
        Arc::new(config.clone()),
        ["user", "session", "account", "verification"].map(|name| (name.into(), Vec::new())),
    )?))
}

fn snapshot(store: &EphemeralStore) -> AuthResult<Value> {
    let mut result = serde_json::Map::new();
    for (name, role) in [
        ("user", EntityRole::User),
        ("session", EntityRole::Session),
        ("account", EntityRole::Account),
        ("verification", EntityRole::Verification),
    ] {
        let rows = FieldValue::from(
            store
                .storage_rows(role)?
                .into_iter()
                .map(FieldValue::from)
                .collect::<Vec<_>>(),
        );
        let _ = result.insert(name.into(), rows.json()?.expect("Table arrays serialize"));
    }
    Ok(Value::Object(result))
}

fn empty_database() -> Value {
    json!({"user": [], "session": [], "account": [], "verification": []})
}

fn lock<T>(value: &Mutex<T>) -> AuthResult<std::sync::MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("Runtime contract recorder lock poisoned"))
}

fn active(context: &AuthContext<S>) -> Arc<AuthContext<S>> {
    let active = context
        .current_request_context()
        .expect("Endpoint runtime is active");
    assert!(std::ptr::eq(active.as_ref(), context));
    active
}

async fn call(auth: &BetterAuth<S>, route: &str, http: bool) -> AuthResult<AuthResponse> {
    if http {
        auth.handle_request(
            AuthRequest::new(HttpMethod::Get, format!("{BASE_PATH}{route}")).with_url(
                format!("{INITIAL_URL}{route}")
                    .parse()
                    .expect("Fixture URL"),
            ),
        )
        .await
    } else {
        auth.call_endpoint(HttpMethod::Get, route, Default::default())
            .await
    }
}
