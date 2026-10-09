#![cfg(all(feature = "seaorm2", feature = "axum"))]
#![expect(
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    reason = "Contract assertions fail the test; Result propagates setup and observation errors."
)]

use better_auth::BetterAuth;
use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateUser, FieldDate,
    FieldMap, FieldValue, ListUsersParams, store::EphemeralStore,
};
use better_auth_seaorm::{SeaOrmStore, sea_orm::DatabaseConnection};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[path = "account_user_auth_boundary_reference_tests/callbacks.rs"]
mod callbacks;
#[path = "account_user_auth_boundary_reference_tests/config.rs"]
mod config;
#[path = "account_user_auth_boundary_reference_tests/email.rs"]
mod email;
#[path = "account_user_auth_boundary_reference_tests/fixture.rs"]
mod fixture;
#[path = "account_user_auth_boundary_reference_tests/hooks.rs"]
mod hooks;
#[path = "account_user_auth_boundary_reference_tests/http.rs"]
mod http;
#[path = "account_user_auth_boundary_reference_tests/models.rs"]
mod models;
#[path = "account_user_auth_boundary_reference_tests/oauth_flow.rs"]
mod oauth_flow;
#[path = "account_user_auth_boundary_reference_tests/observe.rs"]
mod observe;
#[path = "account_user_auth_boundary_reference_tests/recorder.rs"]
mod recorder;
#[path = "account_user_auth_boundary_reference_tests/secondary.rs"]
mod secondary;
#[path = "account_user_auth_boundary_reference_tests/storage.rs"]
mod storage;
#[path = "support/device_where_values.rs"]
mod values;

use fixture::{Case, Fixture, Scenario};
use recorder::Events;

const ORIGIN: &str = "http://account-user-auth-boundary.test";
const SECRET: &str = "account-user-auth-boundary-fixture-secret-at-least-32-characters";
const ID_TOKEN: &str = "account-user-auth-fixture-id-token";
const NONCE: &str = "account-user-auth-fixture-nonce";
const PASSWORD: &str = "account-user-auth-fixture-password";
const PASSWORD_HASH: &str = "account-user-auth-fixture-password-hash";
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    database: Option<&DatabaseConnection>,
    scenario: &Scenario,
    case: &Case,
) -> TestResult {
    storage::seed(raw.as_ref(), scenario).await?;
    let before = storage::snapshot(raw.as_ref(), database, &[]).await?;
    storage::assert_snapshot(&before, &case.before, database.is_some(), case);
    let events = Events::default();
    let options = config::configured(scenario, case.joins, Some(&events))?;
    let store = raw.with_runtime(
        Arc::new(options.clone()),
        vec![Arc::new(hooks::Hooks(events.clone()))],
        Default::default(),
    )?;
    let harness = http::auth(store, options, scenario, &events).await?;
    let request = match (&harness.flow, &case.setup) {
        (Some(flow), Some(setup)) => {
            let request = events
                .capture(flow.prepare(harness.auth.clone(), setup, &case.request))
                .await?;
            assert!(
                events.take()?.is_empty(),
                "OAuth setup must not run database or provider callbacks"
            );
            assert_eq!(
                storage::snapshot(raw.as_ref(), database, &[]).await?,
                before
            );
            request
        }
        (None, None) => case.request.clone(),
        _ => return Err("OAuth setup must match the callback scenario".into()),
    };
    let start = chrono::Utc::now().timestamp_millis();
    let response = events
        .capture(http::request(harness.auth, &request))
        .await?;
    let end = chrono::Utc::now().timestamp_millis();
    let mut observed = events.take()?;
    if let Some(flow) = &harness.flow {
        flow.verify_and_normalize(&mut observed)?;
        assert_eq!(case.checked["oauthStateAndCodeVerifierVerified"], true);
    } else {
        assert!(
            case.checked
                .get("oauthStateAndCodeVerifierVerified")
                .is_none()
        );
    }
    let tokens = observe::issued_tokens(&observed)?;
    let mut after = storage::snapshot(raw.as_ref(), database, &tokens).await?;
    let anchors = observe::verify_dynamic(&observed, &after, case, start, end)?;
    observe::normalize(&mut observed, &mut after, &anchors)?;
    observe::assert_events(&observed, &case.events, case)?;
    storage::assert_snapshot(&after, &case.after, database.is_some(), case);
    http::assert_response(response, &case.response, &anchors)?;
    observe::assert_checked(case, scenario, &anchors, &observed);
    Ok(())
}

#[tokio::test]
async fn memory_account_user_auth_boundaries_match_upstream_http() -> TestResult {
    let fixture = Fixture::read()?;
    for case in fixture.cases.iter().filter(|case| case.backend == "memory") {
        let raw = Arc::new(EphemeralStore::new(Arc::new(config::baseline())));
        contract(raw, None, fixture.scenario(&case.scenario)?, case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_account_user_auth_boundaries_match_upstream_http() -> TestResult {
    let fixture = Fixture::read()?;
    for case in fixture.cases.iter().filter(|case| case.backend == "sqlite") {
        let database = storage::sqlite(fixture.scenario(&case.scenario)?).await?;
        let raw = Arc::new(SeaOrmStore::<models::Core>::new(
            config::baseline(),
            database.clone(),
        ));
        contract(
            raw,
            Some(&database),
            fixture.scenario(&case.scenario)?,
            case,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn memory_account_user_profile_overrides_match_upstream_http() -> TestResult {
    let fixture = Fixture::read_overrides()?;
    for case in fixture.cases.iter().filter(|case| case.backend == "memory") {
        let raw = Arc::new(EphemeralStore::new(Arc::new(config::baseline())));
        contract(raw, None, fixture.scenario(&case.scenario)?, case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_account_user_profile_overrides_match_upstream_http() -> TestResult {
    let fixture = Fixture::read_overrides()?;
    for case in fixture.cases.iter().filter(|case| case.backend == "sqlite") {
        let database = storage::sqlite(fixture.scenario(&case.scenario)?).await?;
        let raw = Arc::new(SeaOrmStore::<models::Core>::new(
            config::baseline(),
            database.clone(),
        ));
        contract(
            raw,
            Some(&database),
            fixture.scenario(&case.scenario)?,
            case,
        )
        .await?;
    }
    Ok(())
}
