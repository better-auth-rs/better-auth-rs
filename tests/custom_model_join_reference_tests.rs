#![cfg(feature = "seaorm2")]

use async_trait::async_trait;
use better_auth::BetterAuth;
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse,
    AuthResult, AuthRoute, AuthSchema, AuthStore, CreateAccount, CreateUser, FieldDate, FieldMap,
    FieldValue, ListUsersParams, UserView,
    store::{EphemeralStore, JoinValue},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
    },
};
use better_auth_seaorm::{SeaOrmStore, sea_orm::DatabaseConnection};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

#[path = "account_user_auth_boundary_reference_tests/models.rs"]
mod core_models;
#[path = "custom_model_join_reference_tests/models.rs"]
mod models;
#[path = "session_user_join_reference_tests/recorder.rs"]
mod recorder;
#[path = "custom_model_join_reference_tests/storage.rs"]
mod storage;
#[path = "support/device_where_values.rs"]
mod values;

use recorder::Events;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn field(events: Option<&Events>, model: &'static str, name: &'static str) -> UserFieldConfig {
    UserFieldConfig {
        transform: events.cloned().map(|events| FieldTransforms {
            output: Some(UserFieldTransform::new(move |value| {
                events.push(json!([
                    "output",
                    format!("{model}.{name}"),
                    values::observe(&value)?
                ]))?;
                Ok(value)
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn config(reference: Option<&str>, joins: bool, events: Option<&Events>) -> AuthConfig {
    let mut config =
        AuthConfig::new("custom-model-join-reference-contract-at-least-thirty-two-characters");
    config.base_url = "http://custom-model-join-reference.test".into();
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.advanced.database.joins = Some(joins);
    config.user.fields_mut().extend([
        (
            "name".into(),
            UserFieldConfig {
                required: Some(true),
                ..field(events, "user", "name")
            },
        ),
        ("image".into(), field(events, "user", "image")),
    ]);
    config.account.additional_fields.extend([
        (
            "accountId".into(),
            UserFieldConfig {
                required: Some(true),
                ..field(events, "account", "accountId")
            },
        ),
        (
            "userId".into(),
            UserFieldConfig {
                required: Some(true),
                references: Some(UserFieldReference {
                    model: "user".into(),
                    field: "id".into(),
                    ..Default::default()
                }),
                ..field(events, "account", "userId")
            },
        ),
        (
            "badgeId".into(),
            UserFieldConfig {
                references: reference.map(|model| UserFieldReference {
                    model: model.into(),
                    field: "id".into(),
                    ..Default::default()
                }),
                ..field(events, "account", "badgeId")
            },
        ),
    ]);
    config
}

struct Badge(Events);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Badge {
    fn name(&self) -> &'static str {
        "custom-model-join-reference"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_custom_model(
            "badge",
            None,
            UserConfig {
                additional_fields: Some(
                    [("label".into(), field(Some(&self.0), "badge", "label"))].into(),
                ),
            },
        )
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

async fn user_fields(user: &UserView, config: &AuthConfig) -> AuthResult<FieldValue> {
    Ok(FieldMap::from(
        UserView::with_internal_fields(user, &config.user, &Default::default()).await?,
    )
    .into())
}

async fn operation<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    config: &AuthConfig,
    input: &Value,
) -> AuthResult<FieldValue> {
    if input["name"] == "user-control" {
        return match store.get_user_by_id("user-a").await? {
            Some(user) => user_fields(&user, config).await,
            None => Ok(FieldValue::Null),
        };
    }
    let missing = input["missing"] == true;
    if input["relationship"] == "accounts" {
        let email = if missing {
            "missing@custom-model-join-reference.test"
        } else {
            "a@custom-model-join-reference.test"
        };
        let Some(result) = store.get_user_with_accounts(email).await? else {
            return Ok(FieldValue::Null);
        };
        let JoinValue::Many(accounts) = result.accounts else {
            return Err(AuthError::internal("Expected the native Account page"));
        };
        return Ok(FieldMap::from([
            ("user".into(), FieldMap::from(result.user).into()),
            (
                "accounts".into(),
                accounts
                    .into_iter()
                    .map(|account| account.internal_fields().map(FieldValue::from))
                    .collect::<AuthResult<Vec<_>>>()?
                    .into(),
            ),
        ])
        .into());
    }
    let account_id = if missing {
        "missing-external"
    } else {
        "external-a"
    };
    let Some(result) = store.get_account_owner("provider", account_id).await? else {
        return Ok(FieldValue::Null);
    };
    let JoinValue::One(Some(user)) = result.user else {
        return Err(AuthError::internal("Expected the native Account owner"));
    };
    Ok(FieldMap::from([
        ("kind".into(), "owned".into()),
        ("user".into(), FieldMap::from(user).into()),
        ("account".into(), result.account.internal_fields()?.into()),
    ])
    .into())
}

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    database: Option<&DatabaseConnection>,
    scenario: &Value,
    case: &Value,
) -> TestResult {
    storage::seed(raw.as_ref()).await?;
    let before = storage::snapshot(raw.as_ref(), database).await?;
    storage::assert_snapshot(&before, &case["before"], database.is_some());
    let reference = scenario["reference"].as_str();
    let joins = case["joins"].as_bool().ok_or("Missing joins option")?;
    let operations = case["operations"].as_array().ok_or("Missing operations")?;
    assert_eq!(operations.len(), 10);
    let mut paired = 0;
    for expected in operations.iter().filter(|operation| {
        operation["surface"] == "internal" || operation["name"] == "user-control"
    }) {
        let events = Events::default();
        let config = config(reference, joins, Some(&events));
        let builder = BetterAuth::new(config.clone()).store_arc(raw.clone());
        let auth = if scenario["declared"] == true {
            builder.plugin(Badge(events.clone())).build().await?
        } else {
            builder.build().await?
        };
        assert_eq!(
            events.take()?,
            json!([]),
            "Declarations must not execute field callbacks"
        );
        let result = operation(auth.store().as_ref(), &config, expected)
            .with_subscriber(tracing_subscriber::registry().with(events.clone()))
            .await;
        assert_eq!(events.take()?, expected["events"], "{case}");
        match result {
            Ok(value) => {
                assert_eq!(expected["returned"], true, "{expected}");
                assert_eq!(value, values::revive(&expected["result"])?, "{expected}");
                assert_eq!(value.json()?, Some(expected["json"].clone()), "{expected}");
                if value.is_null() {
                    assert_eq!(expected["keyOrder"], json!([]));
                } else {
                    println!(
                        "Unpaired property order: {} {:?}",
                        expected["name"], expected["keyOrder"]
                    );
                }
            }
            Err(error) => {
                assert_eq!(expected["returned"], false, "{expected}: {error:?}");
                assert!(matches!(error, AuthError::Config(_)), "{error:?}");
                let expected_error = expected.get("error").ok_or("Missing captured error")?;
                assert_eq!(
                    error.instrumentation_message(),
                    expected_error
                        .get("message")
                        .and_then(Value::as_str)
                        .ok_or("Missing captured error message")?
                );
                assert_eq!(
                    expected_error
                        .get("name")
                        .and_then(Value::as_str)
                        .ok_or("Missing captured error name")?,
                    "BetterAuthError"
                );
                assert_eq!(
                    expected_error
                        .get("properties")
                        .ok_or("Missing captured error properties")?,
                    &json!({"name":"BetterAuthError"})
                );
                assert_eq!(
                    expected_error
                        .get("keys")
                        .ok_or("Missing captured error keys")?,
                    &json!(["name"])
                );
            }
        }
        assert_eq!(expected["storageUnchanged"], true);
        assert_eq!(
            storage::snapshot(raw.as_ref(), database).await?,
            before,
            "{case}"
        );
        paired += 1;
    }
    assert_eq!(paired, 5);
    storage::assert_snapshot(
        &storage::snapshot(raw.as_ref(), database).await?,
        &case["after"],
        database.is_some(),
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract asserts complete fixture inventory before pairing native reads"
)]
async fn custom_model_references_preserve_native_user_account_reads() -> TestResult {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/custom-model-join-reference-1.7.6.json"
    ))?;
    assert_eq!(
        fixture
            .get("version")
            .and_then(Value::as_str)
            .ok_or("Missing fixture version")?,
        "1.7.6"
    );
    let scenarios = fixture
        .get("scenarios")
        .and_then(Value::as_array)
        .ok_or("Missing scenarios")?;
    assert_eq!(scenarios.len(), 4);
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("Missing cases")?;
    assert_eq!(cases.len(), 16);
    for case in cases {
        let scenario = scenarios
            .iter()
            .find(|scenario| scenario["name"] == case["scenario"])
            .ok_or("Unknown captured scenario")?;
        let baseline = config(None, false, None);
        match case["backend"].as_str() {
            Some("memory") => {
                contract(
                    Arc::new(EphemeralStore::new(Arc::new(baseline))),
                    None,
                    scenario,
                    case,
                )
                .await?
            }
            Some("sqlite") => {
                let database = storage::sqlite().await?;
                contract(
                    Arc::new(SeaOrmStore::<models::Core>::new(baseline, database.clone())),
                    Some(&database),
                    scenario,
                    case,
                )
                .await?;
            }
            value => return Err(format!("Unknown backend: {value:?}").into()),
        }
    }
    Ok(())
}
