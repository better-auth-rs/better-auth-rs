#![cfg(feature = "seaorm2")]
#![expect(
    clippy::expect_used,
    reason = "Tracing callbacks cannot return errors; a poisoned fixture recorder must fail the test immediately."
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateUser,
    store::EphemeralStore,
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldReference, UserFieldTransform},
    wire::{AccountView, UserView},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, Schema},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
    store::entities,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tracing::{Subscriber, field::Visit, instrument::WithSubscriber};
use tracing_subscriber::{Layer, layer::Context, prelude::*};

const EMAIL: &str = "owner@schema-join-reference.test";

#[path = "schema_join_reference_tests/unknown.rs"]
mod unknown;

#[path = "native_core_join_tests/account.rs"]
#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture types"
)]
mod alias_account;

struct AliasSchema;
impl AuthSchema for AliasSchema {
    type User = entities::user::Model;
    type Session = entities::session::Model;
    type Account = alias_account::Model;
    type Verification = entities::verification::Model;
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Mode {
    Default,
    Removed,
    AccountDuplicate,
    UserDuplicate,
    Alias,
    AccountMixedDuplicate,
    UserMixedDuplicate,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Operation {
    Accounts,
    Owner,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Backend {
    Memory,
    Sqlite,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Case {
    backend: Backend,
    joins: bool,
    mode: Mode,
    populated: bool,
    operation: Operation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tables: Option<Tables>,
    events: Vec<Value>,
    result: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Tables {
    user: String,
    account: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    version: String,
    cases: Vec<Case>,
}

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<Value>>>, bool);

impl Events {
    fn push(&self, event: Value) {
        self.0
            .lock()
            .expect("fixture recorder must remain available")
            .push(event);
    }

    fn take(&self) -> Vec<Value> {
        std::mem::take(
            &mut *self
                .0
                .lock()
                .expect("fixture recorder must remain available"),
        )
    }
}

#[derive(Default)]
struct SpanName(Option<String>);

impl Visit for SpanName {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "otel.name" {
            self.0 = Some(value.to_owned());
        }
    }
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
}

impl<S: Subscriber> Layer<S> for Events {
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        _: &tracing::Id,
        _: Context<'_, S>,
    ) {
        if attributes.metadata().target() != "better-auth" {
            return;
        }
        let mut name = SpanName::default();
        attributes.record(&mut name);
        let Some(name) = name.0 else {
            return;
        };
        let Some(operation) = name.strip_prefix("db ") else {
            return;
        };
        let Some((operation, table)) = operation.split_once(' ') else {
            return;
        };
        // Alias cases compare physical table names; the original contract uses logical names.
        let model = match (self.1, table) {
            (false, "users") => "user",
            (false, "accounts") => "account",
            (_, name) => name,
        };
        self.push(json!(["query", operation, model]));
    }
}

fn reference(model: &str) -> UserFieldReference {
    UserFieldReference {
        model: model.into(),
        field: "id".into(),
    }
}

fn output(name: &'static str, events: &Events) -> UserFieldConfig {
    let events = events.clone();
    UserFieldConfig {
        required: Some(true),
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new(move |value| {
                events.push(json!(["output", name, value]));
                Ok(value)
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn config(case: &Case, events: &Events) -> AuthConfig {
    let mut config = AuthConfig::default();
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.advanced.database.joins = Some(case.joins);
    let mut name = output("user.name", events);
    if matches!(case.mode, Mode::UserDuplicate | Mode::UserMixedDuplicate) {
        name.references = Some(reference("account"));
        let _ = config.user.fields_mut().insert(
            "image".into(),
            UserFieldConfig {
                required: Some(false),
                references: Some(reference(
                    case.tables
                        .as_ref()
                        .map_or("account", |tables| &tables.account),
                )),
                ..Default::default()
            },
        );
    }
    let _ = config.user.fields_mut().insert("name".into(), name);
    let _ = config
        .account
        .additional_fields
        .insert("accountId".into(), output("account.accountId", events));
    if let Some(tables) = &case.tables {
        let _ = config.account.additional_fields.insert(
            "userId".into(),
            UserFieldConfig {
                required: Some(true),
                references: Some(reference(&tables.user)),
                ..Default::default()
            },
        );
    }
    match case.mode {
        Mode::Removed => {
            let _ = config.account.additional_fields.insert(
                "userId".into(),
                UserFieldConfig {
                    required: Some(true),
                    ..Default::default()
                },
            );
        }
        Mode::AccountDuplicate | Mode::AccountMixedDuplicate => {
            let _ = config.account.additional_fields.insert(
                "accessToken".into(),
                UserFieldConfig {
                    required: Some(false),
                    references: Some(reference("user")),
                    ..Default::default()
                },
            );
        }
        Mode::Default | Mode::UserDuplicate | Mode::Alias | Mode::UserMixedDuplicate => {}
    }
    config
}

fn user_summary(user: &UserView) -> Value {
    json!({ "id": user.id, "name": user.name, "image": user.image })
}

fn account_summary(account: &AccountView) -> Value {
    json!({ "id": account.id, "accountId": account.account_id, "userId": account.user_id, "accessToken": account.access_token })
}

async fn observe<S: AuthSchema>(
    store: &impl AuthStore<S>,
    case: &Case,
    events: &Events,
) -> AuthResult<Case> {
    if case.populated {
        let _ = store
            .create_user(CreateUser {
                id: Some("owner".into()),
                name: Some("Owner".into()).into(),
                email: Some(EMAIL.into()),
                email_verified: Some(true),
                image: Some("owner-image".into()).into(),
                ..Default::default()
            })
            .await?;
        let _ = store
            .create_account(CreateAccount {
                id: "account".into(),
                user_id: "owner".into(),
                account_id: "external-owner".into(),
                provider_id: "provider".into(),
                access_token: Some("original-access".into()).into(),
                ..Default::default()
            })
            .await?;
    }
    let _ = events.take();
    let result: AuthResult<Value> = async {
        match case.operation {
            Operation::Accounts => Ok(store.get_user_with_accounts(EMAIL).await?.map_or(Value::Null, |joined| {
                json!({ "user": user_summary(&joined.user), "accounts": joined.accounts.iter().map(account_summary).collect::<Vec<_>>() })
            })),
            Operation::Owner => Ok(store.get_account_owner("provider", "external-owner").await?.map_or(Value::Null, |joined| {
                json!({ "account": account_summary(&joined.account), "user": joined.user.as_ref().map(user_summary) })
            })),
        }
    }.with_subscriber(tracing_subscriber::registry().with(events.clone())).await;
    let result = match result {
        Ok(value) => value,
        Err(error) => json!({ "error": error.instrumentation_message() }),
    };
    let observed = events.take();
    let invalid = matches!(
        case.mode,
        Mode::Removed | Mode::AccountDuplicate | Mode::AccountMixedDuplicate
    ) || (matches!(case.mode, Mode::UserDuplicate | Mode::UserMixedDuplicate)
        && case.operation == Operation::Owner);
    if invalid {
        assert!(result.get("error").is_some());
        assert!(
            observed.is_empty(),
            "Reference errors must precede raw reads and output callbacks"
        );
    } else {
        assert!(result.get("error").is_none());
        assert_eq!(result.is_null(), !case.populated);
        assert!(
            observed
                .iter()
                .any(|event| event.get(0) == Some(&json!("query")))
        );
    }
    Ok(Case {
        events: observed,
        result,
        ..case.clone()
    })
}

#[tokio::test]
async fn final_account_user_references_match_upstream_before_any_read() -> AuthResult<()> {
    contract("schema-join-reference-1.7.6.json", 64).await
}

#[tokio::test]
async fn account_user_references_accept_actual_table_names_and_detect_mixed_duplicates()
-> AuthResult<()> {
    contract("schema-join-reference-alias-1.7.6.json", 48).await
}

async fn contract(name: &str, count: usize) -> AuthResult<()> {
    let fixture: Fixture = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .map_err(|error| AuthError::internal(error.to_string()))?,
    )?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.cases.len(), count);
    for expected in fixture.cases {
        let events = Events(Default::default(), expected.tables.is_some());
        let config = config(&expected, &events);
        let actual = match expected.backend {
            Backend::Memory => {
                observe(&EphemeralStore::new(Arc::new(config)), &expected, &events).await?
            }
            Backend::Sqlite => {
                let database = Database::connect("sqlite::memory:")
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                migrator::run_migrations(&database)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                if expected
                    .tables
                    .as_ref()
                    .is_some_and(|tables| tables.account == "native_accounts")
                {
                    let backend = database.get_database_backend();
                    let statement =
                        Schema::new(backend).create_table_from_entity(alias_account::Entity);
                    let _ = database
                        .execute_raw(backend.build(&statement))
                        .await
                        .map_err(|error| AuthError::internal(error.to_string()))?;
                    observe(
                        &SeaOrmStore::<AliasSchema>::new(config, database),
                        &expected,
                        &events,
                    )
                    .await?
                } else {
                    observe(
                        &SeaOrmStore::<BundledSchema>::new(config, database),
                        &expected,
                        &events,
                    )
                    .await?
                }
            }
        };
        assert_eq!(actual, expected);
    }
    Ok(())
}
