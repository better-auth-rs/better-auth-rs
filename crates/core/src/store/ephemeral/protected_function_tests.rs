#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Pinned fixture keys and setup must fail immediately when the protected function contract changes"
)]

// Compare complete User rows and callback counts.
// Admission, JavaScript this/arguments, and reflection remain outside this contract.
use crate::{
    AuthConfig, AuthError, AuthResult, AuthStore, FieldFunction, FieldMap, FieldValue, UpdateUser,
    UserView,
    id::{IdGeneration, IdGenerator},
    store::{
        EphemeralStore, RuntimeStore, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
        transaction,
    },
    user_fields::{
        FieldTransforms, FieldValidators, UserFieldConfig, UserFieldFactory, UserFieldTransform,
        UserFieldType,
    },
};
use serde_json::Value;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use support::{fixture, observe, operation, user};

mod support {
    use crate as better_auth_core;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/protected_function_tests/support.rs"
    ));
}

const CALLBACKS: [&str; 8] = [
    "factory",
    "returnedFunction",
    "validator",
    "input",
    "output",
    "before",
    "after",
    "generateId",
];

#[derive(Default)]
struct Counts {
    factory: AtomicUsize,
    returned: AtomicUsize,
    validator: AtomicUsize,
    input: AtomicUsize,
    output: AtomicUsize,
    before: AtomicUsize,
    after: AtomicUsize,
    generate: AtomicUsize,
    hook_rows: Mutex<Vec<(&'static str, FieldMap)>>,
}

impl Counts {
    fn snapshot(&self) -> [u64; 8] {
        [
            &self.factory,
            &self.returned,
            &self.validator,
            &self.input,
            &self.output,
            &self.before,
            &self.after,
            &self.generate,
        ]
        .map(|count| count.load(Ordering::SeqCst) as u64)
    }

    fn check(&self, before: [u64; 8], expected: &Value) {
        for ((name, before), actual) in CALLBACKS.into_iter().zip(before).zip(self.snapshot()) {
            assert_eq!(
                actual - before,
                expected["counts"][name].as_u64().unwrap()
                    - expected["before"]["counts"][name].as_u64().unwrap(),
                "{}: {name}",
                expected["name"]
            );
        }
    }
}

struct Hooks(Arc<Counts>);

#[better_auth::database_hooks()]
impl DatabaseHooks<StatelessSchema> for Hooks {
    async fn before_create_user(
        &self,
        fields: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        let _ = self.0.before.fetch_add(1, Ordering::SeqCst);
        self.0
            .hook_rows
            .lock()
            .unwrap()
            .push(("before", fields.clone()));
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_create_user(
        &self,
        user: Option<&UserView>,
        context: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        assert!(context.transaction.is_none());
        let _ = self.0.after.fetch_add(1, Ordering::SeqCst);
        self.0
            .hook_rows
            .lock()
            .unwrap()
            .push(("after", user.unwrap().clone().into()));
        Ok(())
    }
}

fn date() -> FieldValue {
    "2030-01-02T03:04:05.000Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap()
        .into()
}

fn transform(counts: Arc<Counts>, phase: &'static str, mode: &Value) -> UserFieldTransform {
    let mode = mode.as_str().unwrap_or("identity").to_owned();
    UserFieldTransform::new(move |value| {
        let count = if phase == "input" {
            &counts.input
        } else {
            &counts.output
        };
        let _ = count.fetch_add(1, Ordering::SeqCst);
        let FieldValue::Function(function) = &value else {
            return Ok(value);
        };
        match mode.as_str() {
            "identity" => Ok(value),
            "call" => function.call(),
            "replace" => Ok(format!("{phase}-replacement").into()),
            "throws" => Err(AuthError::internal(format!("protected-{phase}-failed"))),
            _ => Err(AuthError::internal("Unknown protected function transform")),
        }
    })
}

struct Harness {
    config: Arc<AuthConfig>,
    store: Arc<dyn AuthStore<StatelessSchema>>,
    raw: EphemeralStore,
    default: FieldValue,
    returned: FieldValue,
    counts: Arc<Counts>,
}

impl Harness {
    fn new(case: &Value, with_hooks: bool) -> AuthResult<Self> {
        let scenario = &case["observation"]["scenario"];
        let counts = Arc::new(Counts::default());
        let called = counts.clone();
        let returned_factory: UserFieldFactory = Arc::new(move || {
            let _ = called.returned.fetch_add(1, Ordering::SeqCst);
            Ok("returned-function-value".into())
        });
        let returned = FieldValue::Function(FieldFunction::from(returned_factory));
        let result = scenario["result"].as_str().unwrap().to_owned();
        let returned_value = returned.clone();
        let called = counts.clone();
        let factory: UserFieldFactory = Arc::new(move || {
            let _ = called.factory.fetch_add(1, Ordering::SeqCst);
            match result.as_str() {
                "string" => Ok("factory-value".into()),
                "undefined" => Ok(FieldValue::Undefined),
                "date" => Ok(date()),
                "object" => Ok(FieldMap::from([
                    ("source".into(), "factory".into()),
                    ("ownUndefined".into(), FieldValue::Undefined),
                ])
                .into()),
                "function" => Ok(returned_value.clone()),
                "throws" => Err(AuthError::internal("protected-default-failed")),
                _ => Err(AuthError::internal("Unknown protected function result")),
            }
        });
        let default = FieldValue::Function(FieldFunction::from(factory.clone()));
        let mut config =
            AuthConfig::new("protected-function-contract-secret-at-least-32-characters")
                .base_url("http://protected-function.test");
        config.logger.disabled = Some(true);
        config.telemetry.enabled = false;
        let called = counts.clone();
        config.advanced.database.generate_id =
            Some(IdGeneration::Custom(IdGenerator::new(move |request| {
                let sequence = called.generate.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(Some(format!("{}-generated-{sequence}", request.model)))
            })));
        let validated = counts.clone();
        let field = UserFieldConfig {
            field_type: match scenario["fieldType"].as_str() {
                Some("date") => UserFieldType::Date,
                Some("json") => UserFieldType::Json,
                _ => UserFieldType::String,
            },
            required: Some(false),
            input: Some(false),
            returned: Some(scenario["returned"] != false),
            default_value_fn: Some(factory),
            validator: Some(FieldValidators {
                input: Some(Arc::new(move |value| {
                    let _ = validated.validator.fetch_add(1, Ordering::SeqCst);
                    Ok(value)
                })),
                ..Default::default()
            }),
            transform: Some(FieldTransforms {
                input: Some(transform(counts.clone(), "input", &scenario["input"])),
                output: Some(transform(counts.clone(), "output", &scenario["output"])),
            }),
            ..Default::default()
        };
        let _ = config
            .user
            .fields_mut()
            .insert("protectedValue".into(), field);
        let config = Arc::new(config);
        let raw = EphemeralStore::new(config.clone());
        let hooks: Vec<Arc<dyn DatabaseHooks<StatelessSchema>>> = if with_hooks {
            vec![Arc::new(Hooks(counts.clone()))]
        } else {
            Vec::new()
        };
        let store = raw.with_runtime(config.clone(), hooks, Default::default())?;
        Ok(Self {
            config,
            store,
            raw,
            default,
            returned,
            counts,
        })
    }

    fn input(&self, id: &str) -> FieldMap {
        user(
            id,
            FieldMap::from([("protectedValue".into(), self.default.clone())]),
        )
    }

    fn row(&self, row: &UserView) -> AuthResult<Value> {
        observe(
            &FieldMap::from(row.clone()).into(),
            &self.default,
            &self.returned,
        )
    }

    fn outcome(
        &self,
        actual: &AuthResult<Option<UserView>>,
        expected: &Value,
        row: &Value,
    ) -> AuthResult<()> {
        match actual {
            Ok(actual) => {
                assert_eq!(expected["returned"], true);
                let observed = actual
                    .as_ref()
                    .map(|row| self.row(row))
                    .transpose()?
                    .unwrap_or(Value::Null);
                assert_eq!(&observed, row, "{}", expected["name"]);
            }
            Err(error) => check_error(error, expected),
        }
        Ok(())
    }

    fn storage(&self, expected: &Value) -> AuthResult<()> {
        let rows = self.raw.lock()?.users.snapshot()?;
        let rows = rows
            .iter()
            .map(|row| self.row(row))
            .collect::<AuthResult<Vec<_>>>()?;
        assert_eq!(
            Value::Array(rows),
            expected["storage"]["user"],
            "{}",
            expected["name"]
        );
        Ok(())
    }

    fn hooks(&self, expected: &Value) -> AuthResult<()> {
        let rows = self.counts.hook_rows.lock().unwrap();
        let events: Vec<_> = expected["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| event["phase"] == "before" || event["phase"] == "after")
            .collect();
        assert_eq!(rows.len(), events.len());
        for ((phase, fields), event) in rows.iter().zip(events) {
            assert_eq!(*phase, event["phase"]);
            let observed = observe(&fields.clone().into(), &self.default, &self.returned)?;
            assert_eq!(observed, event["user"]);
            assert_eq!(
                fields["protectedValue"].strict_equals(&self.default),
                event["sameDefault"]
            );
        }
        Ok(())
    }

    async fn public(&self, row: &UserView, expected: &Value) -> AuthResult<()> {
        for policies in [false, true] {
            let before = self.counts.snapshot();
            let result = if policies {
                UserView::with_field_policies(
                    row,
                    &self.config.user,
                    &self.config.user,
                    &Default::default(),
                    true,
                )
                .await
            } else {
                UserView::with_fields(row, &self.config.user, &Default::default()).await
            }
            .map(Some);
            self.outcome(&result, expected, &expected["result"]["user"])?;
            self.counts.check(before, expected);
            self.storage(expected)?;
        }
        Ok(())
    }
}

fn check_error(error: &AuthError, expected: &Value) {
    assert_eq!(expected["returned"], false);
    if expected["error"]["name"] == "DataCloneError" {
        assert!(matches!(error, AuthError::DataClone));
    } else {
        assert_eq!(expected["error"]["name"], "Error");
        assert!(matches!(error, AuthError::Internal(_)));
    }
    assert_eq!(
        error.instrumentation_message(),
        expected["error"]["message"].as_str().unwrap()
    );
}

fn case<'a>(fixture: &'a Value, name: &str) -> &'a Value {
    fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()
}

#[tokio::test]
async fn memory_callable_writes_and_public_output_match_complete_pinned_rows() -> AuthResult<()> {
    let fixture = fixture("memory");
    for name in [
        "raw-string",
        "raw-undefined",
        "raw-date",
        "raw-object",
        "raw-throws",
        "raw-returned-function",
        "hidden-function",
        "input-call",
        "input-replace",
        "input-throws",
        "output-call",
        "output-replace",
        "output-throws",
    ] {
        let case = case(&fixture, name);
        for update in [false, true] {
            let harness = Harness::new(case, false)?;
            let id = if update {
                "updated-user"
            } else {
                "direct-user"
            };
            if update {
                let baseline = match case["observation"]["scenario"]["fieldType"].as_str() {
                    Some("date") => date(),
                    Some("json") => FieldMap::from([("source".into(), "baseline".into())]).into(),
                    _ => "baseline".into(),
                };
                let before = harness.counts.snapshot();
                let input = user(id, FieldMap::from([("protectedValue".into(), baseline)]));
                let seeded = harness.store.create_user_fields_optional(input).await;
                let expected = operation(case, "update:seed");
                harness.outcome(&seeded, expected, &expected["result"])?;
                harness.counts.check(before, expected);
                harness.storage(expected)?;
            }
            let before = harness.counts.snapshot();
            let written = if update {
                let update = UpdateUser {
                    additional_fields: FieldMap::from([
                        ("protectedValue".into(), harness.default.clone()),
                        ("updatedAt".into(), date()),
                    ]),
                    ..Default::default()
                };
                harness.store.update_user(id, update).await.map(Some)
            } else {
                harness
                    .store
                    .create_user_fields_optional(harness.input(id))
                    .await
            };
            let write = if update {
                "update:function"
            } else {
                "direct:create"
            };
            let expected = operation(case, write);
            harness.outcome(&written, expected, &expected["result"])?;
            harness.counts.check(before, expected);
            harness.storage(expected)?;
            let before = harness.counts.snapshot();
            let read = harness.store.get_user_by_id(id).await;
            let expected = operation(case, if update { "update:read" } else { "direct:read" });
            harness.outcome(&read, expected, &expected["result"])?;
            harness.counts.check(before, expected);
            harness.storage(expected)?;
            if let Ok(Some(row)) = read {
                let public = if update {
                    "update:public-output"
                } else {
                    "direct:public-output"
                };
                harness.public(&row, operation(case, public)).await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn committed_callable_blocks_the_next_snapshot_before_transaction_work() -> AuthResult<()> {
    let fixture = fixture("memory");
    for name in [
        "raw-string",
        "input-call",
        "input-replace",
        "output-call",
        "output-replace",
    ] {
        let case = case(&fixture, name);
        let harness = Harness::new(case, false)?;
        let input = harness.input("transaction-user");
        let before = harness.counts.snapshot();
        let created = transaction(harness.store.as_ref(), move |tx| {
            Box::pin(async move { tx.create_user_fields_optional(input).await })
        })
        .await;
        let expected = operation(case, "transaction:create-and-commit");
        harness.outcome(&created, expected, &expected["result"])?;
        harness.counts.check(before, expected);
        harness.storage(expected)?;
        let entered = Arc::new(AtomicUsize::new(0));
        let called = entered.clone();
        let before = harness.counts.snapshot();
        let next: AuthResult<Vec<UserView>> = transaction(harness.store.as_ref(), move |tx| {
            Box::pin(async move {
                let _ = called.fetch_add(1, Ordering::SeqCst);
                Ok(tx
                    .get_user_by_id("transaction-user")
                    .await?
                    .into_iter()
                    .collect())
            })
        })
        .await;
        let expected = operation(case, "transaction:next-snapshot");
        match next {
            Ok(rows) => {
                assert_eq!(expected["returned"], true);
                let rows = rows
                    .iter()
                    .map(|row| harness.row(row))
                    .collect::<AuthResult<Vec<_>>>()?;
                assert_eq!(Value::Array(rows), expected["result"]);
            }
            Err(error) => check_error(&error, expected),
        }
        let entries = expected["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| event["phase"] == "next-transaction:enter")
            .count();
        assert_eq!(entered.load(Ordering::SeqCst), entries);
        harness.counts.check(before, expected);
        harness.storage(expected)?;
    }
    Ok(())
}

#[tokio::test]
async fn transaction_public_clone_failure_discards_callable_rows_and_after_hooks() -> AuthResult<()>
{
    let fixture = fixture("memory");
    for name in [
        "raw-string",
        "hidden-function",
        "input-call",
        "input-replace",
        "input-throws",
        "output-call",
        "output-replace",
        "output-throws",
    ] {
        let case = case(&fixture, name);
        for public in [false, true] {
            let harness = Harness::new(case, true)?;
            let label = if public {
                "internal:transaction-public"
            } else {
                "internal:transaction-native"
            };
            let input = harness.input(&label.replace(':', "-"));
            let config = harness.config.clone();
            let counts = harness.counts.clone();
            let before = harness.counts.snapshot();
            let result = transaction(harness.store.as_ref(), move |tx| {
                Box::pin(async move {
                    let row = tx.create_user_fields_optional(input).await?.unwrap();
                    assert_eq!(counts.after.load(Ordering::SeqCst), 0);
                    if public {
                        UserView::with_fields(&row, &config.user, &Default::default())
                            .await
                            .map(Some)
                    } else {
                        Ok(Some(row))
                    }
                })
            })
            .await;
            let expected = operation(case, label);
            let row = if public {
                &expected["result"]["user"]
            } else {
                &expected["result"]
            };
            harness.outcome(&result, expected, row)?;
            harness.counts.check(before, expected);
            harness.hooks(expected)?;
            harness.storage(expected)?;
        }
    }
    Ok(())
}
