#![cfg(feature = "seaorm2")]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateSession,
    CreateUser, CreateVerification, FieldMap, FieldValue, SchemaValue, UpdateUser, UserView,
    store::EphemeralStore,
    types::ListUsersParams,
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::Database,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::{
    future::Future,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, oneshot};

struct Call {
    field: &'static str,
    value: FieldValue,
    reply: oneshot::Sender<AuthResult<FieldValue>>,
}

#[derive(Clone, Default)]
struct Gate(Arc<Mutex<Option<mpsc::UnboundedSender<Call>>>>);

impl Gate {
    fn callback(&self, field: &'static str) -> UserFieldTransform {
        let gate = self.clone();
        UserFieldTransform::new_async(move |value| {
            let gate = gate.clone();
            async move {
                let sender = gate
                    .0
                    .lock()
                    .map_err(|_| AuthError::internal("Callback gate lock poisoned"))?
                    .clone();
                let Some(sender) = sender else {
                    return Ok(value);
                };
                let (reply, result) = oneshot::channel();
                sender
                    .send(Call {
                        field,
                        value,
                        reply,
                    })
                    .map_err(|_| AuthError::internal("Callback controller closed"))?;
                result
                    .await
                    .map_err(|_| AuthError::internal("Callback answer missing"))?
            }
        })
    }

    fn arm(&self) -> AuthResult<mpsc::UnboundedReceiver<Call>> {
        let (sender, receiver) = mpsc::unbounded_channel();
        *self
            .0
            .lock()
            .map_err(|_| AuthError::internal("Callback gate lock poisoned"))? = Some(sender);
        Ok(receiver)
    }

    fn disarm(&self) -> AuthResult<()> {
        *self
            .0
            .lock()
            .map_err(|_| AuthError::internal("Callback gate lock poisoned"))? = None;
        Ok(())
    }
}

async fn next(receiver: &mut mpsc::UnboundedReceiver<Call>) -> AuthResult<Call> {
    receiver
        .recv()
        .await
        .ok_or_else(|| AuthError::internal("Expected a field callback"))
}

fn answer(call: Call, value: AuthResult<Option<Value>>) -> AuthResult<()> {
    let value = value.and_then(|value| {
        value
            .map(FieldValue::from_json)
            .transpose()
            .map(|value| value.unwrap_or(FieldValue::Undefined))
    });
    call.reply
        .send(value)
        .map_err(|_| AuthError::internal("Field callback was cancelled"))
}

async fn drive<T>(
    gate: &Gate,
    operation: impl Future<Output = AuthResult<T>>,
    expected: Vec<(&'static str, Value, AuthResult<Option<Value>>)>,
) -> AuthResult<T> {
    let mut receiver = gate.arm()?;
    let controller = async {
        for (field, value, result) in expected {
            let call = next(&mut receiver).await?;
            assert_eq!(call.field, field);
            assert_eq!(call.value, FieldValue::from_json(value)?);
            answer(call, result)?;
        }
        AuthResult::Ok(())
    };
    let (result, controlled) = tokio::join!(operation, controller);
    gate.disarm()?;
    controlled?;
    result
}

fn field(gate: &Gate, input: &'static str, output: &'static str) -> UserFieldConfig {
    UserFieldConfig {
        transform: Some(FieldTransforms {
            input: Some(gate.callback(input)),
            output: Some(gate.callback(output)),
        }),
        ..Default::default()
    }
}

fn write_config(gate: &Gate) -> AuthConfig {
    let mut config = AuthConfig::default();
    let _ = config
        .user
        .fields_mut()
        .insert("name".into(), field(gate, "user.input", "user.output"));
    let _ = config.account.additional_fields.insert(
        "scope".into(),
        field(gate, "account.input", "account.output"),
    );
    let _ = config.session.fields_mut().insert(
        "userAgent".into(),
        field(gate, "session.input", "session.output"),
    );
    let _ = config.verification.additional_fields.insert(
        "value".into(),
        field(gate, "verification.input", "verification.output"),
    );
    config
}

fn answers(
    input: &'static str,
    output: &'static str,
) -> Vec<(&'static str, Value, AuthResult<Option<Value>>)> {
    vec![
        (input, json!("source"), Ok(Some(json!("stored")))),
        (
            output,
            json!("stored"),
            Ok(Some(json!({"resolved":"stored"}))),
        ),
    ]
}

async fn check_writes<S: AuthSchema>(store: &impl AuthStore<S>, gate: &Gate) -> AuthResult<()> {
    let user = drive(
        gate,
        store.create_user(
            CreateUser::new()
                .with_name("source")
                .with_email("normal@async.test"),
        ),
        answers("user.input", "user.output"),
    )
    .await?;
    assert_eq!(user.name.json()?, Some(json!({"resolved":"stored"})));
    let id = user.id.typed()?.clone();
    let raw = store
        .get_user_by_id(&id)
        .await?
        .ok_or(AuthError::UserNotFound)?;
    assert_eq!(raw.name.json()?, Some(json!("stored")));
    let updated = drive(
        gate,
        store.update_user(
            &id,
            UpdateUser {
                name: SchemaValue::from_json(Some(json!("source")))?,
                ..Default::default()
            },
        ),
        answers("user.input", "user.output"),
    )
    .await?;
    assert_eq!(updated.name.json()?, Some(json!({"resolved":"stored"})));

    let account = drive(
        gate,
        store.create_account(CreateAccount {
            account_id: "normal-account".into(),
            provider_id: "ordinary".into(),
            user_id: id.clone().into(),
            scope: Some("source".into()).into(),
            ..Default::default()
        }),
        answers("account.input", "account.output"),
    )
    .await?;
    assert_eq!(account.scope.json()?, Some(json!({"resolved":"stored"})));
    let session = drive(
        gate,
        store.create_session(CreateSession {
            user_id: id.clone().into(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
            ip_address: None,
            user_agent: Some("source".into()),
            impersonated_by: None,
            active_organization_id: None,
            additional_fields: FieldMap::from_iter([("userAgent".into(), "source".into())]),
        }),
        answers("session.input", "session.output"),
    )
    .await?;
    assert_eq!(
        session.additional_fields.get("userAgent"),
        Some(&FieldValue::from_json(json!({"resolved":"stored"}))?)
    );
    let verification = drive(
        gate,
        store.create_verification(CreateVerification {
            identifier: "ordinary".into(),
            value: "source".into(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
            ..Default::default()
        }),
        answers("verification.input", "verification.output"),
    )
    .await?;
    assert_eq!(
        verification.value.json()?,
        Some(json!({"resolved":"stored"}))
    );

    let failed = drive(
        gate,
        store.create_user(
            CreateUser::new()
                .with_name("source")
                .with_email("input-error@async.test"),
        ),
        vec![(
            "user.input",
            json!("source"),
            Err(AuthError::Config("ordinary input rejection".into())),
        )],
    )
    .await;
    assert!(
        matches!(failed, Err(AuthError::Config(message)) if message == "ordinary input rejection")
    );
    assert!(
        store
            .get_user_by_email("input-error@async.test")
            .await?
            .is_none()
    );
    let failed = drive(
        gate,
        store.create_user(
            CreateUser::new()
                .with_name("source")
                .with_email("output-error@async.test"),
        ),
        vec![
            ("user.input", json!("source"), Ok(Some(json!("stored")))),
            (
                "user.output",
                json!("stored"),
                Err(AuthError::Config("ordinary output rejection".into())),
            ),
        ],
    )
    .await;
    assert!(
        matches!(failed, Err(AuthError::Config(message)) if message == "ordinary output rejection")
    );
    let retained = store
        .get_user_by_email("output-error@async.test")
        .await?
        .ok_or(AuthError::UserNotFound)?;
    assert_eq!(retained.name.json()?, Some(json!("stored")));
    for replacement in [None, Some(Value::Null)] {
        let projected = drive(
            gate,
            async {
                store
                    .get_user_by_id(&id)
                    .await?
                    .ok_or(AuthError::UserNotFound)
            },
            vec![("user.output", json!("stored"), Ok(replacement.clone()))],
        )
        .await?;
        assert_eq!(projected.name.json()?, replacement);
    }
    Ok(())
}

fn batch_config(gate: &Gate) -> AuthConfig {
    let mut config = AuthConfig::default();
    for name in ["name", "image"] {
        let _ = config.user.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(gate.callback(name)),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    config
}

async fn observe_batch<S: AuthSchema>(
    store: &impl AuthStore<S>,
    config: &AuthConfig,
    gate: &Gate,
) -> AuthResult<Value> {
    for name in ["A", "B"] {
        let mut user = CreateUser::new()
            .with_name(name)
            .with_email(format!("{name}@batch-async.test"));
        user.image = Some(format!("{name}.png")).into();
        let _ = store.create_user(user).await?;
    }
    let mut receiver = gate.arm()?;
    let controller = async {
        let a = next(&mut receiver).await?;
        let b = next(&mut receiver).await?;
        assert_eq!((a.field, &a.value), ("name", &FieldValue::from("A")));
        assert_eq!((b.field, &b.value), ("name", &FieldValue::from("B")));
        answer(b, Ok(Some(json!("B:resolved"))))?;
        let image_b = next(&mut receiver).await?;
        assert_eq!(
            (image_b.field, &image_b.value),
            ("image", &FieldValue::from("B.png"))
        );
        answer(image_b, Ok(Some(json!("B.png:resolved"))))?;
        answer(a, Ok(Some(json!("A:resolved"))))?;
        let image_a = next(&mut receiver).await?;
        assert_eq!(
            (image_a.field, &image_a.value),
            ("image", &FieldValue::from("A.png"))
        );
        answer(image_a, Ok(Some(json!("A.png:resolved"))))?;
        AuthResult::Ok(vec!["name:A", "name:B", "image:B.png", "image:A.png"])
    };
    let (rows, trace) = tokio::join!(
        store.list_users(ListUsersParams {
            sort_by: Some("email".into()),
            sort_direction: Some("asc".into()),
            ..Default::default()
        }),
        controller
    );
    let (rows, count) = rows?;
    assert_eq!(count, 2);
    let values = rows
        .iter()
        .map(|row| Ok(json!({"name":row.name.json()?, "image":row.image.json()?})))
        .collect::<AuthResult<Vec<_>>>()?;
    assert_eq!(
        values,
        [
            json!({"name":"A:resolved","image":"A.png:resolved"}),
            json!({"name":"B:resolved","image":"B.png:resolved"})
        ]
    );
    for row in &rows {
        let _ = UserView::with_fields(row, &config.user, &Default::default()).await?;
    }
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    gate.disarm()?;
    Ok(json!({"trace":trace?,"values":values}))
}

async fn sqlite(config: AuthConfig) -> AuthResult<SeaOrmStore<BundledSchema>> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    migrator::run_migrations(&database)
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    Ok(SeaOrmStore::new(config, database))
}

#[tokio::test]
async fn core_adapters_await_values_and_propagate_errors() -> AuthResult<()> {
    let gate = Gate::default();
    check_writes(&EphemeralStore::new(write_config(&gate).into()), &gate).await?;
    check_writes(&sqlite(write_config(&gate)).await?, &gate).await
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report callback contract mismatches; Result propagates fixture setup errors"
)]
async fn core_async_batches_match_the_upstream_success_fixture() -> AuthResult<()> {
    let gate = Gate::default();
    let config = batch_config(&gate);
    let memory = observe_batch(&EphemeralStore::new(config.clone().into()), &config, &gate).await?;
    let sql = observe_batch(&sqlite(config.clone()).await?, &config, &gate).await?;
    let expected: Value =
        serde_json::from_str(include_str!("fixtures/async-transform-upstream.json"))?;
    assert_eq!(json!({"memory":memory,"sqlite":sql}), expected);
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report callback contract mismatches; Result propagates fixture setup errors"
)]
async fn synchronous_input_rejects_async_callbacks_while_organization_adapters_await()
-> AuthResult<()> {
    let callback = UserFieldTransform::new_async(|value| async move { Ok(value) });
    let mut config = UserConfig {
        additional_fields: Some(
            [(
                "label".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        input: Some(callback.clone()),
                        output: Some(callback),
                    }),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    let input = FieldMap::from_iter([("label".into(), "normal".into())]);
    assert!(matches!(
        config.parse_input(&input, true),
        Err(AuthError::Config(_))
    ));
    assert_eq!(
        config
            .organization_storage_fields(Default::default(), input.clone(), true)
            .await?,
        input
    );
    assert_eq!(
        config
            .organization_output_records(
                vec![better_auth_core::user_fields::AdapterRecord::new(
                    Default::default(),
                    input.clone()
                )],
                true
            )
            .await?,
        vec![input.clone()]
    );
    config
        .fields_mut()
        .get_mut("label")
        .ok_or_else(|| AuthError::internal("Fixture field missing"))?
        .validator = Some(better_auth_core::user_fields::FieldValidators {
        input: Some(Arc::new(Ok)),
        ..Default::default()
    });
    assert_eq!(config.parse_input(&input, true)?, input);
    assert_eq!(config.storage_fields(input.clone(), true).await?, input);
    Ok(())
}
