#![expect(
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    reason = "The frozen contract validates complete task counts and fixture structure before comparing native values and ordering."
)]

use super::*;
use crate::plugins::test_helpers::{create_test_config, initialize_test_context};
use better_auth_core::{
    AuthError, FieldDate, FieldFunction, FieldObject, FieldValue,
    background::{BackgroundTask, BackgroundTasks},
    id::{IdGeneration, IdGenerator},
    store::{
        EphemeralStore, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHookControl, DatabaseHooks},
        schema::EntityRole,
    },
    types::CreateVerification,
};
use serde_json::{Value as Json, json};
use std::sync::{
    Mutex, MutexGuard,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::{future::Future, pin::Pin, task::Poll};
use tokio::sync::Notify;

use crate::plugins::test_helpers::native_observation::{NativeObservation, assert_replay};
use crate::plugins::test_helpers::native_source as source;
use source::source_value;

const EMAIL: &str = "override-values@example.com";
const NOW: i64 = 2_000_000_000_000;

struct VerificationClock(chrono::DateTime<chrono::Utc>);

#[better_auth_core::database_hooks()]
impl DatabaseHooks<StatelessSchema> for VerificationClock {
    async fn before_create_verification(
        &self,
        input: &mut CreateVerification,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        let _ = input.created_at.typed()?;
        let _ = input.updated_at.typed()?;
        assert!(
            !input
                .created_at
                .field_value()
                .strict_equals(&input.updated_at.field_value())
        );
        // The source freezes global Date; this hook freezes the Store clock before field policies.
        input.created_at = FieldDate::from(self.0).into();
        input.updated_at = FieldDate::from(self.0).into();
        Ok(DatabaseHookControl::Continue)
    }
}

fn lock<T>(value: &Mutex<T>) -> AuthResult<MutexGuard<'_, T>> {
    value
        .lock()
        .map_err(|_| AuthError::internal("OTP completion observation lock poisoned"))
}

#[derive(Default)]
struct State {
    next_sender: AtomicBool,
    tasks: Mutex<Vec<(bool, BackgroundTask)>>,
    messages: Mutex<Vec<Json>>,
    logs: Mutex<Vec<Json>>,
    events: Mutex<Vec<Json>>,
    entered: Notify,
    registered: Notify,
    gate: Notify,
}

fn database(store: &EphemeralStore) -> AuthResult<Json> {
    let tables = [
        ("user", EntityRole::User),
        ("session", EntityRole::Session),
        ("account", EntityRole::Account),
        ("verification", EntityRole::Verification),
    ]
    .into_iter()
    .map(|(name, role)| {
        Ok((
            name.into(),
            store
                .storage_rows(role)?
                .into_iter()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
        ))
    })
    .collect::<AuthResult<FieldMap>>()?;
    NativeObservation::default().observe(&tables.into())
}

async fn complete(task: BackgroundTask) -> AuthResult<FieldValue> {
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .map_err(|_| AuthError::internal("OTP completion did not settle"))?
        .map_err(|error| AuthError::internal(format!("Unexpected OTP join failure: {error}")))?
}

fn task_states(
    values: &[(bool, Option<FieldValue>)],
    delivery: &FieldValue,
) -> AuthResult<Vec<Json>> {
    values.iter().enumerate().map(|(index, (sender, value))| {
        let state = match value {
            Some(value) => json!({"status":"fulfilled","value":NativeObservation::default().observe(value)?,
                "sameDeliveryValue":value.strict_equals(delivery)}),
            None => json!({"status":"pending"}),
        };
        Ok(json!({"index":index,"role":if *sender {"sender"} else {"endpoint"},"state":state}))
    }).collect()
}

fn compare_tasks(
    actual: &[Json],
    expected: &Json,
    final_source: &Json,
    name: &str,
) -> AuthResult<()> {
    let expected = expected
        .as_array()
        .ok_or_else(|| AuthError::internal("Source OTP tasks missing"))?;
    let final_source = final_source
        .as_array()
        .ok_or_else(|| AuthError::internal("Final source OTP tasks missing"))?;
    assert_eq!(actual.len(), 2);
    assert_eq!(expected.len(), 2);
    assert_eq!(final_source.len(), 2);
    for sender in [false, true] {
        let matches = actual
            .iter()
            .filter(|task| (task["role"] == "sender") == sender)
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1);
        let source_indices = final_source
            .iter()
            .enumerate()
            .filter_map(|(index, task)| (task["sameDeliveryValue"] == sender).then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(source_indices.len(), 1);
        let mut expected = expected[source_indices[0]].clone();
        if let Some(value) = expected.get_mut("value") {
            *value = source_value(value)?;
        }
        assert_replay(&matches[0]["state"], &expected, name);
    }
    Ok(())
}

async fn run(case: &Json) -> AuthResult<()> {
    let name = case["name"]
        .as_str()
        .ok_or_else(|| AuthError::internal("OTP source name missing"))?;
    let pending = case["timing"] == "pending";
    let now = chrono::DateTime::from_timestamp_millis(NOW)
        .ok_or_else(|| AuthError::internal("OTP source clock must be representable"))?;
    let state = Arc::new(State::default());
    let delivery: FieldValue = FieldMap::from([
        ("sender".into(), "completed".into()),
        ("optional".into(), FieldValue::Undefined),
        ("nullable".into(), FieldValue::Null),
    ])
    .into();
    let delivery_before = NativeObservation::default().observe(&delivery)?;
    assert_replay(
        &delivery_before,
        &source_value(&case["deliveryBefore"])?,
        name,
    );
    let mut config = create_test_config().base_url("https://email-otp-override-values.test");
    let ids = Arc::new(AtomicUsize::new(0));
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |input| {
            Ok(Some(format!(
                "{}-{}",
                input.model,
                ids.fetch_add(1, Ordering::SeqCst) + 1
            )))
        })));
    config.logger = FieldObject::from(FieldMap::from([
        ("level".into(), "error".into()),
        (
            "log".into(),
            FieldFunction::contextual({
                let state = state.clone();
                move |_, arguments| {
                    lock(&state.logs)?
                        .push(NativeObservation::default().observe(&arguments.to_vec().into())?);
                    Ok(FieldValue::Undefined)
                }
            })
            .into(),
        ),
    ]))
    .into();
    config.advanced.background_tasks = Some(BackgroundTasks::new({
        let state = state.clone();
        move |task| {
            let sender = state.next_sender.swap(false, Ordering::SeqCst);
            let mut tasks = lock(&state.tasks)?;
            lock(&state.events)?.push(json!({"phase":"handler:received","index":tasks.len(),"role":if sender {"sender"}else{"endpoint"}}));
            tasks.push((sender, task));
            if tasks.len() == 2 {
                state.registered.notify_one();
            }
            Ok(())
        }
    }));
    let config = Arc::new(config);
    let user = FieldMap::from([
        ("name".into(), "Override Values".into()),
        ("email".into(), EMAIL.into()),
        ("emailVerified".into(), false.into()),
        ("image".into(), FieldValue::Null),
        ("createdAt".into(), FieldDate::from(now).into()),
        ("updatedAt".into(), FieldDate::from(now).into()),
        ("id".into(), "owner".into()),
    ]);
    let store = Arc::new(
        EphemeralStore::from_storage(
            config.clone(),
            [
                ("user".into(), vec![user]),
                ("session".into(), vec![]),
                ("account".into(), vec![]),
                ("verification".into(), vec![]),
            ],
        )?
        .with_hooks(vec![Arc::new(VerificationClock(now))]),
    );
    let plugin = EmailOtpPlugin::new().override_default_email_verification(true).callbacks(
        EmailOtpCallbacks::<StatelessSchema>::default().generate(|_, _, _| Ok(Some("123456".into())))
            .send({ let state=state.clone(); let delivery=delivery.clone(); move |message, endpoint| {
                let message: FieldValue = FieldMap::from([("email".into(), message.email.clone().into()),
                    ("otp".into(), message.otp.field_value()), ("type".into(), message.kind.as_str().into())]).into();
                lock(&state.messages)?.push(json!({"message":NativeObservation::default().observe(&message)?,
                    "path":endpoint.path,"body":NativeObservation::default().observe(&endpoint.body)?,"hasRequest":endpoint.request.is_some()}));
                lock(&state.events)?.push(json!({"phase":"sender:start"}));
                state.next_sender.store(true, Ordering::SeqCst);
                state.entered.notify_one();
                let state=state.clone(); let delivery=delivery.clone();
                Ok(Some(BackgroundFuture::native(async move {
                    if pending { state.gate.notified().await; lock(&state.events)?.push(json!({"phase":"sender:resume"})); }
                    Ok(delivery)
                })))
            }}),
    );
    let context = initialize_test_context(config, store.clone(), &[&plugin])
        .await?
        .with_clock(move || now);
    assert_replay(&database(&store)?, &source_value(&case["before"])?, name);
    let endpoint = EndpointContext::new(None, FieldValue::Undefined, &context);
    send_verification_override(EMAIL, &endpoint).await?;
    let override_state = json!({"status":"fulfilled","value":{"type":"undefined"}});
    lock(&state.events)?.push(json!({"phase":"override:fulfilled","state":override_state}));
    state.entered.notified().await;
    state.registered.notified().await;
    let tasks = std::mem::take(&mut *lock(&state.tasks)?);
    let mut tasks = tasks
        .into_iter()
        .map(|(role, task)| (role, Some(task)))
        .collect::<Vec<_>>();
    let mut values = Vec::new();
    for (sender, task) in &mut tasks {
        let value = if pending && *sender {
            None
        } else {
            Some(
                complete(
                    task.take()
                        .ok_or_else(|| AuthError::internal("Retained OTP task missing"))?,
                )
                .await?,
            )
        };
        values.push((*sender, value));
    }
    if pending {
        let task = tasks
            .iter_mut()
            .find_map(|(sender, task)| sender.then_some(task).and_then(Option::as_mut))
            .ok_or_else(|| AuthError::internal("Pending OTP sender task missing"))?;
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut *task).poll(cx)))
                .await
                .is_pending()
        );
    }
    let before_tasks = task_states(&values, &delivery)?;
    compare_tasks(
        &before_tasks,
        &case["beforeRelease"]["taskStates"],
        &case["afterSettlement"]["taskStates"],
        name,
    )?;
    assert_replay(
        &override_state,
        &case["beforeRelease"]["overrideState"],
        name,
    );
    let before_database = database(&store)?;
    assert_replay(
        &before_database,
        &source_value(&case["beforeRelease"]["database"])?,
        name,
    );
    lock(&state.events)?.push(json!({"phase":"gate:release"}));
    state.gate.notify_one();
    for (index, (_, task)) in tasks.into_iter().enumerate() {
        if let Some(task) = task {
            values[index].1 = Some(complete(task).await?);
        }
    }
    let after_tasks = task_states(&values, &delivery)?;
    compare_tasks(
        &after_tasks,
        &case["afterSettlement"]["taskStates"],
        &case["afterSettlement"]["taskStates"],
        name,
    )?;
    let after_database = database(&store)?;
    assert_replay(
        &after_database,
        &source_value(&case["afterSettlement"]["database"])?,
        name,
    );
    assert_replay(
        &override_state,
        &case["afterSettlement"]["overrideState"],
        name,
    );
    let messages = lock(&state.messages)?.clone();
    let expected_messages = case["messages"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Source OTP messages missing"))?;
    assert_eq!(messages.len(), expected_messages.len());
    for (actual, expected) in messages.iter().zip(expected_messages) {
        let mut expected = expected.clone();
        expected["message"] = source_value(&expected["message"])?;
        expected["body"] = source_value(&expected["body"])?;
        assert_replay(actual, &expected, name);
    }
    assert_eq!(lock(&state.messages)?.len(), 1);
    for phase in ["beforeRelease", "afterSettlement"] {
        assert_replay(
            &NativeObservation::default().observe(&delivery)?,
            &source_value(&case[phase]["deliveryValue"])?,
            name,
        );
    }
    assert_replay(
        &NativeObservation::default().observe(&delivery)?,
        &source_value(&case["deliveryAfter"])?,
        name,
    );
    assert_eq!(
        NativeObservation::default().observe(&delivery)?,
        delivery_before
    );
    assert_replay(&Json::from(lock(&state.logs)?.clone()), &case["logs"], name);
    assert_replay(&json!([]), &case["functions"], name);
    // Awaiting a ready Rust future need not yield. Preserve both registration sequences; pair task values by the sender's original identity.
    println!(
        "{}",
        json!({"contract":"email-otp-override-values-rust","name":name,
        "events":*lock(&state.events)?,"beforeTaskStates":before_tasks,"afterTaskStates":after_tasks,
        "beforeDatabase":before_database,"afterDatabase":after_database,"sourceEvents":case["events"]})
    );
    Ok(())
}

#[tokio::test]
async fn direct_override_retains_endpoint_success_and_sender_identity() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/email-otp-override-values-1.7.6.json"
    )))?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Source OTP cases missing"))?;
    assert_eq!(cases.len(), 2);
    for case in cases {
        tokio::time::timeout(std::time::Duration::from_secs(10), run(case))
            .await
            .map_err(|_| AuthError::internal("Direct OTP override did not complete"))??;
    }
    Ok(())
}
