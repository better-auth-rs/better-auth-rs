#![expect(
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    reason = "The paired graph contracts assert complete records, original errors, events, and retained identities."
)]

use super::{EphemeralStore, rows::RowRef, table::TableRef};
use crate::field_value::FieldObjectSource;
use crate::store::{ApiKeyStore, ApiKeyUsageWrite, UserStore, schema::EntityRole};
use crate::user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform};
use crate::{
    AuthConfig, AuthError, AuthRecordFields, AuthResult, FieldDate, FieldFunction, FieldMap,
    FieldObject, FieldValue, UpdateUser,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

mod arrays;
mod root;

type Events = Arc<Mutex<Vec<String>>>;

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Expected a complete graph fixture"))
}

fn record(events: &Events, value: impl Into<String>) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Graph events poisoned"))?
        .push(value.into());
    Ok(())
}

fn events(events: &Events) -> AuthResult<Vec<String>> {
    Ok(events
        .lock()
        .map_err(|_| AuthError::internal("Graph events poisoned"))?
        .clone())
}

fn date() -> FieldValue {
    FieldDate::from_milliseconds(1_893_456_000_000.0).into()
}

fn key(id: &str, remaining: f64) -> FieldMap {
    [
        ("id".into(), id.into()),
        ("name".into(), "Before".into()),
        ("start".into(), FieldValue::Null),
        ("prefix".into(), FieldValue::Null),
        ("key".into(), "stored-hash".into()),
        ("referenceId".into(), "owner".into()),
        ("configId".into(), "default".into()),
        ("refillInterval".into(), FieldValue::Null),
        ("refillAmount".into(), FieldValue::Null),
        ("lastRefillAt".into(), FieldValue::Null),
        ("enabled".into(), true.into()),
        ("rateLimitEnabled".into(), true.into()),
        ("rateLimitTimeWindow".into(), 60_000.0.into()),
        ("rateLimitMax".into(), 3.0.into()),
        ("requestCount".into(), 0.0.into()),
        ("remaining".into(), remaining.into()),
        ("lastRequest".into(), FieldValue::Null),
        ("expiresAt".into(), FieldValue::Null),
        ("createdAt".into(), date()),
        ("updatedAt".into(), date()),
        ("permissions".into(), FieldValue::Null),
        ("metadata".into(), FieldValue::Null),
    ]
    .into()
}

fn user(name: FieldValue) -> FieldMap {
    [
        ("id".into(), "owner".into()),
        ("name".into(), name),
        ("email".into(), "owner@memory-graph.test".into()),
        ("emailVerified".into(), false.into()),
        ("image".into(), FieldValue::Null),
        ("createdAt".into(), date()),
        ("updatedAt".into(), date()),
    ]
    .into()
}

fn named(mut fields: FieldMap, name: FieldValue) -> FieldMap {
    let _ = fields.insert("name".into(), name);
    fields
}

fn fixture(trace: &Events) -> EphemeralStore {
    let field = |model: &'static str| {
        let input = trace.clone();
        let output = trace.clone();
        UserFieldConfig {
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    record(&input, format!("input:{model}.name"))?;
                    Ok(value)
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    record(&output, format!("output:{model}.name"))?;
                    Ok(value)
                })),
            }),
            ..Default::default()
        }
    };
    let mut config = AuthConfig::default();
    let _ = config
        .user
        .fields_mut()
        .insert("name".into(), field("user"));
    let mut store = EphemeralStore::empty(Arc::new(config));
    store.state = Arc::new(Mutex::new(super::State::with_models(
        store.operations.clone(),
        ["user", "session", "account", "verification", "apikey"],
    )));
    store.model_fields.register(
        EntityRole::ApiKey,
        UserConfig {
            additional_fields: Some([("name".into(), field("apikey"))].into()),
        },
    );
    store
}

fn keys(store: &EphemeralStore) -> AuthResult<TableRef<FieldMap>> {
    store.operation(|op| op.capture_table(EntityRole::ApiKey))
}

fn users(store: &EphemeralStore) -> AuthResult<TableRef<FieldMap>> {
    store.operation(|op| op.capture_table(EntityRole::User))
}

fn check_raw(
    store: &EphemeralStore,
    expected_users: &[FieldMap],
    expected_keys: &[FieldMap],
) -> AuthResult<()> {
    check_raw_accounts(store, expected_users, expected_keys, &[])
}

fn check_raw_accounts(
    store: &EphemeralStore,
    expected_users: &[FieldMap],
    expected_keys: &[FieldMap],
    expected_accounts: &[FieldMap],
) -> AuthResult<()> {
    let state = store.operation(|op| op.capture_state())?;
    assert_eq!(state.fixture_table("user").snapshot()?, expected_users);
    assert_eq!(state.fixture_table("apikey").snapshot()?, expected_keys);
    assert_eq!(
        state.fixture_table("account").snapshot()?,
        expected_accounts
    );
    check_empty_tables(&state)
}

fn check_empty_tables(state: &super::State) -> AuthResult<()> {
    assert_eq!(
        state.keys(),
        ["user", "session", "account", "verification", "apikey"]
    );
    for name in ["session", "verification"] {
        assert!(state.table(name)?.snapshot()?.is_empty());
    }
    Ok(())
}

async fn decrement(store: &EphemeralStore) -> AuthResult<FieldMap> {
    required(
        store
            .write_api_key_usage(&"target".to_owned().into(), ApiKeyUsageWrite::Decrement)
            .await?,
    )?
    .field_values()
}

async fn listed(store: &EphemeralStore) -> AuthResult<Vec<FieldMap>> {
    store
        .list_api_keys_by_reference("owner")
        .await?
        .iter()
        .map(AuthRecordFields::field_values)
        .collect()
}

#[tokio::test]
async fn repeated_top_level_rows_share_one_increment_and_committed_identity() -> AuthResult<()> {
    let trace = Events::default();
    let store = fixture(&trace);
    let target = keys(&store)?.push(key("target", 5.0))?;
    store.operation(|op| {
        op.replace_table(
            EntityRole::ApiKey,
            TableRef::from_refs(
                store.operations.clone(),
                vec![target.clone(), target.clone()],
            ),
        )
    })?;
    let captured = keys(&store)?;
    let (base, tx, queue) = store.begin_adapter_transaction()?;
    record(&trace, "transaction:enter")?;
    let updated = decrement(&tx).await?;
    let rows = listed(&tx).await?;
    record(&trace, "transaction:return")?;
    store.commit_adapter_transaction(base, tx, queue).await?;
    record(&trace, "transaction:committed")?;
    assert_eq!(
        events(&trace)?,
        [
            "transaction:enter",
            "output:apikey.name",
            "output:apikey.name",
            "output:apikey.name",
            "transaction:return",
            "transaction:committed"
        ]
    );
    let changed = key("target", 4.0);
    assert_eq!(updated, changed);
    assert_eq!(rows, [changed.clone(), changed.clone()]);
    check_raw(&store, &[], &[changed.clone(), changed])?;
    assert_eq!(
        captured.snapshot()?,
        [key("target", 5.0), key("target", 5.0)]
    );
    let live = keys(&store)?;
    let first = required(live.row_at(0)?)?;
    assert!(first.same_row(&required(live.row_at(1)?)?));
    assert!(!first.same_row(&target));
    assert!(required(captured.row_at(0)?)?.same_row(&target));
    assert!(required(captured.row_at(1)?)?.same_row(&target));
    assert!(updated["createdAt"].strict_equals(&required(first.field("createdAt")?)?));
    assert!(rows[0]["createdAt"].strict_equals(&rows[1]["createdAt"]));
    assert!(!updated["createdAt"].strict_equals(&required(target.field("createdAt")?)?));
    assert!(!FieldValue::from(updated).strict_equals(&first.field_value()));
    Ok(())
}

#[tokio::test]
async fn field_reference_reuses_an_earlier_top_level_key_row() -> AuthResult<()> {
    let trace = Events::default();
    let store = fixture(&trace);
    let captured = keys(&store)?;
    let target = captured.push(key("target", 5.0))?;
    let holder = captured.push(named(key("holder", 3.0), target.field_value()))?;
    let (base, tx, queue) = store.begin_adapter_transaction()?;
    record(&trace, "transaction:enter")?;
    let selected = required(tx.get_api_key_record(&"holder".to_owned().into()).await?)?;
    assert!(!selected["name"].strict_equals(&target.field_value()));
    required(selected["name"].as_object())?.set("remaining", 7.0.into())?;
    record(&trace, "graph:mutate-target")?;
    let updated = decrement(&tx).await?;
    let rows = listed(&tx).await?;
    record(&trace, "transaction:return")?;
    store.commit_adapter_transaction(base, tx, queue).await?;
    record(&trace, "transaction:committed")?;
    assert_eq!(
        events(&trace)?,
        [
            "transaction:enter",
            "output:apikey.name",
            "graph:mutate-target",
            "output:apikey.name",
            "output:apikey.name",
            "output:apikey.name",
            "transaction:return",
            "transaction:committed"
        ]
    );
    let changed = key("target", 6.0);
    assert_eq!(
        required(selected["name"].as_object())?.snapshot_fields()?,
        changed
    );
    let changed_holder = named(key("holder", 3.0), selected["name"].clone());
    assert_eq!(selected, changed_holder);
    assert_eq!(updated, changed);
    assert_eq!(rows, [changed.clone(), changed_holder.clone()]);
    check_raw(&store, &[], &[changed, changed_holder])?;
    assert_eq!(
        captured.snapshot()?,
        [
            key("target", 5.0),
            named(key("holder", 3.0), target.field_value())
        ]
    );
    let live = keys(&store)?;
    let first = required(live.row_at(0)?)?;
    let second = required(live.row_at(1)?)?;
    assert!(required(second.field("name")?)?.strict_equals(&first.field_value()));
    assert!(selected["name"].strict_equals(&first.field_value()));
    assert!(rows[1]["name"].strict_equals(&first.field_value()));
    assert!(!first.same_row(&target));
    assert!(!second.same_row(&holder));
    assert!(required(holder.field("name")?)?.strict_equals(&target.field_value()));
    assert!(!FieldValue::from(updated).strict_equals(&first.field_value()));
    Ok(())
}

#[tokio::test]
async fn user_field_reference_reuses_a_later_top_level_key_table() -> AuthResult<()> {
    let trace = Events::default();
    let store = fixture(&trace);
    let captured_keys = keys(&store)?;
    let captured_users = users(&store)?;
    let target = captured_keys.push(key("target", 5.0))?;
    let owner = captured_users.push(user(target.field_value()))?;
    let (base, tx, queue) = store.begin_adapter_transaction()?;
    record(&trace, "transaction:enter")?;
    let selected = required(tx.get_user_by_id("owner").await?)?.field_values()?;
    assert!(!selected["name"].strict_equals(&target.field_value()));
    required(selected["name"].as_object())?.set("remaining", 7.0.into())?;
    record(&trace, "graph:mutate-target")?;
    let updated = decrement(&tx).await?;
    record(&trace, "transaction:return")?;
    store.commit_adapter_transaction(base, tx, queue).await?;
    record(&trace, "transaction:committed")?;
    assert_eq!(
        events(&trace)?,
        [
            "transaction:enter",
            "output:user.name",
            "graph:mutate-target",
            "output:apikey.name",
            "transaction:return",
            "transaction:committed"
        ]
    );
    let changed = key("target", 6.0);
    assert_eq!(
        required(selected["name"].as_object())?.snapshot_fields()?,
        changed
    );
    assert_eq!(selected, user(selected["name"].clone()));
    assert_eq!(updated, changed);
    check_raw(&store, &[user(selected["name"].clone())], &[changed])?;
    assert_eq!(captured_keys.snapshot()?, [key("target", 5.0)]);
    assert_eq!(
        required(captured_users.row_at(0)?)?.shallow_fields()?,
        user(target.field_value())
    );
    let live_key = required(keys(&store)?.row_at(0)?)?;
    let live_user = required(users(&store)?.row_at(0)?)?;
    assert!(required(live_user.field("name")?)?.strict_equals(&live_key.field_value()));
    assert!(selected["name"].strict_equals(&live_key.field_value()));
    assert!(!live_user.same_row(&owner));
    assert!(!live_key.same_row(&target));
    assert!(required(owner.field("name")?)?.strict_equals(&target.field_value()));
    assert!(!FieldValue::from(updated).strict_equals(&live_key.field_value()));
    Ok(())
}

#[derive(Clone, Copy)]
enum CycleShape {
    Row,
    ObjectArray,
    Table,
}

fn cyclic_name(
    row: &FieldValue,
    table: &TableRef<FieldMap>,
    shape: CycleShape,
) -> AuthResult<FieldValue> {
    match shape {
        CycleShape::Row => Ok(row.clone()),
        CycleShape::Table => Ok(table.array().into()),
        CycleShape::ObjectArray => {
            let graph: FieldValue = FieldMap::from([("label".into(), "graph".into())]).into();
            required(graph.as_object())?.set("nodes", vec![graph.clone()].into())?;
            Ok(graph)
        }
    }
}

fn check_cycle(name: &FieldValue, shape: CycleShape, remaining: f64) -> AuthResult<()> {
    let row = match shape {
        CycleShape::Table => {
            let array = required(name.as_array())?;
            assert_eq!(array.len()?, 1);
            assert_eq!(array.own_indices()?, [0]);
            required(array.first()?)?
        }
        _ => name.clone(),
    };
    let object = required(row.as_object())?;
    let back = match shape {
        CycleShape::Row | CycleShape::Table => {
            assert_eq!(
                object.snapshot_fields()?,
                named(key("target", remaining), name.clone())
            );
            required(object.get("name")?)?
        }
        CycleShape::ObjectArray => {
            assert_eq!(
                object.snapshot_fields()?,
                [
                    ("label".into(), "graph".into()),
                    ("nodes".into(), vec![name.clone()].into()),
                ]
                .into()
            );
            required(required(required(object.get("nodes")?)?.as_array())?.get(0)?)?
        }
    };
    assert!(back.strict_equals(name));
    Ok(())
}

fn unlink(name: &FieldValue, shape: CycleShape) -> AuthResult<()> {
    let (row, field) = match shape {
        CycleShape::Row => (name.clone(), "name"),
        CycleShape::ObjectArray => (name.clone(), "nodes"),
        CycleShape::Table => (required(required(name.as_array())?.first()?)?, "name"),
    };
    let _ = required(row.as_object())?.delete(field)?;
    Ok(())
}

#[tokio::test]
async fn cycles_reach_transaction_work_then_keep_earlier_model_publication_on_json_failure()
-> AuthResult<()> {
    for shape in [CycleShape::Row, CycleShape::ObjectArray, CycleShape::Table] {
        let trace = Events::default();
        let store = fixture(&trace);
        let captured_keys = keys(&store)?;
        let captured_users = users(&store)?;
        let target = captured_keys.push(key("target", 5.0))?;
        let live_name = cyclic_name(&target.field_value(), &captured_keys, shape)?;
        target.set_field("name".into(), live_name.clone())?;
        let owner = captured_users.push(user("Before".into()))?;
        let expected_failure = required(target.field_value().stringify().err())?;
        let (base, tx, queue) = store.begin_adapter_transaction()?;
        let base_name =
            required(required(base.fixture_table("apikey").row_at(0)?)?.field("name")?)?;
        record(&trace, "transaction:enter")?;
        let selected = required(tx.get_api_key_record(&"target".to_owned().into()).await?)?;
        assert!(!selected["name"].strict_equals(&live_name));
        check_cycle(&selected["name"], shape, 5.0)?;
        record(&trace, "graph:verified")?;
        let callback_value = decrement(&tx).await?;
        let changed_user = tx
            .update_user(
                "owner",
                UpdateUser {
                    name: Some("Published".to_owned()).into(),
                    additional_fields: [("updatedAt".into(), date())].into(),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(changed_user.field_values()?, user("Published".into()));
        record(&trace, "transaction:return")?;
        let result = store.commit_adapter_transaction(base, tx, queue).await;
        assert!(
            matches!(&result, Err(AuthError::TypeError(message)) if message == "Converting circular structure to JSON")
        );
        assert_eq!(
            required(result.err())?
                .instrumentation_message()
                .expect("fixture error message"),
            expected_failure
                .instrumentation_message()
                .expect("fixture error message")
        );
        assert_eq!(
            events(&trace)?,
            [
                "transaction:enter",
                "output:apikey.name",
                "graph:verified",
                "output:apikey.name",
                "input:user.name",
                "output:user.name",
                "transaction:return"
            ]
        );
        let expected_live = named(key("target", 5.0), live_name.clone());
        let expected_clone = named(key("target", 4.0), callback_value["name"].clone());
        check_raw(
            &store,
            &[user("Published".into())],
            std::slice::from_ref(&expected_live),
        )?;
        assert_eq!(
            captured_keys.snapshot()?,
            std::slice::from_ref(&expected_live)
        );
        assert_eq!(owner.shallow_fields()?, user("Before".into()));
        assert_eq!(callback_value, expected_clone);
        let live_user = required(users(&store)?.row_at(0)?)?;
        assert!(!live_user.same_row(&owner));
        assert!(required(keys(&store)?.row_at(0)?)?.same_row(&target));
        assert!(!callback_value["name"].strict_equals(&live_name));
        assert!(!callback_value["createdAt"].strict_equals(&required(target.field("createdAt")?)?));
        check_cycle(&live_name, shape, 5.0)?;
        check_cycle(&callback_value["name"], shape, 4.0)?;
        for name in [&live_name, &base_name, &callback_value["name"]] {
            unlink(name, shape)?;
        }
    }
    Ok(())
}

struct CloneProbe {
    owner: RowRef<FieldMap>,
    trace: Events,
    reads: AtomicUsize,
    fail_at: usize,
    failure: Mutex<Option<AuthError>>,
    function: FieldValue,
}

impl CloneProbe {
    fn object(self: &Arc<Self>) -> crate::FieldObject {
        let source = self.clone();
        crate::FieldObject::from(indexmap::IndexMap::from([(
            "value".into(),
            crate::field_value::FieldPropertyDescriptor {
                enumerable: true,
                configurable: true,
                property: crate::field_value::FieldProperty::Accessor {
                    get: Some(crate::FieldFunction::contextual(move |receiver, _| {
                        Ok(source.read("value", receiver)?.unwrap_or_default())
                    })),
                    set: None,
                },
            },
        )]))
    }

    fn read(&self, name: &str, _receiver: &FieldValue) -> AuthResult<Option<FieldValue>> {
        if name != "value" {
            return Ok(None);
        }
        let read = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
        record(&self.trace, format!("clone:{read}"))?;
        self.owner
            .set_field("name".into(), format!("Live side effect {read}").into())?;
        record(&self.trace, format!("side-effect:{read}"))?;
        if read == self.fail_at {
            if let Some(error) = self
                .failure
                .lock()
                .map_err(|_| AuthError::internal("Clone failure poisoned"))?
                .take()
            {
                return Err(error);
            }
            return Ok(Some(self.function.clone()));
        }
        Ok(Some(format!("copied {read}").into()))
    }
}

#[test]
fn clone_getter_failures_preserve_original_errors_and_live_writes_before_work() -> AuthResult<()> {
    for fail_at in [1, 2] {
        for throws in [false, true] {
            let trace = Events::default();
            let store = fixture(&trace);
            let captured_keys = keys(&store)?;
            let captured_users = users(&store)?;
            let owner = captured_users.push(user("Before".into()))?;
            let target = captured_keys.push(key("target", 5.0))?;
            let message = "memory-clone-getter-original".to_owned();
            let original = message.as_ptr() as usize;
            let calls = trace.clone();
            let probe = Arc::new(CloneProbe {
                owner: owner.clone(),
                trace: trace.clone(),
                reads: AtomicUsize::new(0),
                fail_at,
                failure: Mutex::new(throws.then_some(AuthError::Internal(message))),
                function: FieldFunction::contextual(move |_, _| {
                    record(&calls, "unexpected:function:call")?;
                    Ok(FieldValue::Undefined)
                })
                .into(),
            });
            let value = FieldValue::Object(probe.object());
            target.set_field("name".into(), value.clone())?;
            let mut returned = None;
            let result = store.begin_adapter_transaction().and_then(|_| {
                record(&trace, "transaction:enter")?;
                returned = Some("unexpected transaction result");
                Ok(())
            });
            assert!(returned.is_none());
            let failure = required(result.err())?;
            if throws {
                assert!(
                    matches!(failure, AuthError::Internal(message) if message == "memory-clone-getter-original" && message.as_ptr() as usize == original)
                );
            } else {
                assert!(matches!(failure, AuthError::DataClone));
                assert_eq!(
                    failure
                        .instrumentation_message()
                        .expect("fixture error message"),
                    "The object can not be cloned."
                );
            }
            let expected_events = if fail_at == 1 {
                vec!["clone:1", "side-effect:1"]
            } else {
                vec!["clone:1", "side-effect:1", "clone:2", "side-effect:2"]
            };
            assert_eq!(probe.reads.load(Ordering::SeqCst), fail_at);
            assert_eq!(events(&trace)?, expected_events);
            check_raw(
                &store,
                &[user(format!("Live side effect {fail_at}").into())],
                &[named(key("target", 5.0), value.clone())],
            )?;
            assert_eq!(required(value.as_object())?.own_keys()?, ["value"]);
            assert!(required(keys(&store)?.row_at(0)?)?.same_row(&target));
            assert!(required(users(&store)?.row_at(0)?)?.same_row(&owner));
            assert!(required(target.field("name")?)?.strict_equals(&value));
            assert_eq!(probe.reads.load(Ordering::SeqCst), fail_at);
            assert_eq!(events(&trace)?, expected_events);
        }
    }
    Ok(())
}
