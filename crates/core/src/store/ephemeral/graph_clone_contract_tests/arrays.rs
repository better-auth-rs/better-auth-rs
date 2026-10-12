#![expect(
    clippy::expect_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]

//! Paired with memory-array-clone.mjs through actual Memory transactions.

use super::*;
use crate::FieldArray;

fn assert_tree(actual: &FieldValue, expected: &FieldValue) -> AuthResult<()> {
    match (actual, expected) {
        (FieldValue::Number(actual), FieldValue::Number(expected)) => {
            assert_eq!(actual.to_bits(), expected.to_bits());
        }
        (FieldValue::Array(actual), FieldValue::Array(expected)) => {
            assert_eq!(actual.len()?, expected.len()?);
            let indices = expected.own_indices()?;
            assert_eq!(actual.own_indices()?, indices);
            for index in indices {
                assert_tree(
                    &required(actual.get(index)?)?,
                    &required(expected.get(index)?)?,
                )?;
            }
        }
        (FieldValue::Object(actual), FieldValue::Object(expected)) => {
            let actual = actual.snapshot_fields()?;
            let expected = expected.snapshot_fields()?;
            assert_eq!(actual.len(), expected.len());
            for (name, value) in expected {
                assert_tree(required(actual.get(&name))?, &value)?;
            }
        }
        _ => assert_eq!(actual, expected),
    }
    Ok(())
}

#[tokio::test]
async fn table_array_fields_share_transaction_writes_and_commit_row_identities() -> AuthResult<()> {
    for shared_table in [false, true] {
        let trace = Events::default();
        let store = fixture(&trace);
        let captured_keys = keys(&store)?;
        let captured_users = users(&store)?;
        let target = captured_keys.push(key("target", 5.0))?;
        let owner = captured_users.push(user(captured_keys.array().into()))?;
        if shared_table {
            store.operation(|op| op.replace_table(EntityRole::Account, captured_keys.clone()))?;
        }
        let captured_accounts = store.operation(|op| op.capture_table(EntityRole::Account))?;
        let (base, tx, queue) = store.begin_adapter_transaction()?;
        record(&trace, "transaction:enter")?;
        let selected = required(tx.get_user_by_id("owner").await?)?.field_values()?;
        let selected_array = required(selected["name"].as_array())?;
        assert!(!selected_array.same_array(&captured_keys.array()));
        assert_tree(
            &selected["name"],
            &vec![FieldValue::from(key("target", 5.0))].into(),
        )?;
        let created = required(tx.create_api_key_record(key("added", 2.0)).await?)?;
        assert_eq!(selected_array.len()?, 2);
        let count = tx.operation(|op| op.capture_table(EntityRole::Account)?.len())?;
        assert_eq!(count, if shared_table { 2 } else { 0 });
        let first = required(selected_array.first()?)?;
        required(first.as_object())?.set("remaining", 7.0.into())?;
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
                "input:apikey.name",
                "output:apikey.name",
                "graph:mutate-target",
                "output:apikey.name",
                "transaction:return",
                "transaction:committed",
            ]
        );
        let changed = key("target", 6.0);
        let added = key("added", 2.0);
        let mut added_stored = added.clone();
        let _ = added_stored.insert("metadata".into(), "null".into());
        let expected_rows = vec![changed.clone(), added_stored];
        assert_tree(
            &selected.clone().into(),
            &user(
                expected_rows
                    .iter()
                    .cloned()
                    .map(FieldValue::from)
                    .collect::<Vec<_>>()
                    .into(),
            )
            .into(),
        )?;
        assert_eq!(created, added);
        assert_eq!(updated, changed);
        check_raw_accounts(
            &store,
            &[user(selected["name"].clone())],
            &expected_rows,
            if shared_table { &expected_rows } else { &[] },
        )?;
        assert_eq!(captured_keys.snapshot()?, [key("target", 5.0)]);
        assert_tree(
            &owner.field_value(),
            &user(vec![FieldValue::from(key("target", 5.0))].into()).into(),
        )?;
        assert_eq!(captured_users.snapshot()?, [owner.snapshot()?]);
        assert_eq!(
            captured_accounts.snapshot()?,
            if shared_table {
                vec![key("target", 5.0)]
            } else {
                vec![]
            }
        );
        assert!(required(owner.field("name")?)?.strict_equals(&captured_keys.array().into()));
        assert!(required(captured_keys.row_at(0)?)?.same_row(&target));
        let live_keys = keys(&store)?;
        let live_users = users(&store)?;
        assert!(!live_keys.array().same_array(&captured_keys.array()));
        assert!(!live_users.array().same_array(&captured_users.array()));
        assert!(
            selected["name"]
                .strict_equals(&required(required(live_users.row_at(0)?)?.field("name")?)?)
        );
        assert!(!selected_array.same_array(&live_keys.array()));
        for index in [0, 1] {
            assert!(
                required(selected_array.get(index)?)?
                    .strict_equals(&required(live_keys.row_at(index)?)?.field_value())
            );
        }
        assert!(
            !FieldValue::from(updated)
                .strict_equals(&required(live_keys.row_at(0)?)?.field_value())
        );
        assert!(
            !FieldValue::from(created.clone())
                .strict_equals(&required(live_keys.row_at(1)?)?.field_value())
        );
        assert!(created["createdAt"].strict_equals(&required(
            required(live_keys.row_at(1)?)?.field("createdAt")?
        )?));
        if shared_table {
            let accounts = store.operation(|op| op.capture_table(EntityRole::Account))?;
            assert!(!accounts.array().same_array(&live_keys.array()));
            assert!(!accounts.array().same_array(&captured_accounts.array()));
            for index in [0, 1] {
                assert!(
                    required(accounts.row_at(index)?)?
                        .same_row(&required(live_keys.row_at(index)?)?)
                );
            }
        }
    }
    Ok(())
}

fn payload(stage: usize) -> FieldValue {
    FieldMap::from([
        ("stage".into(), (stage as f64).into()),
        ("missing".into(), FieldValue::Undefined),
        ("nil".into(), FieldValue::Null),
        ("date".into(), date()),
        (
            "values".into(),
            vec![
                FieldValue::Undefined,
                FieldValue::Null,
                f64::NAN.into(),
                (-0.0).into(),
            ]
            .into(),
        ),
    ])
    .into()
}

struct ArrayProbe {
    owner: RowRef<FieldMap>,
    trace: Events,
    reads: AtomicUsize,
    fail_at: usize,
    failure: Mutex<Option<AuthError>>,
    function: FieldValue,
    payloads: Mutex<Vec<FieldValue>>,
}

impl ArrayProbe {
    fn array(self: &Arc<Self>) -> AuthResult<FieldArray> {
        let array = FieldArray::with_length(2);
        for index in [0, 1] {
            let source = self.clone();
            FieldValue::Array(array.clone()).define_model_property(
                &index.to_string(),
                crate::field_value::FieldPropertyDescriptor {
                    enumerable: true,
                    configurable: true,
                    property: crate::field_value::FieldProperty::Accessor {
                        get: Some(FieldFunction::contextual(move |_, _| {
                            Ok(source.read(index)?.unwrap_or_default())
                        })),
                        set: None,
                    },
                }
                .into(),
            )?;
        }
        Ok(array)
    }

    fn read(&self, index: usize) -> AuthResult<Option<FieldValue>> {
        if index > 1 {
            return Ok(None);
        }
        if index == 1 {
            let read = self.reads.load(Ordering::SeqCst);
            record(&self.trace, format!("clone:{read}:index1"))?;
            return Ok(Some(required(
                self.payloads
                    .lock()
                    .map_err(|_| AuthError::internal("Array payloads poisoned"))?
                    .last()
                    .cloned(),
            )?));
        }
        let read = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
        record(&self.trace, format!("clone:{read}:index0"))?;
        self.owner
            .set_field("name".into(), format!("Live side effect {read}").into())?;
        record(&self.trace, format!("side-effect:{read}"))?;
        if read == self.fail_at {
            if let Some(error) = self
                .failure
                .lock()
                .map_err(|_| AuthError::internal("Array failure poisoned"))?
                .take()
            {
                return Err(error);
            }
            return Ok(Some(self.function.clone()));
        }
        self.payloads
            .lock()
            .map_err(|_| AuthError::internal("Array payloads poisoned"))?
            .push(payload(read));
        Ok(Some(format!("copied {read}").into()))
    }
}

fn probe(
    owner: RowRef<FieldMap>,
    trace: &Events,
    fail_at: usize,
    failure: Option<AuthError>,
) -> Arc<ArrayProbe> {
    let calls = trace.clone();
    Arc::new(ArrayProbe {
        owner,
        trace: trace.clone(),
        reads: AtomicUsize::new(0),
        fail_at,
        failure: Mutex::new(failure),
        payloads: Mutex::new(Vec::new()),
        function: FieldFunction::contextual(move |_, _| {
            record(&calls, "unexpected:function:call")?;
            Ok(FieldValue::Undefined)
        })
        .into(),
    })
}

#[tokio::test]
async fn array_clone_reads_later_indices_after_earlier_getter_writes() -> AuthResult<()> {
    let trace = Events::default();
    let store = fixture(&trace);
    let captured_users = users(&store)?;
    let captured_keys = keys(&store)?;
    let owner = captured_users.push(user("Before".into()))?;
    let target = captured_keys.push(key("target", 5.0))?;
    let source = probe(owner.clone(), &trace, 0, None);
    let live: FieldValue = source.array()?.into();
    target.set_field("name".into(), live.clone())?;
    let (base, tx, queue) = store.begin_adapter_transaction()?;
    record(&trace, "transaction:enter")?;
    let selected = required(tx.get_api_key_record(&"target".to_owned().into()).await?)?;
    let name: FieldValue = vec!["copied 2".into(), payload(2)].into();
    assert_tree(
        &selected.clone().into(),
        &named(key("target", 5.0), name.clone()).into(),
    )?;
    record(&trace, "graph:verified")?;
    let updated = decrement(&tx).await?;
    record(&trace, "transaction:return")?;
    store.commit_adapter_transaction(base, tx, queue).await?;
    record(&trace, "transaction:committed")?;
    let expected_events = [
        "clone:1:index0",
        "side-effect:1",
        "clone:1:index1",
        "clone:2:index0",
        "side-effect:2",
        "clone:2:index1",
        "transaction:enter",
        "output:apikey.name",
        "graph:verified",
        "output:apikey.name",
        "transaction:return",
        "transaction:committed",
    ];
    assert_eq!(events(&trace)?, expected_events);
    assert_tree(
        &updated.clone().into(),
        &named(key("target", 4.0), name).into(),
    )?;
    let state = store.operation(|op| op.capture_state())?;
    assert_eq!(
        state.fixture_table("user").snapshot()?,
        [user("Live side effect 1".into())]
    );
    assert_eq!(state.fixture_table("apikey").len()?, 1);
    assert_tree(
        &required(state.fixture_table("apikey").row_at(0)?)?.field_value(),
        &named(
            key("target", 4.0),
            vec!["copied 2".into(), payload(2)].into(),
        )
        .into(),
    )?;
    assert!(state.fixture_table("account").snapshot()?.is_empty());
    check_empty_tables(&state)?;
    assert_eq!(
        captured_users.snapshot()?,
        [user("Live side effect 2".into())]
    );
    assert_eq!(
        captured_keys.snapshot()?,
        [named(key("target", 5.0), live.clone())]
    );
    assert!(!users(&store)?.array().same_array(&captured_users.array()));
    assert!(!keys(&store)?.array().same_array(&captured_keys.array()));
    assert!(required(captured_users.row_at(0)?)?.same_row(&owner));
    assert!(required(captured_keys.row_at(0)?)?.same_row(&target));
    assert!(required(target.field("name")?)?.strict_equals(&live));
    assert!(selected["name"].strict_equals(&updated["name"]));
    assert!(updated["name"].strict_equals(&required(
        required(keys(&store)?.row_at(0)?)?.field("name")?
    )?));
    assert!(!selected["name"].strict_equals(&live));
    let copied_array = required(selected["name"].as_array())?;
    let copied_payload = required(copied_array.get(1)?)?;
    let original_payload = required(
        source
            .payloads
            .lock()
            .map_err(|_| AuthError::internal("Array payloads poisoned"))?
            .get(1)
            .cloned(),
    )?;
    assert!(!copied_payload.strict_equals(&original_payload));
    assert!(
        !copied_payload
            .model_property("date")?
            .strict_equals(&original_payload.model_property("date")?)
    );
    assert_eq!(copied_array.own_indices()?, [0, 1]);
    let fields = required(copied_payload.as_object())?.snapshot_fields()?;
    assert_eq!(
        fields.keys().map(String::as_str).collect::<Vec<_>>(),
        ["stage", "missing", "nil", "date", "values"]
    );
    assert_eq!(fields.get("missing"), Some(&FieldValue::Undefined));
    assert_eq!(source.reads.load(Ordering::SeqCst), 2);
    assert_eq!(events(&trace)?, expected_events);
    Ok(())
}

#[test]
fn array_clone_failures_stop_later_indices_and_preserve_original_storage() -> AuthResult<()> {
    for fail_at in [1, 2] {
        for throws in [false, true] {
            let trace = Events::default();
            let store = fixture(&trace);
            let captured_users = users(&store)?;
            let captured_keys = keys(&store)?;
            let owner = captured_users.push(user("Before".into()))?;
            let target = captured_keys.push(key("target", 5.0))?;
            let message = "memory-array-getter-original".to_owned();
            let original_error = message.as_ptr() as usize;
            let source = probe(
                owner.clone(),
                &trace,
                fail_at,
                throws.then_some(AuthError::Internal(message)),
            );
            let live: FieldValue = source.array()?.into();
            target.set_field("name".into(), live.clone())?;
            let error = match store.begin_adapter_transaction() {
                Ok(_) => {
                    return Err(AuthError::internal(
                        "Array clone unexpectedly entered transaction work",
                    ));
                }
                Err(error) => error,
            };
            if throws {
                assert!(
                    matches!(error, AuthError::Internal(message) if message == "memory-array-getter-original" && message.as_ptr() as usize == original_error)
                );
            } else {
                assert!(matches!(error, AuthError::DataClone));
                assert_eq!(
                    error
                        .instrumentation_message()
                        .expect("fixture error message"),
                    "The object can not be cloned."
                );
            }
            let expected_events = if fail_at == 1 {
                vec!["clone:1:index0", "side-effect:1"]
            } else {
                vec![
                    "clone:1:index0",
                    "side-effect:1",
                    "clone:1:index1",
                    "clone:2:index0",
                    "side-effect:2",
                ]
            };
            assert_eq!(events(&trace)?, expected_events);
            assert_eq!(source.reads.load(Ordering::SeqCst), fail_at);
            check_raw(
                &store,
                &[user(format!("Live side effect {fail_at}").into())],
                &[named(key("target", 5.0), live.clone())],
            )?;
            assert!(users(&store)?.array().same_array(&captured_users.array()));
            assert!(keys(&store)?.array().same_array(&captured_keys.array()));
            assert!(required(captured_users.row_at(0)?)?.same_row(&owner));
            assert!(required(captured_keys.row_at(0)?)?.same_row(&target));
            assert!(required(target.field("name")?)?.strict_equals(&live));
            assert_eq!(required(live.as_array())?.own_indices()?, [0, 1]);
            assert_eq!(required(live.as_array())?.len()?, 2);
            assert_eq!(source.reads.load(Ordering::SeqCst), fail_at);
            assert_eq!(events(&trace)?, expected_events);
        }
    }
    Ok(())
}
