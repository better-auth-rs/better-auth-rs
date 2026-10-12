#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
//! Paired with memory-root-lifecycle.mjs and memory-root-order.mjs.

use super::*;
use crate::{LogArgument, LogLevel, LogSink, plugin_runtime::ModelFields};

fn bind(store: &EphemeralStore, name: &str, table: TableRef<FieldMap>) -> AuthResult<()> {
    store.operation(|op| op.replace_physical_table(name.to_owned(), Some(table)))
}

fn physical(store: &EphemeralStore, name: &str) -> AuthResult<TableRef<FieldMap>> {
    store.operation(|op| required(op.capture_physical_table(name)?))
}

fn rows(
    store: &EphemeralStore,
    values: impl IntoIterator<Item = FieldMap>,
) -> AuthResult<TableRef<FieldMap>> {
    let table = TableRef::new(store.operations.clone());
    for value in values {
        let _ = table.push(value)?;
    }
    Ok(table)
}

fn root_value(store: &EphemeralStore) -> AuthResult<FieldValue> {
    let root = store.operation(|op| op.capture_state())?;
    let fields = root
        .keys()
        .into_iter()
        .map(|name| {
            let value = root.table(&name)?.array().into();
            Ok((name, super::super::test_support::snapshot_tree(&value)?))
        })
        .collect::<AuthResult<FieldMap>>()?;
    Ok(fields.into())
}

struct RootProbe(FieldFunction);

impl FieldObjectSource for RootProbe {
    fn own_property_descriptor(
        &self,
        name: &str,
    ) -> AuthResult<Option<crate::field_value::FieldPropertyDescriptor>> {
        Ok(
            (name == "value").then(|| crate::field_value::FieldPropertyDescriptor {
                enumerable: true,
                configurable: true,
                property: crate::field_value::FieldProperty::Accessor {
                    get: Some(self.0.clone()),
                    set: None,
                },
            }),
        )
    }

    fn own_keys(&self) -> AuthResult<Vec<String>> {
        Ok(vec!["value".into()])
    }
    fn get_with_receiver(
        &self,
        name: &str,
        receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        if name == "value" {
            self.0.call_with(receiver, &[]).map(Some)
        } else {
            Ok(None)
        }
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        Ok([(
            "value".into(),
            required(self.get_with_receiver("value", &FieldValue::Undefined)?)?,
        )]
        .into())
    }
    fn set_with_receiver(&self, _: String, _: FieldValue, _: &FieldValue) -> AuthResult<bool> {
        Err(AuthError::internal("The root probe is read-only"))
    }

    fn define_own_property(
        &self,
        _: String,
        _: crate::field_value::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        Err(AuthError::internal("The root probe is read-only"))
    }
    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal("The root probe is read-only"))
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

fn probe(read: impl Fn() -> AuthResult<FieldValue> + Send + Sync + 'static) -> FieldValue {
    FieldValue::Object(FieldObject::from_source(Arc::new(RootProbe(
        FieldFunction::contextual(move |_, _| read()),
    ))))
}

fn probe_value(value: impl Into<FieldValue>) -> FieldValue {
    FieldMap::from([("value".into(), value.into())]).into()
}

#[tokio::test]
async fn numeric_root_order_clones_aliases_once_then_commits_each_binding() -> AuthResult<()> {
    let trace = Events::default();
    let counters = Arc::new(parking_lot::Mutex::new(indexmap::IndexMap::<
        &'static str,
        usize,
    >::new()));
    let observed = |label: &'static str| {
        let (trace, counters) = (trace.clone(), counters.clone());
        probe(move || {
            let read = {
                let mut counters = counters.lock();
                let count = counters.entry(label).or_default();
                *count += 1;
                *count
            };
            record(&trace, format!("clone:{label}:{read}"))?;
            Ok(format!("{label}:{read}").into())
        })
    };
    let store = EphemeralStore::empty(Arc::new(AuthConfig::default()));
    let shared = rows(&store, [named(key("target", 5.0), observed("key"))])?;
    let target = required(shared.row_at(0)?)?;
    let single = rows(
        &store,
        [[
            ("id".into(), "one".into()),
            ("probe".into(), observed("one")),
        ]
        .into()],
    )?;
    let users = rows(&store, [user(observed("user"))])?;
    let owner = required(users.row_at(0)?)?;
    for (name, table) in [
        ("extra", &shared),
        ("9", &shared),
        ("1", &single),
        ("user", &users),
        ("apikey", &shared),
    ] {
        bind(&store, name, table.clone())?;
    }
    assert!(events(&trace)?.is_empty());
    let (base, tx, queue) = store.begin_adapter_transaction()?;
    record(&trace, "transaction:enter")?;
    store.commit_adapter_transaction(base, tx, queue).await?;
    assert_eq!(
        events(&trace)?,
        [
            "clone:one:1",
            "clone:key:1",
            "clone:user:1",
            "clone:one:2",
            "clone:key:2",
            "clone:user:2",
            "transaction:enter"
        ]
    );
    let expected_key = named(key("target", 5.0), probe_value("key:2"));
    let expected: FieldMap = [
        (
            "1".into(),
            vec![FieldValue::from(FieldMap::from([
                ("id".into(), "one".into()),
                ("probe".into(), probe_value("one:2")),
            ]))]
            .into(),
        ),
        (
            "9".into(),
            vec![FieldValue::from(expected_key.clone())].into(),
        ),
        (
            "extra".into(),
            vec![FieldValue::from(expected_key.clone())].into(),
        ),
        (
            "user".into(),
            vec![FieldValue::from(user(probe_value("user:2")))].into(),
        ),
        ("apikey".into(), vec![FieldValue::from(expected_key)].into()),
    ]
    .into();
    assert_eq!(root_value(&store)?, expected.into());
    assert_eq!(
        store.operation(|op| op.root_keys())?,
        ["1", "9", "extra", "user", "apikey"]
    );
    let committed_keys = physical(&store, "apikey")?;
    let committed = required(committed_keys.row_at(0)?)?;
    for name in ["9", "extra", "apikey"] {
        let table = physical(&store, name)?;
        assert!(!table.array().same_array(&shared.array()));
        assert!(required(table.row_at(0)?)?.same_row(&committed));
        assert!(!committed.same_row(&target));
    }
    assert!(
        !physical(&store, "9")?
            .array()
            .same_array(&physical(&store, "extra")?.array())
    );
    assert!(
        !physical(&store, "extra")?
            .array()
            .same_array(&committed_keys.array())
    );
    assert!(
        !physical(&store, "9")?
            .array()
            .same_array(&committed_keys.array())
    );
    assert!(!physical(&store, "1")?.array().same_array(&single.array()));
    assert!(!physical(&store, "user")?.array().same_array(&users.array()));
    assert!(required(shared.row_at(0)?)?.same_row(&target));
    assert!(required(users.row_at(0)?)?.same_row(&owner));
    assert_eq!(
        counters
            .lock()
            .iter()
            .map(|(label, count)| (*label, *count))
            .collect::<Vec<_>>(),
        [("one", 2), ("key", 2), ("user", 2)]
    );
    Ok(())
}

#[tokio::test]
async fn root_clone_captures_keys_once_and_reads_later_bindings_live() -> AuthResult<()> {
    let trace = Events::default();
    let store = EphemeralStore::empty(Arc::new(AuthConfig::default()));
    let original = rows(&store, [key("target", 5.0)])?;
    let user_reads = Arc::new(AtomicUsize::new(0));
    let late_reads = Arc::new(AtomicUsize::new(0));
    let replacements = Arc::new(parking_lot::Mutex::new(Vec::<TableRef<FieldMap>>::new()));
    let late = rows(
        &store,
        [[
            ("id".into(), "late".into()),
            (
                "probe".into(),
                probe({
                    let (trace, reads) = (trace.clone(), late_reads.clone());
                    move || {
                        let read = reads.fetch_add(1, Ordering::SeqCst) + 1;
                        record(&trace, format!("clone:late:{read}"))?;
                        Ok("copied late".into())
                    }
                }),
            ),
        ]
        .into()],
    )?;
    let getter = probe({
        let (store, trace, reads, replacements, late) = (
            store.clone(),
            trace.clone(),
            user_reads.clone(),
            replacements.clone(),
            late.clone(),
        );
        move || {
            let read = reads.fetch_add(1, Ordering::SeqCst) + 1;
            record(&trace, format!("clone:user:{read}"))?;
            let replacement = rows(&store, [key("target", (read * 10) as f64)])?;
            replacements.lock().push(replacement.clone());
            bind(&store, "apikey", replacement)?;
            if read == 1 {
                bind(&store, "2", late.clone())?;
            }
            Ok(format!("copied user {read}").into())
        }
    });
    let captured_users = rows(&store, [user(getter.clone())])?;
    let owner = required(captured_users.row_at(0)?)?;
    bind(&store, "user", captured_users.clone())?;
    bind(&store, "apikey", original.clone())?;
    let (base, tx, queue) = store.begin_adapter_transaction()?;
    record(&trace, "transaction:enter")?;
    let selected = required(tx.get_user_by_id("owner").await?)?.field_values()?;
    let updated = decrement(&tx).await?;
    store.commit_adapter_transaction(base, tx, queue).await?;
    assert_eq!(
        events(&trace)?,
        [
            "clone:user:1",
            "clone:late:1",
            "clone:user:2",
            "transaction:enter"
        ]
    );
    assert_eq!(selected, user(probe_value("copied user 2")));
    assert_eq!(updated, key("target", 19.0));
    let expected: FieldMap = [
        (
            "2".into(),
            vec![FieldValue::from(FieldMap::from([
                ("id".into(), "late".into()),
                ("probe".into(), probe_value("copied late")),
            ]))]
            .into(),
        ),
        (
            "user".into(),
            vec![FieldValue::from(user(probe_value("copied user 2")))].into(),
        ),
        (
            "apikey".into(),
            vec![FieldValue::from(key("target", 19.0))].into(),
        ),
    ]
    .into();
    assert_eq!(root_value(&store)?, expected.into());
    assert_eq!(
        store.operation(|op| op.root_keys())?,
        ["2", "user", "apikey"]
    );
    assert_eq!(original.snapshot()?, [key("target", 5.0)]);
    let replacements = replacements.lock();
    assert_eq!(
        replacements
            .iter()
            .map(TableRef::snapshot)
            .collect::<AuthResult<Vec<_>>>()?,
        [vec![key("target", 10.0)], vec![key("target", 20.0)]]
    );
    assert!(
        !physical(&store, "user")?
            .array()
            .same_array(&captured_users.array())
    );
    assert!(
        !physical(&store, "apikey")?
            .array()
            .same_array(&required(replacements.last())?.array())
    );
    assert!(!physical(&store, "2")?.array().same_array(&late.array()));
    assert!(required(captured_users.row_at(0)?)?.same_row(&owner));
    assert!(required(owner.field("name")?)?.strict_equals(&getter));
    assert_eq!(required(getter.as_object())?.own_keys()?, ["value"]);
    assert_eq!(user_reads.load(Ordering::SeqCst), 2);
    assert_eq!(late_reads.load(Ordering::SeqCst), 1);
    // Release the retained probe's captured store after checking the original graph.
    let _ = owner.delete_field("name")?;
    Ok(())
}

#[tokio::test]
async fn earlier_key_root_publishes_before_later_user_json_failure() -> AuthResult<()> {
    let store = EphemeralStore::empty(Arc::new(AuthConfig::default()));
    let captured_keys = rows(&store, [key("target", 5.0)])?;
    let target = required(captured_keys.row_at(0)?)?;
    let captured_users = rows(&store, [user("Before".into())])?;
    let owner = required(captured_users.row_at(0)?)?;
    owner.set_field("name".into(), owner.field_value())?;
    bind(&store, "apikey", captured_keys.clone())?;
    bind(&store, "user", captured_users.clone())?;
    let expected_failure = required(owner.field_value().stringify().err())?;
    let (base, tx, queue) = store.begin_adapter_transaction()?;
    let base_owner = required(base.table("user")?.row_at(0)?)?;
    let working_owner = required(physical(&tx, "user")?.row_at(0)?)?;
    let callback = decrement(&tx).await?;
    let failure = required(
        store
            .commit_adapter_transaction(base, tx, queue)
            .await
            .err(),
    )?;
    assert!(matches!(&failure, AuthError::TypeError(_)));
    assert_eq!(
        failure
            .instrumentation_message()
            .expect("fixture error message"),
        expected_failure
            .instrumentation_message()
            .expect("fixture error message")
    );
    assert_eq!(callback, key("target", 4.0));
    assert_eq!(
        physical(&store, "apikey")?.snapshot()?,
        [key("target", 4.0)]
    );
    assert_eq!(
        physical(&store, "user")?.snapshot()?,
        [user(owner.field_value())]
    );
    assert_eq!(store.operation(|op| op.root_keys())?, ["apikey", "user"]);
    assert_eq!(captured_keys.snapshot()?, [key("target", 5.0)]);
    let committed_keys = physical(&store, "apikey")?;
    let committed = required(committed_keys.row_at(0)?)?;
    assert!(!committed_keys.array().same_array(&captured_keys.array()));
    assert!(!committed.same_row(&target));
    assert!(
        physical(&store, "user")?
            .array()
            .same_array(&captured_users.array())
    );
    assert!(required(physical(&store, "user")?.row_at(0)?)?.same_row(&owner));
    assert!(required(owner.field("name")?)?.strict_equals(&owner.field_value()));
    assert!(callback["createdAt"].strict_equals(&required(committed.field("createdAt")?)?));
    for owner in [&owner, &base_owner, &working_owner] {
        let _ = owner.delete_field("name")?;
    }
    Ok(())
}

#[tokio::test]
async fn deleted_working_root_key_removes_a_concurrent_live_rebinding() -> AuthResult<()> {
    let trace = Events::default();
    let store = EphemeralStore::empty(Arc::new(AuthConfig::default()));
    let reads = Arc::new(AtomicUsize::new(0));
    let getter = probe({
        let (store, trace, reads) = (store.clone(), trace.clone(), reads.clone());
        move || {
            let read = reads.fetch_add(1, Ordering::SeqCst) + 1;
            record(&trace, format!("clone:user:{read}"))?;
            if read == 2 {
                store.operation(|op| op.replace_physical_table("apikey".into(), None))?;
            }
            Ok(format!("copied user {read}").into())
        }
    });
    let captured_users = rows(&store, [user(getter.clone())])?;
    let owner = required(captured_users.row_at(0)?)?;
    let captured_keys = rows(&store, [key("target", 5.0)])?;
    let target = required(captured_keys.row_at(0)?)?;
    bind(&store, "user", captured_users.clone())?;
    bind(&store, "apikey", captured_keys.clone())?;
    let (base, tx, queue) = store.begin_adapter_transaction()?;
    record(&trace, "transaction:enter")?;
    assert_eq!(base.keys(), ["user", "apikey"]);
    assert_eq!(
        base.table("user")?.snapshot()?,
        [user(probe_value("copied user 1"))]
    );
    assert_eq!(base.table("apikey")?.snapshot()?, [key("target", 5.0)]);
    let expected: FieldValue = FieldMap::from([(
        "user".into(),
        vec![FieldValue::from(user(probe_value("copied user 2")))].into(),
    )])
    .into();
    assert_eq!(tx.operation(|op| op.root_keys())?, ["user"]);
    assert_eq!(root_value(&tx)?, expected);
    let selected = required(tx.get_user_by_id("owner").await?)?.field_values()?;
    assert_eq!(selected, user(probe_value("copied user 2")));
    let concurrent = rows(&store, [key("concurrent", 9.0)])?;
    let concurrent_row = required(concurrent.row_at(0)?)?;
    bind(&store, "apikey", concurrent.clone())?;
    record(&trace, "live:rebind")?;
    store.commit_adapter_transaction(base, tx, queue).await?;
    assert_eq!(
        events(&trace)?,
        [
            "clone:user:1",
            "clone:user:2",
            "transaction:enter",
            "live:rebind"
        ]
    );
    assert_eq!(store.operation(|op| op.root_keys())?, ["user"]);
    assert_eq!(root_value(&store)?, expected);
    assert_eq!(captured_keys.snapshot()?, [key("target", 5.0)]);
    assert!(required(captured_keys.row_at(0)?)?.same_row(&target));
    assert_eq!(concurrent.snapshot()?, [key("concurrent", 9.0)]);
    assert!(required(concurrent.row_at(0)?)?.same_row(&concurrent_row));
    assert!(required(captured_users.row_at(0)?)?.same_row(&owner));
    assert!(required(owner.field("name")?)?.strict_equals(&getter));
    assert!(
        !physical(&store, "user")?
            .array()
            .same_array(&captured_users.array())
    );
    assert!(!required(physical(&store, "user")?.row_at(0)?)?.same_row(&owner));
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    let _ = owner.delete_field("name")?;
    Ok(())
}

#[derive(Default)]
struct RootLogs(parking_lot::Mutex<Vec<serde_json::Value>>);
impl LogSink for RootLogs {
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> crate::AuthResult<()> {
        assert_eq!(level, LogLevel::Error);
        let mut entry = vec![serde_json::Value::String(message.to_string())];
        entry.extend(arguments.iter().map(|argument| match argument {
            LogArgument::Value(value) => (**value).clone(),
            argument => serde_json::Value::String(argument.to_string()),
        }));
        self.0.lock().push(entry.into());
        Ok(())
    }
}

#[tokio::test]
async fn schema_default_and_explicit_empty_roots_keep_create_and_error_timing() -> AuthResult<()> {
    for explicit in [false, true] {
        for alias in [false, true] {
            for serial in [false, true] {
                let trace = Events::default();
                let logs = Arc::new(RootLogs::default());
                let physical_name = if alias { "credential_store" } else { "apikey" };
                let prebuilt = !explicit && !alias;
                let observed = |name: &'static str| {
                    let (input, output) = (trace.clone(), trace.clone());
                    UserFieldConfig {
                        transform: Some(FieldTransforms {
                            input: Some(UserFieldTransform::new(move |value| {
                                record(&input, format!("input:{name}"))?;
                                Ok(value)
                            })),
                            output: Some(UserFieldTransform::new(move |value| {
                                record(&output, format!("output:{name}"))?;
                                Ok(value)
                            })),
                        }),
                        ..Default::default()
                    }
                };
                let mut config = AuthConfig::default();
                config.advanced.database.generate_id = Some(if serial {
                    crate::id::IdGeneration::Serial
                } else {
                    crate::id::IdGeneration::Database
                });
                config.logger = crate::LoggerConfig {
                    log: Some(logs.clone()),
                    ..Default::default()
                }
                .into();
                config.base_url = "http://memory-root.test".into();
                let mut models = ModelFields::default();
                models.register(
                    EntityRole::ApiKey,
                    UserConfig {
                        additional_fields: Some(
                            [
                                ("name".into(), observed("name")),
                                ("before".into(), observed("before")),
                                ("id".into(), UserFieldConfig::default()),
                                ("after".into(), observed("after")),
                            ]
                            .into(),
                        ),
                    },
                );
                models.set_model_name(EntityRole::ApiKey, Some(physical_name))?;
                let config = Arc::new(config);
                let mut store = if explicit {
                    EphemeralStore::empty(config)
                } else {
                    EphemeralStore::from_schema(config, &models)
                };
                models.bind_execution_gate(store.operations.clone())?;
                store.model_fields = models;
                record(&trace, "init")?;
                let context = crate::AuthContext::<super::super::StatelessSchema>::new(
                    store.config.clone(),
                    Arc::new(store.clone()),
                )
                .expect("fixture context initializes");
                let (found, count, filtered) = context
                    .with_native_context(Default::default(), |_| async {
                        let found = store
                            .raw("apikey", "findMany", |op| {
                                op.capture_table(EntityRole::ApiKey)?.snapshot()
                            })
                            .await;
                        let count = store
                            .raw("apikey", "count", |op| op.table_length(EntityRole::ApiKey))
                            .await;
                        let filtered = store
                            .raw("apikey", "count", |op| {
                                op.capture_table(EntityRole::ApiKey)?.len()
                            })
                            .await;
                        Ok((found, count, filtered))
                    })
                    .await?;
                if prebuilt {
                    assert!(found?.is_empty());
                    assert_eq!(count?, 0);
                    assert_eq!(filtered?, 0);
                } else {
                    for error in [required(found.err())?, required(filtered.err())?] {
                        assert!(
                            matches!(&error, AuthError::Internal(message) if message == &format!("Model {physical_name} not found"))
                        );
                    }
                    assert!(
                        matches!(count, Err(AuthError::TypeError(message)) if message == "Cannot read properties of undefined (reading 'length')")
                    );
                }
                let initial_keys = if explicit {
                    vec![]
                } else {
                    vec!["user", "session", "account", "verification", "apikey"]
                };
                let expected_logs = if prebuilt {
                    vec![]
                } else {
                    vec![
                        serde_json::json!([
                            format!("[MemoryAdapter] Model {physical_name} not found in the DB"),
                            initial_keys
                        ]);
                        2
                    ]
                };
                assert_eq!(*logs.0.lock(), expected_logs);
                assert_eq!(events(&trace)?, ["init"]);
                assert_eq!(store.operation(|op| op.root_keys())?, initial_keys);
                let mut input = key("target", 5.0);
                let _ = input.insert("before".into(), "before".into());
                let _ = input.insert("after".into(), "after".into());
                let result = store.create_api_key_record(input.clone()).await;
                if serial && !prebuilt {
                    assert!(
                        matches!(result, Err(AuthError::TypeError(message)) if message == "Cannot read properties of undefined (reading 'length')")
                    );
                    assert_eq!(events(&trace)?, ["init", "input:name", "input:before"]);
                    assert_eq!(store.operation(|op| op.root_keys())?, initial_keys);
                } else {
                    let output = required(result?)?;
                    let mut expected = input.clone();
                    if serial {
                        let _ = expected.insert("id".into(), "1".into());
                    }
                    assert_eq!(output, expected);
                    assert_eq!(
                        events(&trace)?,
                        [
                            "init",
                            "input:name",
                            "input:before",
                            "input:after",
                            "output:name",
                            "output:before",
                            "output:after"
                        ]
                    );
                    let mut stored = input.clone();
                    let _ = stored.insert("metadata".into(), "null".into());
                    if serial {
                        let _ = stored.insert("id".into(), 1.0.into());
                    }
                    assert_eq!(physical(&store, physical_name)?.snapshot()?, [stored]);
                    let source = required(physical(&store, physical_name)?.row_at(0)?)?;
                    assert!(
                        required(source.field("createdAt")?)?.strict_equals(&input["createdAt"])
                    );
                    if explicit {
                        assert_eq!(store.operation(|op| op.root_keys())?, [physical_name]);
                    }
                    let sources = store
                        .raw("apikey", "findMany", |op| {
                            op.capture_table(EntityRole::ApiKey)?.snapshot_refs()
                        })
                        .await?;
                    let readback = store
                        .project_plugin_refs(EntityRole::ApiKey, sources)
                        .await?;
                    assert_eq!(readback, [expected]);
                    assert!(
                        required(readback.first())?["createdAt"]
                            .strict_equals(&output["createdAt"])
                    );
                    assert_eq!(
                        events(&trace)?,
                        [
                            "init",
                            "input:name",
                            "input:before",
                            "input:after",
                            "output:name",
                            "output:before",
                            "output:after",
                            "output:name",
                            "output:before",
                            "output:after"
                        ]
                    );
                }
                assert_eq!(*logs.0.lock(), expected_logs);
            }
        }
    }
    Ok(())
}
