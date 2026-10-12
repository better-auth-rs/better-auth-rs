#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "These regressions require complete fixture records and fail immediately on an invalid fixture shape."
)]

use super::*;
use crate::field_value::{FieldObjectSource, FieldPropertyDescriptor};
use crate::{AuthError, FieldFunction, FieldObject};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

#[path = "session_methods.rs"]
mod methods;

#[tokio::test]
async fn session_writes_preserve_complete_existing_index_entries() -> AuthResult<()> {
    let (store, cache) = storage()?;
    let user = store
        .create_user(CreateUser::new().with_email("full-index@example.test"))
        .await?;
    let owner = user.id.field_value();
    let index = super::super::super::sessions::active_sessions_key(&owner)?;
    let early = FieldMap::from([
        ("extra".into(), payload(2.0)),
        ("expiresAt".into(), (EXPIRY - 1_000).into()),
        ("token".into(), "early".into()),
    ]);
    let late = FieldMap::from([
        ("token".into(), "late".into()),
        ("note".into(), "retain this field and position".into()),
        ("expiresAt".into(), (EXPIRY + 1_000).into()),
    ]);
    cache
        .set_native(
            &index,
            &FieldValue::from(vec![late.clone().into(), early.clone().into()])
                .stringify_native()?,
            None,
        )
        .await?;
    let created = store
        .create_session(session_input(user.id, "current".into()))
        .await?;
    let current = FieldMap::from([
        ("token".into(), "current".into()),
        ("expiresAt".into(), EXPIRY.into()),
    ]);
    let expected = FieldValue::from(vec![
        early.clone().into(),
        current.into(),
        late.clone().into(),
    ]);
    assert_eq!(
        encoded(&cache, &index).await?,
        expected.stringify()?.unwrap()
    );

    let mut envelope =
        crate::utils::json::parse_native_json(&encoded(&cache, &"current".into()).await?.into())?
            .enumerable_fields()?;
    let _ = envelope.insert("unrelatedEnvelopeField".into(), true.into());
    cache
        .set(
            "current",
            &FieldValue::from(envelope).stringify()?.unwrap(),
            None,
        )
        .await?;
    let updated = store
        .update_session_fields(
            "current",
            FieldMap::from([("payload".into(), payload(3.0))]),
        )
        .await?
        .unwrap();
    assert_eq!(updated.token, created.token);
    assert_eq!(
        encoded(&cache, &index).await?,
        expected.stringify()?.unwrap()
    );
    let envelope =
        crate::utils::json::parse_native_json(&encoded(&cache, &"current".into()).await?.into())?
            .enumerable_fields()?;
    assert_eq!(
        envelope.keys().map(String::as_str).collect::<Vec<_>>(),
        ["session", "user"]
    );
    assert_eq!(envelope["session"].model_property("payload")?, payload(3.0));

    store.delete_session("current").await?;
    let expected = FieldValue::from(vec![early.into(), late.into()]);
    assert_eq!(
        encoded(&cache, &index).await?,
        expected.stringify()?.unwrap()
    );

    let selected = store.references_value(&owner).await?;
    let concurrent = FieldMap::from([
        ("extra".into(), payload(4.0)),
        ("token".into(), "concurrent".into()),
        ("expiresAt".into(), (EXPIRY + 2_000).into()),
    ]);
    let mut changed = expected.as_array().unwrap().snapshot()?;
    changed.push(concurrent.clone().into());
    cache
        .set_native(&index, &FieldValue::from(changed).stringify_native()?, None)
        .await?;
    store
        .queue_cached_user_session_deletion_value(owner, selected, None)
        .await?;
    assert_eq!(
        encoded(&cache, &index).await?,
        FieldValue::from(vec![concurrent.into()])
            .stringify()?
            .unwrap(),
    );
    Ok(())
}

#[tokio::test]
async fn index_failure_preserves_the_preceding_session_write() -> AuthResult<()> {
    let (store, cache) = storage()?;
    let user = store
        .create_user(CreateUser::new().with_email("index-error@example.test"))
        .await?;
    let index = super::super::super::sessions::active_sessions_key(&user.id.field_value())?;
    let created = store
        .create_session(session_input(user.id, "current".into()))
        .await?;
    let before =
        crate::utils::json::parse_native_json(&encoded(&cache, &"current".into()).await?.into())?;
    cache.set_native(&index, &"{}".into(), None).await?;
    let error = store
        .update_session_fields(
            "current",
            FieldMap::from([("payload".into(), payload(5.0))]),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("filter"));
    let mut expected = FieldMap::from(created);
    let _ = expected.insert("payload".into(), payload(5.0));
    let expected = FieldValue::from(FieldMap::from([
        ("session".into(), expected.into()),
        ("user".into(), before.model_property("user")?),
    ]));
    assert_eq!(
        encoded(&cache, &"current".into()).await?,
        expected.stringify()?.unwrap()
    );
    assert_eq!(encoded(&cache, &index).await?, "{}");
    Ok(())
}

#[derive(Default)]
struct NativeCache {
    native: Mutex<HashMap<Vec<u16>, FieldValue>>,
    values: MemoryCacheAdapter,
    reads: Mutex<Vec<FieldValue>>,
}

impl NativeCache {
    fn seed(&self, key: &str, value: FieldValue) {
        let _ = self
            .native
            .lock()
            .unwrap()
            .insert(key.encode_utf16().collect(), value);
    }
}

#[async_trait]
impl SecondaryStorage for NativeCache {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        self.get_native(&key.into())
            .await?
            .map(|value| value.json())
            .transpose()
            .map(Option::flatten)
    }

    async fn get_native(&self, key: &FieldValue) -> AuthResult<Option<FieldValue>> {
        self.reads.lock().unwrap().push(key.clone());
        let value = self
            .native
            .lock()
            .unwrap()
            .get(key.display_utf16()?.as_utf16())
            .cloned();
        match value {
            Some(value) => Ok(Some(value)),
            None => self.values.get_native(key).await,
        }
    }

    async fn set_native(
        &self,
        key: &FieldValue,
        value: &FieldValue,
        ttl: Option<f64>,
    ) -> AuthResult<()> {
        let _ = self
            .native
            .lock()
            .unwrap()
            .remove(key.display_utf16()?.as_utf16());
        self.values.set_native(key, value, ttl).await
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        let _ = self
            .native
            .lock()
            .unwrap()
            .remove(&key.encode_utf16().collect::<Vec<_>>());
        self.values.delete(key).await
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        let value = self.get(key).await?;
        self.delete(key).await?;
        Ok(value)
    }
}

fn native_store(cache: Arc<NativeCache>) -> AuthResult<SecondaryStore<StatelessSchema>> {
    let config = Arc::new(AuthConfig::default());
    Ok(SecondaryStore::new(
        Arc::new(EphemeralStore::new(config.clone())),
        cache,
        config,
        Default::default(),
    )?
    .with_clock(|| chrono::DateTime::from_timestamp_millis(NOW).unwrap()))
}

#[tokio::test]
async fn cached_array_records_are_spread_before_their_dates_are_constructed() -> AuthResult<()> {
    let (store, cache) = storage()?;
    cache
        .set("array", r#"{"session":[7],"user":[9]}"#, None)
        .await?;
    let (single, relation) = store.get_session_snapshot("array").await?.unwrap();
    let mut expected = FieldMap::from([("0".into(), 7.into())]);
    for name in ["expiresAt", "createdAt", "updatedAt"] {
        let _ = expected.insert(name.into(), FieldDate::invalid().into());
    }
    assert_eq!(FieldMap::from(single), expected);
    let user = relation.unwrap().into_typed()?.unwrap().user;
    assert_eq!(
        FieldMap::from(user),
        FieldMap::from([
            ("0".into(), 9.into()),
            ("createdAt".into(), FieldDate::invalid().into()),
            ("updatedAt".into(), FieldDate::invalid().into()),
        ])
    );
    let batch = store.get_session_snapshots(&["array".into()], true).await?;
    let _ = expected.remove("createdAt");
    let _ = expected.remove("updatedAt");
    assert_eq!(batch.len(), 1);
    assert_eq!(FieldMap::from(batch[0].0.clone()), expected);
    Ok(())
}

struct Properties {
    values: FieldMap,
    reads: Arc<Mutex<Vec<String>>>,
    reject: Option<&'static str>,
}

impl FieldObjectSource for Properties {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        crate::FieldObject::from(self.values.clone()).own_keys()
    }

    fn get_with_receiver(
        &self,
        name: &str,
        _receiver: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        self.reads.lock().unwrap().push(name.into());
        if self.reject == Some(name) {
            return Err(AuthError::bad_request("original cached property failure"));
        }
        Ok(self.values.get(name).cloned())
    }

    fn own_property_descriptor(&self, name: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        Ok(self
            .values
            .get(name)
            .cloned()
            .map(FieldPropertyDescriptor::data))
    }

    fn set_with_receiver(
        &self,
        _: String,
        _: FieldValue,
        _receiver: &FieldValue,
    ) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The cached getter fixture is read-only",
        ))
    }

    fn delete(&self, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The cached getter fixture is read-only",
        ))
    }

    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.own_keys()?
            .into_iter()
            .map(|name| {
                Ok((
                    name.clone(),
                    self.get_with_receiver(&name, &FieldValue::Undefined)?
                        .unwrap_or_default(),
                ))
            })
            .collect()
    }

    fn identity(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }

    fn define_own_property(
        &self,
        _name: String,
        _definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        Err(AuthError::internal(
            "This contract source does not define properties",
        ))
    }
}

fn function_record(
    fields: FieldMap,
    reads: Arc<Mutex<Vec<String>>>,
    reject: Option<&'static str>,
) -> FieldValue {
    FieldFunction::contextual_with_properties(
        |_, _| Ok(FieldValue::Undefined),
        FieldObject::from_source(Arc::new(Properties {
            values: fields,
            reads,
            reject,
        })),
    )
    .into()
}

#[tokio::test]
async fn native_cache_consumers_read_only_the_properties_used_by_each_protocol() -> AuthResult<()> {
    let cache = Arc::new(NativeCache::default());
    let store = native_store(cache.clone())?;
    let root_reads = Arc::new(Mutex::new(Vec::new()));
    let session_reads = Arc::new(Mutex::new(Vec::new()));
    let user_reads = Arc::new(Mutex::new(Vec::new()));
    let session = function_record(
        FieldMap::from([
            ("token".into(), "native".into()),
            ("expiresAt".into(), EXPIRY.into()),
            ("createdAt".into(), NOW.into()),
            ("updatedAt".into(), NOW.into()),
        ]),
        session_reads.clone(),
        None,
    );
    let user = function_record(
        FieldMap::from([
            ("id".into(), "owner".into()),
            ("createdAt".into(), NOW.into()),
            ("updatedAt".into(), NOW.into()),
        ]),
        user_reads.clone(),
        None,
    );
    cache.seed(
        "native",
        function_record(
            FieldMap::from([
                ("session".into(), session),
                ("user".into(), user),
                ("unrelated".into(), true.into()),
            ]),
            root_reads.clone(),
            Some("unrelated"),
        ),
    );
    let (single, _) = store.get_session_snapshot("native").await?.unwrap();
    assert_eq!(single.token, "native");
    assert_eq!(
        *root_reads.lock().unwrap(),
        [
            "session", "session", "session", "session", "user", "user", "user"
        ]
    );
    assert_eq!(
        *session_reads.lock().unwrap(),
        [
            "token",
            "expiresAt",
            "createdAt",
            "updatedAt",
            "expiresAt",
            "createdAt",
            "updatedAt"
        ]
    );
    assert_eq!(
        *user_reads.lock().unwrap(),
        ["id", "createdAt", "updatedAt", "createdAt", "updatedAt"]
    );

    root_reads.lock().unwrap().clear();
    session_reads.lock().unwrap().clear();
    user_reads.lock().unwrap().clear();
    let batch = store
        .get_session_snapshots(&["native".into()], true)
        .await?;
    assert_eq!(batch.len(), 1);
    assert_eq!(
        *root_reads.lock().unwrap(),
        ["session", "session", "session", "user", "user", "user"]
    );
    assert_eq!(
        *session_reads.lock().unwrap(),
        [
            "expiresAt",
            "token",
            "expiresAt",
            "createdAt",
            "updatedAt",
            "expiresAt"
        ]
    );
    assert_eq!(
        *user_reads.lock().unwrap(),
        ["id", "createdAt", "updatedAt", "createdAt", "updatedAt"]
    );
    Ok(())
}

#[tokio::test]
async fn expired_batch_records_do_not_read_later_fields_or_user_properties() -> AuthResult<()> {
    let cache = Arc::new(NativeCache::default());
    let store = native_store(cache.clone())?;
    let reads = Arc::new(Mutex::new(Vec::new()));
    let session = function_record(
        FieldMap::from([
            ("expiresAt".into(), (NOW - 1).into()),
            ("token".into(), "expired".into()),
        ]),
        reads.clone(),
        Some("token"),
    );
    cache.seed(
        "expired",
        function_record(
            FieldMap::from([("session".into(), session), ("user".into(), true.into())]),
            Arc::new(Mutex::new(Vec::new())),
            Some("user"),
        ),
    );
    assert!(
        store
            .get_session_snapshots(&["expired".into()], true)
            .await?
            .is_empty()
    );
    assert_eq!(*reads.lock().unwrap(), ["expiresAt"]);
    Ok(())
}

#[tokio::test]
async fn user_refresh_consumes_native_index_entries_and_retains_the_session_value() -> AuthResult<()>
{
    let cache = Arc::new(NativeCache::default());
    let store = native_store(cache.clone())?;
    let user = store
        .create_user(CreateUser::new().with_email("native-refresh@example.test"))
        .await?;
    let id = user.id.typed()?.clone();
    let index = format!("active-sessions-{id}");
    let reference = FieldDate::from_milliseconds_with_properties(
        0.0,
        FieldMap::from([
            ("token".into(), "native".into()),
            ("expiresAt".into(), EXPIRY.into()),
        ])
        .into(),
    );
    cache.seed(&index, vec![reference.into()].into());
    let session = FieldDate::from_milliseconds_with_properties(
        NOW as f64,
        FieldMap::from([("expiresAt".into(), EXPIRY.into())]).into(),
    );
    cache.seed(
        "native",
        FieldMap::from([("session".into(), session.into())]).into(),
    );
    let updated = store
        .update_user(
            &id,
            UpdateUser {
                name: Some("Refreshed".into()).into(),
                ..Default::default()
            },
        )
        .await?;
    let encoded = encoded(&cache.values, &"native".into()).await?;
    let after = crate::utils::json::parse_native_json(&encoded.into())?;
    assert_eq!(after.model_property("session")?, DATE_TEXT.into());
    assert_eq!(
        after.model_property("user")?.model_property("name")?,
        updated.name.field_value()
    );
    assert!(
        cache
            .reads
            .lock()
            .unwrap()
            .iter()
            .any(|key| key == &FieldValue::from("native"))
    );
    Ok(())
}
