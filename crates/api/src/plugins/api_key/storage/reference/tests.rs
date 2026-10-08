#![expect(
    clippy::unwrap_used,
    reason = "Cache contract fixtures fail immediately if fixture setup or an observation is invalid."
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthContext, FieldMap, SchemaValue,
    store::{EphemeralStore, StatelessSchema},
};
use serde_json::Value;

use super::super::{ApiKeyConfig, ApiKeyStorage, deserialize, list, put, remove_cached};
use super::*;

const INDEX: &str = "api-key:by-ref:owner";

#[derive(Debug, PartialEq)]
enum Write {
    Set(FieldValue, String),
    Delete(FieldValue),
}

#[derive(Default)]
struct Cache {
    values: Mutex<HashMap<Vec<u16>, FieldValue>>,
    writes: Mutex<Vec<Write>>,
}

impl Cache {
    fn seed(&self, key: &str, value: FieldValue) {
        let _ = self
            .values
            .lock()
            .unwrap()
            .insert(key.encode_utf16().collect(), value);
        self.writes.lock().unwrap().clear();
    }

    fn value(&self, key: &str) -> Option<FieldValue> {
        self.values
            .lock()
            .unwrap()
            .get(&key.encode_utf16().collect::<Vec<_>>())
            .cloned()
    }
}

#[async_trait]
impl SecondaryStorage for Cache {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        self.get_native(&key.into())
            .await?
            .map(|value| value.json())
            .transpose()
            .map(Option::flatten)
    }

    async fn get_native(&self, key: &FieldValue) -> AuthResult<Option<FieldValue>> {
        Ok(self
            .values
            .lock()
            .unwrap()
            .get(key.display_utf16()?.as_utf16())
            .cloned())
    }

    async fn set_native(&self, key: &FieldValue, value: &str, _: Option<f64>) -> AuthResult<()> {
        let _ = self
            .values
            .lock()
            .unwrap()
            .insert(key.display_utf16()?.as_utf16().to_vec(), value.into());
        self.writes
            .lock()
            .unwrap()
            .push(Write::Set(key.clone(), value.into()));
        Ok(())
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.delete_native(&key.into()).await
    }

    async fn delete_native(&self, key: &FieldValue) -> AuthResult<()> {
        let _ = self
            .values
            .lock()
            .unwrap()
            .remove(key.display_utf16()?.as_utf16());
        self.writes.lock().unwrap().push(Write::Delete(key.clone()));
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        self.values
            .lock()
            .unwrap()
            .remove(&key.encode_utf16().collect::<Vec<_>>())
            .map(|value| value.json())
            .transpose()
            .map(Option::flatten)
    }
}

fn record(id: FieldValue) -> ApiKey {
    let mut key = deserialize(Some(r#"{"id":"key","key":"hash","referenceId":"owner","createdAt":"2026-10-01T00:00:00.000Z","updatedAt":"2026-10-01T00:00:00.000Z"}"#.into())).unwrap();
    key.id = SchemaValue::from_field(id);
    key
}

fn context(cache: Arc<Cache>, fallback: bool) -> (ApiKeyConfig, AuthContext<StatelessSchema>) {
    let config = Arc::new(AuthConfig::new(
        "reference-list-contract-secret-at-least-32-characters",
    ));
    let database = Arc::new(EphemeralStore::new(config.clone()));
    (
        ApiKeyConfig {
            storage: ApiKeyStorage::SecondaryStorage,
            fallback_to_database: fallback,
            custom_storage: Some(cache),
            ..Default::default()
        },
        AuthContext::new(config, database),
    )
}

#[tokio::test]
async fn reference_mutations_compare_object_identity_and_native_numbers() {
    let cache = Cache::default();
    let id = FieldValue::from(vec![7.0.into()]);
    let key = record(id.clone());
    cache.seed(INDEX, "[[7]]".into());
    modify_reference(&cache, &key, true).await.unwrap();
    assert_eq!(cache.value(INDEX), Some("[[7],[7]]".into()));
    cache.seed(INDEX, "[[7]]".into());
    modify_reference(&cache, &key, false).await.unwrap();
    assert_eq!(cache.value(INDEX), Some("[[7]]".into()));

    cache.seed(INDEX, vec![id.clone()].into());
    modify_reference(&cache, &key, true).await.unwrap();
    assert_eq!(cache.value(INDEX), Some("[[7]]".into()));
    cache.seed(INDEX, vec![id].into());
    modify_reference(&cache, &key, false).await.unwrap();
    assert_eq!(cache.value(INDEX), None);

    let key = record(FieldValue::Number(f64::NAN));
    for insert in [true, false] {
        cache.seed(INDEX, vec![FieldValue::Number(f64::NAN)].into());
        modify_reference(&cache, &key, insert).await.unwrap();
        assert_eq!(cache.value(INDEX), Some("[null]".into()));
    }
}

#[tokio::test]
async fn valid_non_arrays_fail_at_the_method_without_rewriting_the_index() {
    let cache = Cache::default();
    let key = record("key".into());
    for source in ["null", "{}", "7", "false"] {
        for insert in [true, false] {
            cache.seed(INDEX, source.into());
            let error = modify_reference(&cache, &key, insert).await.unwrap_err();
            let method = if insert { "includes" } else { "filter" };
            assert!(error.to_string().contains(method), "{source}: {error}");
            assert_eq!(cache.value(INDEX), Some(source.into()));
            assert!(cache.writes.lock().unwrap().is_empty());
        }
        cache.seed(INDEX, source.into());
        assert!(put(&cache, &key, false).await.is_err());
        assert_eq!(cache.value(INDEX), Some(source.into()));
        let serialized = super::super::serialize(&key).unwrap();
        assert_eq!(
            *cache.writes.lock().unwrap(),
            vec![
                Write::Set("api-key:hash".into(), serialized.clone()),
                Write::Set("api-key:by-id:key".into(), serialized),
            ]
        );
        cache.writes.lock().unwrap().clear();
        assert!(remove_cached(&cache, &key, false).await.is_err());
        assert_eq!(cache.value(INDEX), Some(source.into()));
        assert_eq!(
            *cache.writes.lock().unwrap(),
            vec![
                Write::Delete("api-key:hash".into()),
                Write::Delete("api-key:by-id:key".into()),
            ]
        );
    }
    for source in ["malformed", ""] {
        cache.seed(INDEX, source.into());
        modify_reference(&cache, &key, true).await.unwrap();
        assert_eq!(cache.value(INDEX), Some(r#"["key"]"#.into()));
    }
    cache.seed(INDEX, FieldMap::new().into());
    modify_reference(&cache, &key, true).await.unwrap();
    assert_eq!(cache.value(INDEX), Some(r#"["key"]"#.into()));
}

#[tokio::test]
async fn string_reference_lists_use_includes_and_code_point_spread() {
    let cache = Cache::default();
    cache.seed(INDEX, r#""A😀B""#.into());
    modify_reference(&cache, &record("😀".into()), true)
        .await
        .unwrap();
    assert_eq!(cache.value(INDEX), Some(r#""A😀B""#.into()));
    modify_reference(&cache, &record("C".into()), true)
        .await
        .unwrap();
    assert_eq!(cache.value(INDEX), Some(r#"["A","😀","B","C"]"#.into()));
    cache.seed(INDEX, r#""A😀B""#.into());
    assert!(
        modify_reference(&cache, &record("A".into()), false)
            .await
            .unwrap_err()
            .to_string()
            .contains("filter")
    );
    assert_eq!(cache.value(INDEX), Some(r#""A😀B""#.into()));
    assert!(cache.writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn escaped_surrogate_ids_survive_cache_writes_lists_and_removal() {
    let cache = Arc::new(Cache::default());
    let (config, ctx) = context(cache.clone(), false);
    let mut key = record(Utf16String::from_units(vec![0xd800]).into());
    key.key_hash = SchemaValue::from_field(Utf16String::from_units(vec![0xdc00]).into());
    cache.seed(INDEX, r#"["\ud800"]"#.into());
    put(cache.as_ref(), &key, false).await.unwrap();
    assert_eq!(cache.value(INDEX), Some(r#"["\ud800"]"#.into()));
    let keys = list(&config, &ctx, "owner", None).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys.first().unwrap().id, key.id);
    assert_eq!(keys.first().unwrap().key_hash, key.key_hash);
    remove_cached(cache.as_ref(), &key, false).await.unwrap();
    assert!(cache.values.lock().unwrap().is_empty());

    key.reference_id = SchemaValue::from_field(Utf16String::from_units(vec![0xdfff]).into());
    put(cache.as_ref(), &key, false).await.unwrap();
    let index = cache_key("api-key:by-ref:", &key.reference_id.field_value()).unwrap();
    assert_eq!(
        cache.get_native(&index).await.unwrap(),
        Some(r#"["\ud800"]"#.into())
    );
    remove_cached(cache.as_ref(), &key, false).await.unwrap();
    assert!(cache.values.lock().unwrap().is_empty());
}

#[tokio::test]
async fn list_consumes_length_and_index_properties_without_array_normalization() {
    let cache = Arc::new(Cache::default());
    for name in ["A", "B"] {
        let mut key = record(name.into());
        key.key_hash = name.to_owned().into();
        put(cache.as_ref(), &key, false).await.unwrap();
    }
    for fallback in [false, true] {
        let (config, ctx) = context(cache.clone(), fallback);
        for (source, expected) in [
            (r#""AB""#, vec!["A", "B"]),
            (r#"{"length":2,"0":"B","1":"A"}"#, vec!["B", "A"]),
            ("{}", vec![]),
            ("7", vec![]),
            ("malformed", vec![]),
        ] {
            cache.seed(INDEX, source.into());
            let keys = list(&config, &ctx, "owner", None).await.unwrap();
            assert_eq!(
                keys.iter()
                    .map(|key| key.id.typed().unwrap().as_str())
                    .collect::<Vec<_>>(),
                expected
            );
            assert_eq!(cache.value(INDEX), Some(source.into()));
            assert!(cache.writes.lock().unwrap().is_empty());
        }
        cache.seed(INDEX, "null".into());
        assert!(
            list(&config, &ctx, "owner", None)
                .await
                .unwrap_err()
                .to_string()
                .contains("length")
        );
        assert_eq!(cache.value(INDEX), Some("null".into()));
        assert!(cache.writes.lock().unwrap().is_empty());
    }
}
