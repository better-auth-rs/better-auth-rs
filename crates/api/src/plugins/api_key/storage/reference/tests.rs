#![expect(
    clippy::unwrap_used,
    reason = "Cache contract fixtures fail immediately if fixture setup or an observation is invalid."
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthContext, AuthRecordFields, FieldMap, SchemaValue,
    store::{EphemeralStore, StatelessSchema},
};
use serde_json::{Value, json};

use crate::plugins::api_key::{ApiKeyPlugin, handlers, types::ListKeysQuery};

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
    reads: Mutex<Vec<FieldValue>>,
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
        self.reads.lock().unwrap().push(key.clone());
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
    assert_eq!(
        property(keys.first().unwrap(), "id").unwrap(),
        key.id.field_value()
    );
    assert_eq!(
        property(keys.first().unwrap(), "key").unwrap(),
        key.key_hash.field_value()
    );
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
async fn raw_utf16_cache_json_preserves_records_and_reference_mutation() {
    let cache = Arc::new(Cache::default());
    let (config, ctx) = context(cache.clone(), false);
    let key = record(Utf16String::from_units(vec![0xd800]).into());
    let index: FieldValue = Utf16String::from_units(
        r#"[""#.encode_utf16().chain([0xd800]).chain(r#""]"#.encode_utf16()).collect(),
    )
    .into();
    let stored: FieldValue = Utf16String::from_units(
        r#"{"id":""#
            .encode_utf16()
            .chain([0xd800])
            .chain(r#"","key":"hash","referenceId":"owner","createdAt":"2026-10-01T00:00:00.000Z","updatedAt":"2026-10-01T00:00:00.000Z"}"#.encode_utf16())
            .collect(),
    )
    .into();
    let cache_id = cache_key("api-key:by-id:", &key.id.field_value()).unwrap();
    cache.seed(INDEX, index);
    let _ = cache.values.lock().unwrap().insert(
        cache_id.display_utf16().unwrap().as_utf16().to_vec(),
        stored,
    );
    let keys = list(&config, &ctx, "owner", None).await.unwrap();
    let mut expected = key.field_values().unwrap();
    expected.retain(|_, value| !value.is_undefined());
    assert_eq!(keys, vec![FieldValue::from(expected)]);
    let before = cache.values.lock().unwrap().clone();
    cache.reads.lock().unwrap().clear();
    let response = handlers::list_keys_core(
        "owner",
        &ListKeysQuery::default(),
        &ApiKeyPlugin::with_config(config),
        &ctx,
    )
    .await
    .unwrap();
    assert!(matches!(
        response.api_keys.first().unwrap().created_at.field_value(),
        FieldValue::Date(_)
    ));
    assert_eq!(
        response
            .api_keys
            .first()
            .unwrap()
            .field_values()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "id",
            "referenceId",
            "createdAt",
            "updatedAt",
            "expiresAt",
            "lastRefillAt",
            "lastRequest",
            "metadata",
            "permissions"
        ]
    );
    assert_eq!(
        serde_json::to_string(&response).unwrap(),
        r#"{"apiKeys":[{"id":"\ud800","referenceId":"owner","createdAt":"2026-10-01T00:00:00.000Z","updatedAt":"2026-10-01T00:00:00.000Z","expiresAt":null,"lastRefillAt":null,"lastRequest":null,"metadata":null,"permissions":null}],"total":1}"#
    );
    assert_eq!(
        *cache.reads.lock().unwrap(),
        vec![FieldValue::from(INDEX), cache_id]
    );
    assert_eq!(*cache.values.lock().unwrap(), before);
    assert!(cache.writes.lock().unwrap().is_empty());
    modify_reference(cache.as_ref(), &key, true).await.unwrap();
    assert_eq!(cache.value(INDEX), Some(r#"["\ud800"]"#.into()));
    remove_cached(cache.as_ref(), &key, false).await.unwrap();
    assert!(cache.values.lock().unwrap().is_empty());

    let native = vec![key.id.field_value()].into();
    cache.seed(INDEX, native);
    let expected = cache.value(INDEX).unwrap();
    assert!(
        read(cache.as_ref(), &INDEX.into())
            .await
            .unwrap()
            .strict_equals(&expected)
    );
    for units in [vec![0xd800], vec![34, 92, 0xd800, 34]] {
        let invalid: FieldValue = Utf16String::from_units(units).into();
        assert!(deserialize(Some(invalid.clone())).is_none());
        cache.seed(INDEX, invalid);
        modify_reference(cache.as_ref(), &key, true).await.unwrap();
        assert_eq!(cache.value(INDEX), Some(r#"["\ud800"]"#.into()));
    }
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
                    .map(|key| property(key, "id").unwrap().as_str().unwrap().to_owned())
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

#[tokio::test]
async fn idle_workers_preserve_raw_length_before_group_deduplication_and_owner_filtering() {
    let cache = Arc::new(Cache::default());
    let (config, ctx) = context(cache.clone(), false);
    let other = Arc::new(Cache::default());
    other.seed(INDEX, r#"["without-id"]"#.into());
    other.seed("api-key:by-id:without-id", r#"{"referenceId":"owner","configId":"second","key":"secret","createdAt":"2030-01-02T03:04:05.000Z","updatedAt":"2030-01-02T03:04:05.000Z"}"#.into());
    let plugin = ApiKeyPlugin::with_config(config.clone()).configuration(ApiKeyConfig {
        config_id: "second".into(),
        custom_storage: Some(other.clone()),
        ..config.clone()
    });
    for length in [
        json!("0"),
        json!(false),
        json!(""),
        json!("-1"),
        json!("0.5"),
        json!("word"),
        json!([]),
        json!({}),
    ] {
        cache.seed(INDEX, json!({"length":length}).to_string().into());
        cache.reads.lock().unwrap().clear();
        let before = cache.values.lock().unwrap().clone();
        let values = list(&config, &ctx, "owner", None).await.unwrap();
        assert_eq!(values, vec![FieldValue::from_json(length).unwrap()]);
        assert_eq!(*cache.reads.lock().unwrap(), vec![FieldValue::from(INDEX)]);
        let response = handlers::list_keys_core("owner", &ListKeysQuery::default(), &plugin, &ctx)
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            json!({"apiKeys":[],"total":0})
        );
        assert_eq!(*cache.values.lock().unwrap(), before);
        assert!(cache.writes.lock().unwrap().is_empty());
        assert!(other.writes.lock().unwrap().is_empty());
    }
    for source in ["{}", r#"{"length":null}"#, r#"{"length":0}"#] {
        cache.seed(INDEX, source.into());
        let response = handlers::list_keys_core("owner", &ListKeysQuery::default(), &plugin, &ctx)
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            json!({"apiKeys":[{
            "referenceId":"owner","configId":"second","createdAt":"2030-01-02T03:04:05.000Z",
            "updatedAt":"2030-01-02T03:04:05.000Z","expiresAt":null,"lastRefillAt":null,"lastRequest":null,
            "metadata":null,"permissions":null
        }],"total":1})
        );
    }
}

#[tokio::test]
async fn raw_length_objects_reach_complete_responses_without_cache_date_revival() {
    let cache = Arc::new(Cache::default());
    let (config, ctx) = context(cache.clone(), false);
    let plugin = ApiKeyPlugin::with_config(config);
    let raw: FieldValue = Utf16String::from_units(
        r#"{"length":{"id":"raw-id","referenceId":"owner","configId":"default","key":"hidden","name":""#
            .encode_utf16()
            .chain([0xd800])
            .chain(r#"","createdAt":"raw-date","updatedAt":null,"expiresAt":"still-raw","lastRefillAt":0,"metadata":{"native":true},"permissions":"{\"resource\":[\"read\"]}","extra":[1,{"nested":true}]}}"#.encode_utf16())
            .collect(),
    ).into();
    cache.seed(INDEX, raw);
    let before = cache.values.lock().unwrap().clone();
    let response = handlers::list_keys_core("owner", &ListKeysQuery::default(), &plugin, &ctx)
        .await
        .unwrap();
    let key = response.api_keys.first().unwrap();
    assert_eq!(
        key.name.field_value(),
        Utf16String::from_units(vec![0xd800]).into()
    );
    assert_eq!(key.created_at.field_value(), FieldValue::from("raw-date"));
    assert!(key.last_request.is_undefined());
    assert_eq!(
        key.field_values()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "id",
            "referenceId",
            "configId",
            "name",
            "createdAt",
            "updatedAt",
            "expiresAt",
            "lastRefillAt",
            "metadata",
            "permissions",
            "extra"
        ]
    );
    assert_eq!(
        serde_json::to_string(&response).unwrap(),
        r#"{"apiKeys":[{"id":"raw-id","referenceId":"owner","configId":"default","name":"\ud800","createdAt":"raw-date","updatedAt":null,"expiresAt":"still-raw","lastRefillAt":0,"metadata":{"native":true},"permissions":{"resource":["read"]},"extra":[1,{"nested":true}]}],"total":1}"#
    );
    assert_eq!(*cache.reads.lock().unwrap(), vec![FieldValue::from(INDEX)]);
    assert_eq!(*cache.values.lock().unwrap(), before);
    assert!(cache.writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn explicit_configuration_preserves_duplicate_cache_rows_and_paginates_after_filtering() {
    let cache = Arc::new(Cache::default());
    let (config, ctx) = context(cache.clone(), false);
    let plugin = ApiKeyPlugin::with_config(config);
    let key = record("duplicate".into());
    put(cache.as_ref(), &key, false).await.unwrap();
    cache.seed(INDEX, r#"["duplicate","duplicate","duplicate"]"#.into());
    let before = cache.values.lock().unwrap().clone();
    for config_id in [None, Some("default".into())] {
        let scoped = config_id.is_some();
        let response = handlers::list_keys_core(
            "owner",
            &ListKeysQuery {
                config_id,
                limit: Some(1),
                offset: Some(1),
                ..Default::default()
            },
            &plugin,
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            if scoped {
                json!({"apiKeys":[{
            "id":"duplicate","referenceId":"owner","createdAt":"2026-10-01T00:00:00.000Z",
            "updatedAt":"2026-10-01T00:00:00.000Z","expiresAt":null,"lastRefillAt":null,"lastRequest":null,
            "metadata":null,"permissions":null
        }],"total":3,"limit":1,"offset":1})
            } else {
                json!({"apiKeys":[],"total":1,"limit":1,"offset":1})
            }
        );
        assert_eq!(*cache.values.lock().unwrap(), before);
        assert!(cache.writes.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn array_constructor_errors_and_fallback_branch_follow_native_length_guards() {
    let cache = Arc::new(Cache::default());
    for fallback in [false, true] {
        let (config, ctx) = context(cache.clone(), fallback);
        for source in [
            r#"{"length":1.5}"#,
            r#"{"length":1e999}"#,
            r#"{"length":4294967296}"#,
        ] {
            cache.seed(INDEX, source.into());
            cache.reads.lock().unwrap().clear();
            let before = cache.values.lock().unwrap().clone();
            let error = list(&config, &ctx, "owner", None).await.unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("Array length must be a positive integer of safe magnitude.")
            );
            assert_eq!(*cache.reads.lock().unwrap(), vec![FieldValue::from(INDEX)]);
            assert_eq!(*cache.values.lock().unwrap(), before);
            assert!(cache.writes.lock().unwrap().is_empty());
        }
        for (source, retained) in [(r#"{"length":"0"}"#, "0"), (r#"{"length":"0.5"}"#, "0.5")] {
            cache.seed(INDEX, source.into());
            let values = list(&config, &ctx, "owner", None).await.unwrap();
            assert_eq!(
                values,
                if fallback && retained == "0" {
                    vec![]
                } else {
                    vec![FieldValue::from(retained)]
                }
            );
            assert_eq!(cache.value(INDEX), Some(source.into()));
            assert!(cache.writes.lock().unwrap().is_empty());
        }
        cache.seed(INDEX, r#"{"length":-1}"#.into());
        let result = list(&config, &ctx, "owner", None).await;
        if fallback {
            assert!(result.unwrap().is_empty());
        } else {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Array length must be a positive integer of safe magnitude.")
            );
        }
    }
}
