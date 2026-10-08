use super::*;
use crate::store::database_hooks::{DatabaseHookContext, DatabaseHookControl, DatabaseHooks};
use crate::store::{
    EphemeralStore, MemoryCacheAdapter, SecondaryStorage, SessionStore, StatelessSchema,
};
use crate::{AuthConfig, FieldMap};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<(&'static str, FieldValue)>>>;

fn record(events: &Events, name: &'static str, key: &FieldValue) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Trace lock poisoned"))?
        .push((name, key.clone()));
    Ok(())
}

struct Storage {
    values: MemoryCacheAdapter,
    events: Events,
}

#[async_trait]
impl SecondaryStorage for Storage {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        self.get_native(&key.into())
            .await?
            .map(|value| value.json())
            .transpose()
            .map(Option::flatten)
    }

    async fn get_native(&self, key: &FieldValue) -> AuthResult<Option<FieldValue>> {
        record(&self.events, "get", key)?;
        self.values.get_native(key).await
    }

    async fn set_native(&self, key: &FieldValue, value: &str, ttl: Option<f64>) -> AuthResult<()> {
        record(&self.events, "set", key)?;
        self.values.set_native(key, value, ttl).await
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.delete_native(&key.into()).await
    }

    async fn delete_native(&self, key: &FieldValue) -> AuthResult<()> {
        record(&self.events, "delete", key)?;
        self.values.delete_native(key).await
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        self.values.get_and_delete(key).await
    }
}

struct Hooks(Events);

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for Hooks {
    async fn before_delete_session(
        &self,
        session: &crate::wire::SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        record(&self.0, "before-delete", &session.token.field_value())?;
        Ok(DatabaseHookControl::Continue)
    }

    async fn after_delete_session(
        &self,
        session: &crate::wire::SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        record(&self.0, "after-delete", &session.token.field_value())
    }
}

#[tokio::test]
async fn deletion_preserves_native_references_and_stops_before_later_mutations_on_failure()
-> AuthResult<()> {
    // Pinned internal-adapter.deleteSession filters before sorting, then mutates the list, token, and database.
    let early = 4_102_444_800_000_i64;
    let late = 4_134_067_200_000_i64;
    for mode in [
        "references",
        "preserve",
        "cache-only",
        "invalid-list",
        "invalid-ttl",
        "missing-owner",
        "missing-session",
    ] {
        let events = Events::default();
        let mut config = AuthConfig::default();
        config.session.store_session_in_database = Some(mode != "cache-only");
        config.session.preserve_session_in_database = Some(mode == "preserve");
        let config = Arc::new(config);
        let inner = Arc::new(
            EphemeralStore::new(config.clone()).with_hooks(vec![Arc::new(Hooks(events.clone()))]),
        );
        let session = inner
            .create_session(crate::types::CreateSession {
                inherited_fields: FieldMap::default(),
                additional_fields: [("token".into(), "7".into())].into(),
                user_id: "owner".into(),
                expires_at: crate::FieldDate::from_milliseconds(late as f64),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        assert_eq!(session.token, "7");
        let cache = Arc::new(Storage {
            values: MemoryCacheAdapter::new(),
            events: events.clone(),
        });
        let cached = match mode {
            "missing-owner" => json!({"session": {}}),
            "missing-session" => json!({"user": {"id": 42}}),
            _ => json!({"session": {"userId": 42}}),
        };
        cache.values.set("7", &cached.to_string(), None).await?;
        let references = match mode {
            "invalid-list" => json!({"token": "7", "expiresAt": late}),
            "invalid-ttl" => json!([{"token": "keep", "expiresAt": late.to_string()}]),
            _ => json!([
                {"token": "last", "expiresAt": "2101-01-01T00:00:00.000Z", "extra": true},
                {"token": "7", "expiresAt": late},
                {"token": 7, "expiresAt": early},
                {"token": "expired", "expiresAt": 1},
                {"token": "missing-expiry"}
            ]),
        };
        cache
            .values
            .set("active-sessions-42", &references.to_string(), None)
            .await?;
        let store = SecondaryStore::new(inner.clone(), cache.clone(), config, Default::default())?;
        let result = store.delete_session("7").await;
        let mut expected = vec![("get", FieldValue::from("7"))];
        if mode != "missing-session" {
            expected.push((
                "get",
                if mode == "missing-owner" {
                    "active-sessions-undefined"
                } else {
                    "active-sessions-42"
                }
                .into(),
            ));
        }
        match mode {
            "invalid-list" => assert_eq!(
                result
                    .err()
                    .map(|error| error.instrumentation_message())
                    .as_deref(),
                Some("list.filter is not a function")
            ),
            "invalid-ttl" => assert_eq!(
                result
                    .err()
                    .map(|error| error.instrumentation_message())
                    .as_deref(),
                Some("expiresAt.getTime is not a function")
            ),
            "missing-session" => result?,
            _ => {
                result?;
                if matches!(mode, "references" | "preserve" | "cache-only") {
                    expected.push(("set", "active-sessions-42".into()));
                    let encoded = cache
                        .values
                        .get_native(&"active-sessions-42".into())
                        .await?
                        .ok_or_else(|| AuthError::internal("Missing retained references"))?;
                    assert_eq!(
                        safe_parse_field(&encoded).json()?,
                        Some(json!([
                            {"token": 7, "expiresAt": early},
                            {"token": "last", "expiresAt": "2101-01-01T00:00:00.000Z", "extra": true}
                        ]))
                    );
                }
                expected.push(("delete", "7".into()));
                if mode != "cache-only" {
                    expected.extend([("before-delete", "7".into()), ("after-delete", "7".into())]);
                }
            }
        }
        assert_eq!(
            *events
                .lock()
                .map_err(|_| AuthError::internal("Trace lock poisoned"))?,
            expected,
            "{mode}"
        );
        let removed = matches!(
            mode,
            "references" | "preserve" | "cache-only" | "missing-owner"
        );
        assert_eq!(
            cache.values.get_native(&"7".into()).await?.is_none(),
            removed,
            "{mode}"
        );
        let stored = inner.get_session("7").await?;
        assert_eq!(
            stored.is_none(),
            matches!(mode, "references" | "missing-owner"),
            "{mode}"
        );
        if mode == "preserve" {
            assert!(
                stored
                    .ok_or(AuthError::SessionNotFound)?
                    .expires_at
                    .date_milliseconds()?
                    <= Utc::now().timestamp_millis() as f64
            );
        } else if mode == "cache-only" {
            assert_eq!(
                stored
                    .ok_or(AuthError::SessionNotFound)?
                    .expires_at
                    .date_milliseconds()?,
                late as f64
            );
        }
    }
    Ok(())
}
