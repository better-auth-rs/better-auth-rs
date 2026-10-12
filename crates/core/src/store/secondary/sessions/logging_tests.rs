#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
use super::*;
use crate::observability::{LogArgument, LogLevel, LogSink};
use crate::store::{
    EphemeralStore, MemoryCacheAdapter, SecondaryStorage, StatelessSchema, UserStore, transaction,
};
use crate::{AuthConfig, AuthContext, FieldDate};
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::sync::Arc;

type Events = Arc<Mutex<Vec<Value>>>;
const DATE: f64 = 1_893_456_000_000.0;
const EXPIRY: f64 = 4_102_444_800_000.0;

struct Logs {
    owner: &'static str,
    events: Events,
    cause: FieldValue,
}

impl LogSink for Logs {
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> crate::AuthResult<()> {
        let arguments: Vec<_> = arguments
            .iter()
            .map(|argument| {
                let original = match argument {
                    LogArgument::Error(error) => error
                        .downcast_ref::<AuthError>()
                        .and_then(AuthError::raw_value)
                        .is_some_and(|value| value.strict_equals(&self.cause)),
                    _ => false,
                };
                json!({"original": original})
            })
            .collect();
        self.events.lock().push(json!([
            "log",
            self.owner,
            level.as_str(),
            message.to_string(),
            arguments
        ]));
        Ok(())
    }
}

struct Storage {
    values: MemoryCacheAdapter,
    mode: &'static str,
    events: Events,
    cause: FieldValue,
}

#[async_trait]
impl SecondaryStorage for Storage {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        self.events.lock().push(json!(["get", key]));
        if self.mode == "mirror-failure" {
            return Err(AuthError::from_thrown(self.cause.clone()));
        }
        self.values.get(key).await
    }

    async fn set_native(
        &self,
        key: &FieldValue,
        value: &FieldValue,
        ttl: Option<f64>,
    ) -> AuthResult<()> {
        self.events
            .lock()
            .push(json!(["set", key.json()?, value.decode::<Value>()?, ttl]));
        self.values.set_native(key, value, ttl).await
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.events.lock().push(json!(["delete", key]));
        if self.mode == "delete-failure" {
            return Err(AuthError::from_thrown(self.cause.clone()));
        }
        self.values.delete(key).await
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        self.values.get_and_delete(key).await
    }
}

fn configuration(owner: &'static str, events: &Events, cause: &FieldValue) -> Arc<AuthConfig> {
    let mut config = AuthConfig::default();
    config.session.store_session_in_database = Some(true);
    config.logger = crate::LoggerConfig {
        disable_colors: Some(true),
        log: Some(Arc::new(Logs {
            owner,
            events: events.clone(),
            cause: cause.clone(),
        })),
        ..Default::default()
    }
    .into();
    config.advanced.database.generate_id = Some(crate::id::IdGeneration::Custom(
        crate::id::IdGenerator::new(|request| Ok(Some(format!("{}-created", request.model)))),
    ));
    config
        .initialize_logger()
        .expect("fixture initialization succeeds");
    Arc::new(config)
}

fn user() -> FieldMap {
    [
        ("id".into(), "owner".into()),
        ("name".into(), "Owner".into()),
        ("email".into(), "owner@scope.test".into()),
        ("emailVerified".into(), true.into()),
        ("image".into(), FieldValue::Null),
        (
            "createdAt".into(),
            FieldDate::from_milliseconds(DATE).into(),
        ),
        (
            "updatedAt".into(),
            FieldDate::from_milliseconds(DATE).into(),
        ),
    ]
    .into()
}

fn session() -> FieldMap {
    [
        ("id".into(), "session".into()),
        ("token".into(), "token".into()),
        ("userId".into(), "owner".into()),
        (
            "expiresAt".into(),
            FieldDate::from_milliseconds(EXPIRY).into(),
        ),
        (
            "createdAt".into(),
            FieldDate::from_milliseconds(DATE).into(),
        ),
        (
            "updatedAt".into(),
            FieldDate::from_milliseconds(DATE).into(),
        ),
        ("ipAddress".into(), "".into()),
        ("userAgent".into(), "".into()),
    ]
    .into()
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract compares complete records, cache effects, log ownership, and original error identity."
)]
async fn secondary_logger_uses_own_instance_inside_another_endpoint() -> AuthResult<()> {
    for (mode, message) in [
        ("missing-session", "Session not found in secondary storage"),
        (
            "missing-list",
            "Active sessions list not found in secondary storage",
        ),
        (
            "mirror-failure",
            "Failed to mirror committed session to secondary storage",
        ),
        (
            "delete-failure",
            "Failed to delete committed user sessions from secondary storage",
        ),
    ] {
        for nested in [false, true] {
            let events = Events::default();
            let cause: FieldValue = FieldMap::from([
                ("name".into(), "Error".into()),
                ("message".into(), "cache failure".into()),
            ])
            .into();
            let before_cause = cause.json()?;
            let config = configuration("B", &events, &cause);
            let inner = Arc::new(EphemeralStore::from_storage(
                config.clone(),
                [
                    ("user".into(), vec![user()]),
                    (
                        "session".into(),
                        if mode == "mirror-failure" {
                            vec![]
                        } else {
                            vec![session()]
                        },
                    ),
                    ("account".into(), vec![]),
                    ("verification".into(), vec![]),
                ],
            )?);
            let storage = Arc::new(Storage {
                values: MemoryCacheAdapter::new(),
                mode,
                events: events.clone(),
                cause: cause.clone(),
            });
            let before_cache: Vec<(&str, String)> = match mode {
                "missing-session" => vec![("token", "{}".into())],
                "missing-list" => {
                    vec![("token", json!({"session": session().json()?}).to_string())]
                }
                "delete-failure" => vec![
                    (
                        "active-sessions-owner",
                        json!([{"token": "token", "expiresAt": EXPIRY}]).to_string(),
                    ),
                    (
                        "token",
                        json!({"session": session().json()?, "user": user().json()?}).to_string(),
                    ),
                ],
                _ => vec![],
            };
            for (key, value) in &before_cache {
                storage.values.set(key, value, None).await?;
            }
            let store = SecondaryStore::<StatelessSchema>::new(
                inner.clone(),
                storage.clone(),
                config,
                Default::default(),
            )?;
            let config_a = configuration("A", &events, &cause);
            let inner_a = Arc::new(EphemeralStore::new(config_a.clone()));
            let context_a =
                AuthContext::new(config_a, inner_a.clone()).expect("fixture context initializes");
            let operation = async {
                let created = if mode == "mirror-failure" {
                    let input = CreateSession {
                        inherited_fields: Default::default(),
                        additional_fields: session(),
                        user_id: "owner".into(),
                        expires_at: FieldDate::from_milliseconds(EXPIRY),
                        ip_address: Some(String::new()),
                        user_agent: Some(String::new()),
                        impersonated_by: None,
                        active_organization_id: None,
                    };
                    Some(
                        transaction(&store, move |tx| {
                            Box::pin(async move {
                                tx.create_session_with_deferred_secondary(input).await
                            })
                        })
                        .await?,
                    )
                } else {
                    if mode == "delete-failure" {
                        transaction(&store, |tx| {
                            Box::pin(async move { tx.delete_user("owner").await })
                        })
                        .await?;
                    } else {
                        store.delete_runtime_session(&"token".into()).await?;
                    }
                    None
                };
                AuthResult::Ok(created)
            };
            let created = if nested {
                context_a.with_endpoint_context(|_| operation).await?
            } else {
                operation.await?
            };
            let log = json!([
                "log",
                "B",
                "error",
                message,
                if mode.ends_with("failure") {
                    vec![json!({"original": true})]
                } else {
                    vec![]
                }
            ]);
            let expected = match mode {
                "missing-session" => vec![json!(["get", "token"]), log],
                "missing-list" => vec![
                    json!(["get", "token"]),
                    json!(["get", "active-sessions-owner"]),
                    log,
                    json!(["delete", "token"]),
                ],
                "mirror-failure" => vec![json!(["get", "active-sessions-owner"]), log],
                _ => vec![
                    json!(["get", "active-sessions-owner"]),
                    json!(["delete", "token"]),
                    log,
                ],
            };
            assert_eq!(*events.lock(), expected, "{mode} nested={nested}");
            assert_eq!(cause.json()?, before_cause);
            assert!(inner_a.get_user_by_id("owner").await?.is_none());
            assert!(inner_a.get_session("token").await?.is_none());
            let stored_user = inner.get_user_by_id("owner").await?.map(FieldMap::from);
            assert_eq!(stored_user, (mode != "delete-failure").then(user));
            let mut expected_session = session();
            if mode == "mirror-failure" {
                let _ = expected_session.insert("id".into(), "session-created".into());
            }
            assert_eq!(
                created.map(FieldMap::from),
                (mode == "mirror-failure").then(|| expected_session.clone())
            );
            assert_eq!(
                inner.get_session("token").await?.map(FieldMap::from),
                matches!(mode, "mirror-failure" | "missing-session").then_some(expected_session)
            );
            for key in ["active-sessions-owner", "token"] {
                let expected = (mode != "missing-list")
                    .then(|| before_cache.iter().find(|(name, _)| *name == key))
                    .flatten()
                    .map(|(_, value)| Value::String(value.clone()));
                assert_eq!(storage.values.get(key).await?, expected, "{mode} {key}");
            }
        }
    }
    Ok(())
}
