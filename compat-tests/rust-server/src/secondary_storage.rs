use async_trait::async_trait;
use axum::{Json, Router, routing::post};
use better_auth::__private_core::store::{SecondaryStorage, transaction};
use better_auth::__private_core::types::{CreateSession, CreateVerification};
use better_auth::{AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, Statement};
use better_auth_seaorm::{HookControl, SeaOrmHookContext, SeaOrmHooks};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct CustomHash;
#[async_trait]
impl better_auth::config::VerificationIdentifierHasher for CustomHash {
    async fn hash(&self, identifier: &str) -> AuthResult<String> {
        Ok(format!("custom-{identifier}"))
    }
}

#[derive(Default)]
struct Backend {
    entries: Mutex<BTreeMap<String, Entry>>,
    failure: Mutex<Option<String>>,
}
struct Entry {
    value: String,
    ttl: Option<u64>,
    expires: Option<Instant>,
}
impl Backend {
    fn check(&self, operation: &str) -> AuthResult<()> {
        if self.failure.lock().unwrap().as_deref() == Some(operation) {
            Err(AuthError::internal(format!("secondary {operation} failed")))
        } else {
            Ok(())
        }
    }
}
#[async_trait]
impl SecondaryStorage for Backend {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        self.check("get")?;
        Ok(self
            .entries
            .lock()
            .unwrap()
            .get(key)
            .filter(|entry| entry.expires.is_none_or(|expires| expires > Instant::now()))
            .map(|entry| Value::String(entry.value.clone())))
    }
    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> AuthResult<()> {
        self.check("set")?;
        let _ = self.entries.lock().unwrap().insert(
            key.into(),
            Entry {
                value: value.into(),
                ttl,
                expires: ttl.map(|ttl| Instant::now() + Duration::from_secs(ttl)),
            },
        );
        Ok(())
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.check("delete")?;
        let _ = self.entries.lock().unwrap().remove(key);
        Ok(())
    }
    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        self.check("getAndDelete")?;
        Ok(self
            .entries
            .lock()
            .unwrap()
            .remove(key)
            .filter(|entry| entry.expires.is_none_or(|expires| expires > Instant::now()))
            .map(|entry| Value::String(entry.value)))
    }
}
#[derive(Default)]
struct Events(Mutex<Vec<String>>);
impl Events {
    fn push(&self, event: &str) {
        self.0.lock().unwrap().push(event.into());
    }
}
#[better_auth::database_hooks()]
impl<S: AuthSchema> SeaOrmHooks<S> for Events {
    async fn before_create_session(
        &self,
        _: &mut CreateSession,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        self.push("session.create.before");
        Ok(HookControl::Continue)
    }
    async fn after_create_session(
        &self,
        _: &better_auth_core::wire::SessionView,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.push("session.create.after");
        Ok(())
    }
    async fn before_delete_session(
        &self,
        _: &better_auth_core::wire::SessionView,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        self.push("session.delete.before");
        Ok(HookControl::Continue)
    }
    async fn after_delete_session(
        &self,
        _: &better_auth_core::wire::SessionView,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.push("session.delete.after");
        Ok(())
    }
    async fn before_create_verification(
        &self,
        _: &mut CreateVerification,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        self.push("verification.create.before");
        Ok(HookControl::Continue)
    }
    async fn after_create_verification(
        &self,
        _: &better_auth_core::wire::VerificationView,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.push("verification.create.after");
        Ok(())
    }
    async fn before_delete_verification(
        &self,
        _: &better_auth_core::wire::VerificationView,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<HookControl> {
        self.push("verification.delete.before");
        Ok(HookControl::Continue)
    }
    async fn after_delete_verification(
        &self,
        _: &better_auth_core::wire::VerificationView,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.push("verification.delete.after");
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct SecondaryFixture {
    enabled: bool,
    use_secondary: bool,
    store_verification: bool,
    backend: Arc<Backend>,
    events: Arc<Events>,
    database: DatabaseConnection,
}
impl SecondaryFixture {
    pub(super) fn configure(profile: &str, config: &mut AuthConfig) {
        if !profile.starts_with("secondary-")
            && !profile.starts_with("session-fields")
            && profile != "verification-identifiers"
        {
            return;
        }
        config.session.store_session_in_database =
            Some(profile != "secondary-session-only" && profile != "session-fields-cache");
        config.session.preserve_session_in_database =
            Some(profile == "secondary-session-preserved");
        config.verification.store_in_database = profile != "secondary-verification-only";
        use better_auth::config::{
            VerificationIdentifierConfig, VerificationIdentifierStorage as Strategy,
        };
        config.verification.store_identifier = VerificationIdentifierConfig {
            default: Strategy::Plain,
            overrides: vec![
                ("hash:".into(), Strategy::Hashed),
                ("reset-password:".into(), Strategy::Hashed),
                ("custom:".into(), Strategy::Custom(Arc::new(CustomHash))),
                ("custom:specific:".into(), Strategy::Plain),
            ],
        };
        config
            .session
            .additional_fields
            .insert("deviceLabel".into(), Default::default());
        config.session.additional_fields.insert(
            "internalNote".into(),
            better_auth::config::SessionFieldConfig {
                input: false,
                returned: false,
                ..Default::default()
            },
        );
    }
    pub(super) fn new(profile: &str, database: DatabaseConnection) -> Self {
        Self {
            enabled: profile.starts_with("secondary-")
                || profile.starts_with("session-fields")
                || profile == "verification-identifiers",
            use_secondary: profile != "verification-identifiers" && profile != "session-fields",
            store_verification: profile != "secondary-verification-only",
            backend: Arc::default(),
            events: Arc::default(),
            database,
        }
    }
    pub(super) fn storage(&self) -> Option<Arc<dyn SecondaryStorage>> {
        (self.enabled && self.use_secondary)
            .then(|| self.backend.clone() as Arc<dyn SecondaryStorage>)
    }
    pub(super) fn hooks<S: AuthSchema>(&self) -> Vec<Arc<dyn SeaOrmHooks<S>>> {
        if self.enabled {
            vec![self.events.clone()]
        } else {
            Vec::new()
        }
    }
    pub(super) fn reset(&self) {
        self.backend.entries.lock().unwrap().clear();
        *self.backend.failure.lock().unwrap() = None;
        self.events.0.lock().unwrap().clear();
    }
    pub(super) fn router<S: AuthSchema>(&self, auth: Arc<BetterAuth<S>>) -> Router {
        if !self.enabled {
            return Router::new();
        }
        let fixture = self.clone();
        Router::new().route(
            "/__test/secondary",
            post(move |Json(body): Json<Value>| {
                let fixture = fixture.clone();
                let auth = auth.clone();
                async move {
                    match fixture.control(&auth, body).await {
                        Ok(value) => (axum::http::StatusCode::OK, Json(value)),
                        Err(error) => (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "error": error.to_string() })),
                        ),
                    }
                }
            }),
        )
    }
    async fn control<S: AuthSchema>(&self, auth: &BetterAuth<S>, body: Value) -> AuthResult<Value> {
        let text = |name| body.get(name).and_then(Value::as_str).unwrap_or_default();
        let identifier = text("identifier");
        match text("action") {
            "failure" => {
                *self.backend.failure.lock().unwrap() = body
                    .get("operation")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            }
            "evict" => {
                let _ = self.backend.entries.lock().unwrap().remove(text("key"));
            }
            "put" => self.backend.set(text("key"), text("value"), None).await?,
            "clear-events" => self.events.0.lock().unwrap().clear(),
            "database-user-name" => {
                self.database
                    .execute_raw(Statement::from_sql_and_values(
                        self.database.get_database_backend(),
                        "UPDATE users SET name = ? WHERE id = ?",
                        [text("name").into(), text("userId").into()],
                    ))
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
            }
            "seed-verification" => {
                let now = Utc::now();
                let expires = now
                    + chrono::Duration::seconds(
                        body.get("seconds").and_then(Value::as_i64).unwrap_or(60),
                    );
                let row = json!({ "id": text("id"), "identifier": identifier, "value": text("value"), "expiresAt": expires, "createdAt": now, "updatedAt": now });
                if self.store_verification {
                    let _ = self.database.execute_raw(Statement::from_sql_and_values(self.database.get_database_backend(),
                        "INSERT INTO verifications (id, identifier, value, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                        [text("id").into(), identifier.into(), text("value").into(), expires.into(), now.into(), now.into()]
                    )).await.map_err(|error| AuthError::internal(error.to_string()))?;
                }
                if self.use_secondary {
                    self.backend
                        .set(
                            &format!("verification:{identifier}"),
                            &row.to_string(),
                            None,
                        )
                        .await?;
                }
                return Ok(json!({ "ok": true }));
            }
            "create-verification" => {
                let row = auth
                    .store()
                    .create_verification(CreateVerification {
                        identifier: identifier.into(),
                        value: text("value").into(),
                        expires_at: (Utc::now()
                            + chrono::Duration::seconds(
                                body.get("seconds").and_then(Value::as_i64).unwrap_or(60),
                            ))
                        .into(),
                        ..Default::default()
                    })
                    .await?;
                return Ok(serde_json::to_value(&row)?);
            }
            "find-verification" => {
                return Ok(auth
                    .store()
                    .get_verification_including_expired(identifier)
                    .await?
                    .as_ref()
                    .cloned()
                    .map_or(Value::Null, |row| json!(row)));
            }
            "update-verification" => {
                auth.store()
                    .update_verification_by_identifier(identifier, Some(text("value").into()), None)
                    .await?;
                return Ok(json!({ "ok": true }));
            }
            "delete-verification" => {
                auth.store()
                    .delete_verification_by_identifier(identifier)
                    .await?;
                return Ok(json!({ "ok": true }));
            }
            "consume-verification" => {
                return Ok(auth
                    .store()
                    .consume_verification_by_identifier(identifier)
                    .await?
                    .as_ref()
                    .cloned()
                    .map_or(Value::Null, |row| json!(row)));
            }
            "reserve-verification" => {
                return match auth
                    .store()
                    .reserve_verification_value(CreateVerification {
                        identifier: identifier.into(),
                        value: text("value").into(),
                        expires_at: (Utc::now() + chrono::Duration::seconds(60)).into(),
                        ..Default::default()
                    })
                    .await
                {
                    Ok(reserved) => Ok(json!({ "reserved": reserved })),
                    Err(AuthError::Config(error)) => Ok(json!({ "error": error })),
                    Err(error) => Err(error),
                };
            }
            "transaction-session" => {
                let user_id = text("userId").to_owned();
                let rollback = body
                    .get("rollback")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let result = transaction(auth.store().as_ref(), move |tx| {
                    Box::pin(async move {
                        let _ = tx
                            .create_session_with_deferred_secondary(CreateSession {
                                additional_fields: Default::default(),
                                user_id: user_id.into(),
                                expires_at: Utc::now() + chrono::Duration::days(7),
                                ip_address: None,
                                user_agent: None,
                                impersonated_by: None,
                                active_organization_id: None,
                            })
                            .await?;
                        if rollback {
                            return Err(AuthError::internal("secondary transaction rollback"));
                        }
                        Ok(())
                    })
                })
                .await;
                return Ok(match result {
                    Ok(()) => json!({ "committed": true }),
                    Err(error) => {
                        json!({ "error": match error { AuthError::Internal(error) => error, other => other.to_string() } })
                    }
                });
            }
            "end-session" => {
                auth.store().delete_session(text("token")).await?;
                return Ok(json!({ "ok": true }));
            }
            _ => {}
        }
        let count = |table: &'static str| async move {
            let row = self
                .database
                .query_one_raw(Statement::from_string(
                    self.database.get_database_backend(),
                    format!("SELECT COUNT(*) AS count FROM {table}"),
                ))
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?
                .ok_or_else(|| AuthError::internal("Count query returned no row"))?;
            row.try_get::<i64>("", "count")
                .map_err(|error| AuthError::internal(error.to_string()))
        };
        let rows = self
            .database
            .query_all_raw(Statement::from_string(
                self.database.get_database_backend(),
                "SELECT token, expires_at FROM sessions",
            ))
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let rows: Vec<Value> = rows.into_iter().map(|row| -> AuthResult<Value> { Ok(json!({ "token": row.try_get::<String>("", "token").map_err(|error| AuthError::internal(error.to_string()))?, "live": row.try_get::<DateTime<Utc>>("", "expires_at").map_err(|error| AuthError::internal(error.to_string()))? > Utc::now() })) }).collect::<AuthResult<_>>()?;
        let entries: Vec<_> = self
            .backend
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, entry)| entry.expires.is_none_or(|expires| expires > Instant::now()))
            .map(|(key, entry)| json!({ "key": key, "value": entry.value, "ttl": entry.ttl }))
            .collect();
        Ok(
            json!({ "sessions": count("sessions").await?, "verifications": count("verifications").await?, "rows": rows, "entries": entries, "events": *self.events.0.lock().unwrap() }),
        )
    }
}
