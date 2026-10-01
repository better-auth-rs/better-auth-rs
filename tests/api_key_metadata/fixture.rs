use async_trait::async_trait;
use better_auth::plugins::{
    EmailPasswordPlugin,
    api_key::{ApiKeyConfig, ApiKeyPlugin, ApiKeyStorage},
};
use better_auth::server_api::{CreateKeyOptions, EndpointInput, VerifyKeyOptions};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::{
    HttpMethod, PasswordHasher,
    background::{BackgroundTask, BackgroundTasks},
    observability::{LogArgument, LogLevel, LogSink},
    store::{MemoryCacheAdapter, SecondaryStorage},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub(super) struct State {
    pub(super) logs: Mutex<Vec<String>>,
    pub(super) tasks: Mutex<Vec<BackgroundTask>>,
}
impl LogSink for State {
    fn log(&self, _: LogLevel, message: LogArgument<'_>, _: &[LogArgument<'_>]) {
        let message = message.to_string();
        if message.starts_with("Failed to migrate double-stringified metadata") {
            self.logs.lock().unwrap().push("migration-warning".into());
        } else if message == "Failed to run background task:" {
            self.logs.lock().unwrap().push(message);
        }
    }
}
struct Hasher;
#[async_trait]
impl PasswordHasher for Hasher {
    async fn hash(&self, _: &str) -> AuthResult<String> {
        Ok("fixture".into())
    }
    async fn verify(&self, _: &str, _: &str) -> AuthResult<bool> {
        Ok(true)
    }
}
pub(super) struct Fixture {
    pub(super) auth: BetterAuth<BundledSchema>,
    pub(super) db: DatabaseConnection,
    pub(super) cache: Arc<MemoryCacheAdapter>,
    pub(super) state: Arc<State>,
    pub(super) cookie: String,
    pub(super) keys: Vec<(String, String)>,
}

pub(super) async fn database_metadata(db: &impl ConnectionTrait) -> Vec<Value> {
    db.query_all_raw(Statement::from_string(
        DbBackend::Sqlite,
        "SELECT metadata FROM api_keys ORDER BY name",
    ))
    .await
    .unwrap()
    .iter()
    .map(|row| serde_json::from_str(&row.try_get::<String>("", "metadata").unwrap()).unwrap())
    .collect()
}

impl Fixture {
    pub(super) async fn new(
        backend: &str,
        scheduling: &'static str,
        db: DatabaseConnection,
    ) -> Self {
        migrator::run_migrations(&db).await.unwrap();
        let state = Arc::new(State::default());
        let cache = Arc::new(MemoryCacheAdapter::new());
        let mut config = AuthConfig::new("api-key-metadata-contract-secret-longer-than-thirty-two")
            .base_url("http://localhost:3000");
        config.session.store_session_in_database = true;
        config.logger.level = LogLevel::Warn;
        config.logger.log = Some(state.clone());
        if scheduling != "default" {
            let state = state.clone();
            config.advanced.background_tasks = Some(BackgroundTasks::new(move |task| {
                state.tasks.lock().unwrap().push(task);
                if scheduling == "handler-throw" {
                    return Err(AuthError::internal("handler-sync"));
                }
                Ok(())
            }));
        }
        let mut key_config = ApiKeyConfig {
            enable_metadata: true,
            storage: if backend == "database" {
                ApiKeyStorage::Database
            } else {
                ApiKeyStorage::SecondaryStorage
            },
            fallback_to_database: backend == "fallback",
            ..Default::default()
        };
        key_config.rate_limit.enabled = false;
        if backend == "mixed-cache" {
            key_config.config_id = "cache".into();
        }
        let mut plugin = ApiKeyPlugin::with_config(key_config);
        if backend == "mixed-cache" {
            plugin = plugin.configuration(ApiKeyConfig {
                config_id: "db".into(),
                enable_metadata: true,
                ..Default::default()
            });
        }
        let auth = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<BundledSchema>::new(config, db.clone()))
            .secondary_storage(cache.clone())
            .rate_limit(better_auth_core::middleware::RateLimitConfig {
                enabled: false,
                ..Default::default()
            })
            .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(Hasher)))
            .plugin(plugin)
            .build()
            .await
            .unwrap();
        let response = auth.call_endpoint(HttpMethod::Post,"/sign-up/email",EndpointInput {
            body: Some(json!({"name":"Owner","email":"owner@example.com","password":"fixture-password"})),
            ..Default::default()
        }).await.unwrap();
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        let owner = body
            .get("user")
            .unwrap()
            .get("id")
            .unwrap()
            .as_str()
            .unwrap();
        let cookie = response
            .headers
            .get_all("set-cookie")
            .map(|value| value.split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        let mut keys = Vec::new();
        for name in ["one", "two"] {
            let key = auth
                .api_keys()
                .unwrap()
                .create(
                    owner,
                    CreateKeyOptions {
                        name: Some(name.into()),
                        metadata: Some(json!({"legacy":name})),
                        config_id: (backend == "mixed-cache").then(|| "cache".into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            let id = key.api_key.id.typed().unwrap().clone();
            let legacy = json!({"legacy":name}).to_string();
            if matches!(backend, "database" | "fallback") {
                let _ = db
                    .execute_raw(Statement::from_sql_and_values(
                        DbBackend::Sqlite,
                        "UPDATE api_keys SET metadata=? WHERE id=?",
                        [json!(legacy).to_string().into(), id.clone().into()],
                    ))
                    .await
                    .unwrap();
            }
            let cache_key = format!("api-key:by-id:{id}");
            if let Some(Value::String(text)) = cache.get(&cache_key).await.unwrap() {
                let mut value: Value = serde_json::from_str(&text).unwrap();
                *value.get_mut("metadata").unwrap() = json!(legacy);
                cache
                    .set(&cache_key, &value.to_string(), None)
                    .await
                    .unwrap();
                cache
                    .set(
                        &format!("api-key:{}", value.get("key").unwrap().as_str().unwrap()),
                        &value.to_string(),
                        None,
                    )
                    .await
                    .unwrap();
            }
            keys.push((id, key.key));
        }
        Self {
            auth,
            db,
            cache,
            state,
            cookie,
            keys,
        }
    }
    pub(super) async fn snapshot(&self) -> Value {
        let database = database_metadata(&self.db).await;
        let mut cache = Vec::new();
        for (id, _) in &self.keys {
            let value = self
                .cache
                .get(&format!("api-key:by-id:{id}"))
                .await
                .unwrap();
            cache.push(match value {
                Some(Value::String(text)) => serde_json::from_str::<Value>(&text)
                    .unwrap()
                    .get("metadata")
                    .unwrap()
                    .clone(),
                _ => Value::Null,
            });
        }
        json!({"database":database,"cache":cache})
    }
    pub(super) async fn operation(&self, endpoint: &str) -> Vec<Value> {
        let (id, key) = self.keys.first().unwrap();
        if endpoint == "verify" {
            let key = self
                .auth
                .api_keys()
                .unwrap()
                .verify(key, VerifyKeyOptions::default())
                .await
                .unwrap();
            return vec![key.metadata.unwrap_or(Value::Null)];
        }
        let (method, path, body, query) = match endpoint {
            "get" => (
                HttpMethod::Get,
                "/api-key/get",
                None,
                Some(json!({"id":id})),
            ),
            "list" => (HttpMethod::Get, "/api-key/list", None, Default::default()),
            _ => {
                assert_eq!(endpoint, "update", "invalid contract endpoint");
                (
                    HttpMethod::Post,
                    "/api-key/update",
                    Some(json!({"keyId":id,"name":"one"})),
                    None,
                )
            }
        };
        let response = self
            .auth
            .call_endpoint(
                method,
                path,
                EndpointInput {
                    body,
                    query,
                    headers: Some([("cookie".into(), self.cookie.clone())].into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        if endpoint == "list" {
            value
                .get("apiKeys")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|key| key.get("metadata").unwrap().clone())
                .collect()
        } else {
            vec![value.get("metadata").unwrap().clone()]
        }
    }
    pub(super) async fn finish(&self) -> Vec<&'static str> {
        let tasks = std::mem::take(&mut *self.state.tasks.lock().unwrap());
        let mut states = Vec::new();
        for task in tasks {
            task.await.unwrap();
            states.push("fulfilled");
        }
        states
    }
}
