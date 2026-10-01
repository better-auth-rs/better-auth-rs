use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{Json, Router, routing::post};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::{
    CreateVerification,
    store::{MemoryCacheAdapter, SecondaryStorage},
    user_fields::{UserFieldConfig, UserFieldType},
    wire::VerificationView,
};
use better_auth_seaorm::{
    SeaOrmHookContext, SeaOrmHooks, SeaOrmStore,
    sea_orm::{Database, EntityTrait, PaginatorTrait},
    store::{__private_test_support::migrator, entities::verification},
};
use serde::Deserialize;
use serde_json::{Value, json};

type Schema = crate::user_fields::Schema;

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Mode {
    Database,
    Cache,
    DatabaseCache,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Kind {
    Number,
    Null,
    Undefined,
    Object,
    InvalidDate,
}

#[derive(Deserialize)]
struct Input {
    mode: Mode,
    kind: Kind,
}

struct Cache {
    inner: MemoryCacheAdapter,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl SecondaryStorage for Cache {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        self.inner.get(key).await
    }
    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> AuthResult<()> {
        self.events.lock().unwrap().push("cache.set");
        self.inner.set(key, value, ttl).await
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.inner.delete(key).await
    }
    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        self.inner.get_and_delete(key).await
    }
}

struct Hooks(Arc<Mutex<Vec<&'static str>>>);

#[better_auth::database_hooks()]
impl SeaOrmHooks<Schema> for Hooks {
    async fn after_create_verification(
        &self,
        _: &VerificationView,
        _: &SeaOrmHookContext<'_, Schema>,
    ) -> AuthResult<()> {
        self.0.lock().unwrap().push("after");
        Ok(())
    }
}

fn database_error(error: better_auth_seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(format!("Verification date fixture database: {error}"))
}

async fn run(input: Input) -> AuthResult<Value> {
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(database_error)?;
    migrator::run_migrations(&database)
        .await
        .map_err(database_error)?;
    let events = Arc::new(Mutex::new(Vec::new()));
    let cache = Arc::new(Cache {
        inner: MemoryCacheAdapter::new(),
        events: events.clone(),
    });
    let uses_database = !matches!(input.mode, Mode::Cache);
    let mut config =
        AuthConfig::new("verification-date-output-fixture-secret-at-least-32-characters");
    config.base_url = "http://localhost:3000".into();
    config.verification.store_in_database = uses_database;
    config.verification.disable_cleanup = Some(true);
    let output_events = events.clone();
    let _ = config.verification.additional_fields.insert(
        "expiresAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            required: Some(true),
            output_transform: Some(Arc::new(move |_| {
                output_events.lock().unwrap().push("output");
                Ok(match input.kind {
                    Kind::Number => Some(json!(4_102_444_800_000_i64)),
                    Kind::Null => Some(Value::Null),
                    Kind::Undefined => None,
                    Kind::Object => Some(json!({"unknown": true})),
                    Kind::InvalidDate => Some(json!("invalid-date")),
                })
            })),
            ..Default::default()
        },
    );
    let store =
        SeaOrmStore::<Schema>::new(config.clone(), database.clone()).hook(Hooks(events.clone()));
    let builder = AuthBuilder::<Schema>::new(config).store(store);
    let builder = if matches!(input.mode, Mode::Database) {
        builder
    } else {
        builder.secondary_storage(cache.clone())
    };
    let auth = builder.build().await?;
    let created = auth
        .store()
        .create_verification(CreateVerification {
            identifier: "date-output".to_owned().into(),
            value: "proof".to_owned().into(),
            expires_at: "2100-01-01T00:00:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap()
                .into(),
            ..Default::default()
        })
        .await;
    let create_error = created.is_err();
    let created_json = match created {
        Ok(created) => serde_json::to_value(created)?,
        // The shared contract checks the committed SQL row and absent cache/after hook.
        // Preserve unrelated fixture failures instead of classifying every error as a type error.
        Err(AuthError::Internal(message)) if message == "expiresAt.getTime is not a function" => {
            Value::Null
        }
        Err(error) => return Err(error),
    };
    let create_events = events.lock().unwrap().clone();
    let rows_before = verification::Entity::find()
        .count(&database)
        .await
        .map_err(database_error)?;
    let cache_before = usize::from(cache.get("verification:date-output").await?.is_some());
    let consume_found = if create_error {
        None
    } else {
        Some(
            auth.store()
                .consume_verification_by_identifier("date-output")
                .await?
                .is_some(),
        )
    };
    let rows_after = verification::Entity::find()
        .count(&database)
        .await
        .map_err(database_error)?;
    Ok(json!({
        "createError": create_error,
        "createdHasExpiry": created_json.get("expiresAt").is_some(),
        "createdExpiry": created_json.get("expiresAt").unwrap_or(&Value::Null),
        "rowsBefore": rows_before, "cacheBefore": cache_before,
        "createEvents": create_events, "consumeFound": consume_found, "rowsAfter": rows_after,
    }))
}

pub fn router() -> Router {
    Router::new().route(
        "/__test/verification-date-output",
        post(|Json(input): Json<Input>| async move { run(input).await.map(Json) }),
    )
}
