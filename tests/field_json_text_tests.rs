#![cfg(feature = "seaorm2")]

#[path = "support/field_json_text.rs"]
mod fixture;

use better_auth::__private_core::__private_async_trait::async_trait;
use better_auth::{
    __private_core::{
        AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
        AuthSchema, AuthStore, CreateJwk,
        store::{EphemeralStore, schema::EntityRole},
        user_fields::{
            FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
        },
    },
    AuthConfig, BetterAuth,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const ORACLE: &str = r#"{"4294967295":"last-index","01":"leading-zero","4294967294":1e21,"0":-0.0,"numbers":[0.0,-0.0,1e-7,1e-6,1e20,1e21],"nested":{"2":2.0,"1":1.0,"01":1.0}}"#;
type Trace = Arc<Mutex<Vec<Value>>>;

struct Fields(UserConfig);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "ordinary-field-json-text"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(EntityRole::Jwk, self.0.clone())
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn config() -> AuthConfig {
    AuthConfig::new("ordinary-field-json-text-secret-at-least-32-characters")
        .base_url("http://field-json-text.test")
}

#[expect(
    clippy::expect_used,
    reason = "The contract must stop if a callback receives absent or non-text JSON storage"
)]
fn field(events: Option<Trace>) -> UserFieldConfig {
    let mut field = UserFieldConfig {
        field_type: UserFieldType::Json,
        field_name: Some("stored_settings".into()),
        required: Some(false),
        ..Default::default()
    };
    if let Some(events) = events {
        let input_events = events.clone();
        field.transform = Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                input_events
                    .lock()
                    .expect("JSON field trace lock")
                    .push(json!(["input", "settings"]));
                Ok(value)
            })),
            output: Some(UserFieldTransform::new(move |value| {
                let text = value
                    .as_ref()
                    .and_then(Value::as_str)
                    .expect("JSON output callback receives stored text");
                events
                    .lock()
                    .expect("JSON field trace lock")
                    .push(json!(["output", "settings", text]));
                Ok(value)
            })),
        });
    }
    field
}

fn fields(field: UserFieldConfig) -> UserConfig {
    UserConfig {
        additional_fields: Some([("settings".into(), field)].into_iter().collect()),
    }
}

#[expect(
    clippy::expect_used,
    reason = "The fixed inert fixture timestamp must parse"
)]
fn input(settings: Value) -> CreateJwk {
    CreateJwk {
        public_key: "public".into(),
        private_key: "private".into(),
        created_at: "2030-01-01T00:00:00Z"
            .parse()
            .expect("fixed inert fixture date parses"),
        expires_at: None,
        alg: "EdDSA".into(),
        crv: None,
        additional_fields: [("settings".into(), settings)].into_iter().collect(),
    }
}

#[expect(
    clippy::expect_used,
    reason = "The contract must stop if an ordinary record or captured callback is missing"
)]
async fn observe<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>, backend: &str) -> AuthResult<Value> {
    let mut storage_field = field(None);
    storage_field.field_type = UserFieldType::String;
    let reader = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(Fields(fields(storage_field)))
        .build()
        .await?;
    let events = Trace::default();
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(Fields(fields(field(Some(events.clone())))))
        .build()
        .await?;

    events
        .lock()
        .expect("JSON field trace lock")
        .push(json!(["operation", "create"]));
    let created = auth
        .store()
        .create_jwk(input(serde_json::from_str(ORACLE)?))
        .await?;
    let created_text = events
        .lock()
        .expect("JSON field trace lock")
        .last()
        .and_then(|event| event.get(2))
        .and_then(Value::as_str)
        .expect("create output callback recorded text")
        .to_owned();
    let created_matches_text = created.additional_fields.get("settings")
        == Some(&serde_json::from_str::<Value>(&created_text)?);
    assert!(created_matches_text);

    events
        .lock()
        .expect("JSON field trace lock")
        .push(json!(["operation", "read"]));
    let read = auth
        .store()
        .get_jwk(created.id.typed()?)
        .await?
        .expect("created display row exists");
    let read_text = events
        .lock()
        .expect("JSON field trace lock")
        .last()
        .and_then(|event| event.get(2))
        .and_then(Value::as_str)
        .expect("read output callback recorded text")
        .to_owned();
    let read_matches_text =
        read.additional_fields.get("settings") == Some(&serde_json::from_str::<Value>(&read_text)?);
    assert!(read_matches_text);
    let stored = reader
        .store()
        .get_jwk(created.id.typed()?)
        .await?
        .expect("callback-free reader finds stored display row");
    let stored_text = stored
        .additional_fields
        .get("settings")
        .and_then(Value::as_str)
        .expect("plain-string reader preserves stored JSON text");
    Ok(json!({
        "backend": backend,
        "events": events.lock().expect("JSON field trace lock").clone(),
        "storedText": stored_text,
        "createdMatchesText": created_matches_text,
        "readMatchesText": read_matches_text,
    }))
}

#[expect(
    clippy::expect_used,
    reason = "Captured SQLite text and reconstructed JSON must remain present"
)]
async fn contract() -> Result<(), Box<dyn std::error::Error>> {
    let expected: Value =
        serde_json::from_str(include_str!("fixtures/field-json-text-1.7.6.json"))?;
    let memory = observe(Arc::new(EphemeralStore::new(Arc::new(config()))), "memory").await?;
    let (sqlite, connection) = fixture::sqlite(config()).await?;
    let sqlite = observe(Arc::new(sqlite), "sqlite").await?;
    connection.close().await?;
    assert_eq!(json!({"version":"1.7.6","cases":[memory,sqlite]}), expected);

    // Typed native JSON reconstructs callback text; the driver retains its own raw storage format.
    let sqlite_text = expected
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case.get("backend") == Some(&json!("sqlite")))
        })
        .and_then(|case| case.get("storedText"))
        .and_then(Value::as_str)
        .expect("pinned SQLite storage text exists");
    let events = Trace::default();
    let result = field(Some(events.clone()))
        .adapter_output(Some(serde_json::from_str(ORACLE)?), false)
        .await?;
    assert_eq!(
        *events.lock().expect("JSON field trace lock"),
        [json!(["output", "settings", sqlite_text])],
    );
    assert_eq!(result, Some(serde_json::from_str::<Value>(sqlite_text)?));
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "Setup errors and contract failures must fail this acceptance test"
)]
async fn declared_json_text_matches_pinned_memory_sqlite_and_callback_reconstruction() {
    contract().await.expect("JSON field text contract passes");
}
