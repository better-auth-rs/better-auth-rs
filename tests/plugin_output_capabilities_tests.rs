#![cfg(feature = "seaorm2")]
#![expect(
    clippy::expect_used,
    reason = "The paired contract must fail on missing fixture records, invalid timestamps, or a poisoned callback trace."
)]

#[path = "support/plugin_output_capabilities_rows.rs"]
mod rows;

#[path = "support/api_key_fields_common.rs"]
mod api_key;
#[path = "support/device_fields.rs"]
mod device;
#[path = "support/jwk_fields.rs"]
mod jwk;
#[path = "support/passkey_fields.rs"]
mod passkey;
#[path = "support/two_factor_fields.rs"]
mod two_factor;
#[path = "support/wallet_fields.rs"]
mod wallet;

use better_auth::{
    __private_core::{
        __private_async_trait::async_trait,
        AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
        AuthRoute, AuthSchema, AuthStore, CreateUser,
        store::{EphemeralStore, schema::EntityRole},
        user_fields::{
            FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
        },
    },
    AuthConfig, BetterAuth,
    plugins::TwoFactorPlugin,
    seaorm::sea_orm::entity::prelude::DateTimeUtc,
};
use rows::{create, read};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicU8, Ordering},
};

const MODEL_NAMES: [&str; 6] = [
    "apikey",
    "passkey",
    "deviceCode",
    "twoFactor",
    "jwks",
    "walletAddress",
];
const OPERATIONS: [&str; 3] = ["create", "read-rewrite", "read-error"];
const DATE: &str = "2030-01-02T03:04:05.123Z";
const EXTRA_DATE: &str = "2029-01-02T03:04:05.000Z";
const ADDRESS: &str = "0x0000000000000000000000000000000000000001";
const ERROR: &str = "ordinary plugin output error";
type Trace = Arc<Mutex<Vec<Value>>>;

fn config() -> AuthConfig {
    let mut config = AuthConfig::new("plugin-output-capabilities-secret-at-least-32-characters")
        .base_url("http://plugin-output-capabilities.test");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config
}

fn push(trace: &Trace, phase: &str, name: &str, value: &Option<Value>) {
    trace.lock().expect("callback trace lock").push(json!([
        phase,
        name,
        value.clone().unwrap_or_else(|| json!({"type":"undefined"}))
    ]));
}

fn take(trace: &Trace) -> Vec<Value> {
    std::mem::take(&mut *trace.lock().expect("callback trace lock"))
}

fn fields(trace: Option<&Trace>, mode: &Arc<AtomicU8>) -> UserConfig {
    let mut fields = UserConfig::default();
    for (name, column, field_type, replacement) in [
        (
            "enabledFlag",
            "stored_enabled_flag",
            UserFieldType::Boolean,
            json!(0),
        ),
        (
            "disabledFlag",
            "stored_disabled_flag",
            UserFieldType::Boolean,
            json!(1),
        ),
        (
            "labels",
            "stored_labels",
            UserFieldType::StringArray,
            json!("[\"changed\",\"third\"]"),
        ),
        (
            "scores",
            "stored_scores",
            UserFieldType::NumberArray,
            json!("[4,5.5]"),
        ),
        (
            "shortDate",
            "stored_short_date",
            UserFieldType::Date,
            json!("2030-02-03"),
        ),
        (
            "invalidDate",
            "stored_invalid_date",
            UserFieldType::Date,
            json!("not-a-date"),
        ),
    ] {
        let transform = trace.map(|trace| {
            let input_trace = trace.clone();
            let output_trace = trace.clone();
            let mode = mode.clone();
            FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    push(&input_trace, "input", name, &value);
                    Ok(value)
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    push(&output_trace, "output", name, &value);
                    let mode = mode.load(Ordering::SeqCst);
                    if mode == 2 && name == "labels" {
                        return Err(AuthError::internal(ERROR));
                    }
                    Ok(if mode == 0 {
                        value
                    } else {
                        Some(replacement.clone())
                    })
                })),
            }
        });
        let _ = fields.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_type,
                field_name: Some(column.into()),
                required: Some(false),
                transform,
                ..Default::default()
            },
        );
    }
    fields
}

struct Fields(EntityRole, UserConfig);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "plugin-output-capabilities"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(self.0, self.1.clone())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn role(model: &str) -> AuthResult<EntityRole> {
    Ok(match model {
        "apikey" => EntityRole::ApiKey,
        "passkey" => EntityRole::Passkey,
        "deviceCode" => EntityRole::DeviceCode,
        "twoFactor" => EntityRole::TwoFactor,
        "jwks" => EntityRole::Jwk,
        "walletAddress" => EntityRole::WalletAddress,
        _ => return Err(AuthError::internal("Unknown plugin output model")),
    })
}

struct Identity {
    model: String,
    owner: String,
    id: String,
    created: OnceLock<String>,
}

impl Identity {
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Contract assertions verify IDs, owners, and timestamps before normalization; Result propagates JSON conversion errors."
    )]
    fn normalize(&self, value: Value) -> AuthResult<Value> {
        // The shared JSON serializer retains JavaScript number formatting for SQL f64 columns.
        let mut value: Value = serde_json::from_str(
            &better_auth::__private_core::utils::json::stringify(&value)?,
        )?;
        let fields = value.as_object_mut().expect("complete plugin row");
        assert_eq!(fields.get("id"), Some(&json!(self.id)));
        let _ = fields.insert("id".into(), json!("<model-id>"));
        let owner_field = if self.model == "apikey" {
            "referenceId"
        } else {
            "userId"
        };
        if self.model != "jwks" {
            assert_eq!(fields.get(owner_field), Some(&json!(self.owner)));
            let _ = fields.insert(owner_field.into(), json!("<owner-id>"));
        }
        if matches!(
            self.model.as_str(),
            "apikey" | "passkey" | "jwks" | "walletAddress"
        ) {
            let created = fields
                .get("createdAt")
                .and_then(Value::as_str)
                .expect("creation timestamp");
            let _ = created
                .parse::<DateTimeUtc>()
                .expect("valid creation timestamp");
            assert_eq!(created, self.created.get_or_init(|| created.to_owned()));
            if matches!(self.model.as_str(), "jwks" | "walletAddress") {
                assert_eq!(created, DATE);
            }
            if self.model == "apikey" {
                assert_eq!(fields.get("updatedAt"), fields.get("createdAt"));
            }
            let _ = fields.insert("createdAt".into(), json!("<created-at>"));
            if self.model == "apikey" {
                let _ = fields.insert("updatedAt".into(), json!("<created-at>"));
            }
        }
        Ok(value)
    }
}

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
    model: &str,
) -> AuthResult<()> {
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/plugin-output-capabilities-1.7.6.json"
        ))
        .map_err(|error| AuthError::internal(error.to_string()))?,
    )?;
    assert_eq!(fixture.get("version").expect("captured version"), "1.7.6");
    let backends = fixture
        .get("backends")
        .expect("captured backends field")
        .as_array()
        .expect("captured backends");
    assert_eq!(
        backends
            .iter()
            .map(|case| case.get("backend").expect("captured backend name").as_str())
            .collect::<Vec<_>>(),
        [Some("memory"), Some("sqlite")]
    );
    let expected = backends
        .iter()
        .find(|case| case.get("backend").expect("captured backend name") == backend)
        .expect("captured backend");
    let models = expected
        .get("models")
        .expect("captured models field")
        .as_array()
        .expect("captured models");
    assert_eq!(
        models
            .iter()
            .map(|case| case.get("model").expect("captured model name").as_str())
            .collect::<Vec<_>>(),
        MODEL_NAMES.map(Some)
    );
    let expected = models
        .iter()
        .find(|case| case.get("model").expect("captured model name") == model)
        .expect("captured model");
    let expected = expected
        .get("observations")
        .expect("captured observations field")
        .as_array()
        .expect("captured observations");
    assert_eq!(
        expected
            .iter()
            .map(|case| case
                .get("name")
                .expect("captured observation name")
                .as_str())
            .collect::<Vec<_>>(),
        OPERATIONS.map(Some)
    );

    let trace = Trace::default();
    let mode = Arc::new(AtomicU8::new(0));
    let reader = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(TwoFactorPlugin::new())
        .plugin(Fields(role(model)?, fields(None, &mode)))
        .build()
        .await?;
    let owner = reader
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Plugin fields owner")
                .with_email("owner@plugin-output-capabilities.test"),
        )
        .await?
        .id
        .typed()?
        .clone();
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(TwoFactorPlugin::new())
        .plugin(Fields(role(model)?, fields(Some(&trace), &mode)))
        .build()
        .await?;
    let created = create(auth.store().as_ref(), model, &owner).await?;
    let id = created
        .get("id")
        .expect("generated model ID field")
        .as_str()
        .expect("generated model ID")
        .to_owned();
    assert!(!id.is_empty());
    let identity = Identity {
        model: model.into(),
        owner,
        id,
        created: OnceLock::new(),
    };
    let mut actual = Vec::new();
    let result = identity.normalize(created)?;
    let events = take(&trace);
    let stored = identity.normalize(
        read(
            reader.store().as_ref(),
            model,
            &identity.owner,
            &identity.id,
        )
        .await?,
    )?;
    let initial = stored.clone();
    actual.push(json!({"name":"create", "events":events, "result":result, "stored":stored}));
    for (phase, operation) in [(1, "read-rewrite"), (2, "read-error")] {
        mode.store(phase, Ordering::SeqCst);
        let result = read(auth.store().as_ref(), model, &identity.owner, &identity.id).await;
        let result = if phase == 2 {
            match result {
                Err(AuthError::Internal(message)) => {
                    assert_eq!(message, ERROR);
                    json!({"sameError":true, "message":message})
                }
                Err(error) => return Err(error),
                Ok(_) => {
                    return Err(AuthError::internal(
                        "Plugin output callback did not reject the read",
                    ));
                }
            }
        } else {
            identity.normalize(result?)?
        };
        let events = take(&trace);
        let stored = identity.normalize(
            read(
                reader.store().as_ref(),
                model,
                &identity.owner,
                &identity.id,
            )
            .await?,
        )?;
        assert_eq!(stored, initial);
        actual.push(json!({"name":operation, "events":events, "result":result, "stored":stored}));
    }
    assert_eq!(&actual, expected, "{backend}/{model}");
    Ok(())
}

#[tokio::test]
async fn memory_plugin_output_capabilities_match_complete_upstream_observations() -> AuthResult<()>
{
    for model in MODEL_NAMES {
        contract(
            Arc::new(EphemeralStore::new(Arc::new(config()))),
            "memory",
            model,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_plugin_output_capabilities_match_complete_upstream_observations()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (store, database) = api_key::sqlite(config()).await;
    contract(Arc::new(store), "sqlite", "apikey").await?;
    database.close().await?;
    let (store, database) = passkey::sqlite(config()).await;
    contract(Arc::new(store), "sqlite", "passkey").await?;
    database.close().await?;
    let (store, database) = device::sqlite(config()).await;
    contract(Arc::new(store), "sqlite", "deviceCode").await?;
    database.close().await?;
    let (store, database) = two_factor::sqlite(config()).await;
    contract(Arc::new(store), "sqlite", "twoFactor").await?;
    database.close().await?;
    let (store, database) = jwk::sqlite(config()).await;
    contract(Arc::new(store), "sqlite", "jwks").await?;
    database.close().await?;
    let (store, database) = wallet::sqlite(config()).await;
    contract(Arc::new(store), "sqlite", "walletAddress").await?;
    database.close().await?;
    Ok(())
}
