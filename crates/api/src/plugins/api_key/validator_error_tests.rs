#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
use super::{ApiKeyEndpoint, ApiKeyPlugin, ApiKeyVerificationError, VerifyApiKey};
use crate::plugins::api_key::{ApiKeyConfig, ApiKeyValidator};
use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthResponse, AuthResult, FieldDate, FieldMap, FieldObject,
    FieldValue,
    observability::{LogArgument, LogLevel, LogSink},
    store::{ApiKeyStore, EphemeralStore, schema::EntityRole},
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Copy, Debug)]
enum Failure {
    Ordinary,
    CyclicJson,
    Range,
    DataClone,
    Api(u16),
    StructuralApi,
    BetterCallApi,
}

impl Failure {
    fn error(self) -> AuthResult<AuthError> {
        Ok(match self {
            Self::Ordinary => AuthError::internal("Validator operation failed"),
            Self::CyclicJson => {
                let object = FieldObject::from(FieldMap::new());
                object.set("self", FieldValue::Object(object.clone()))?;
                let result = FieldValue::Object(object.clone()).stringify();
                let _ = object.delete("self")?;
                match result {
                    Err(error @ AuthError::TypeError(_)) => error,
                    other => {
                        return Err(AuthError::internal(format!(
                            "Cyclic JSON must preserve a TypeError, got {other:?}"
                        )));
                    }
                }
            }
            Self::Range => AuthError::RangeError("Invalid array length".into()),
            Self::DataClone => AuthError::DataClone,
            Self::Api(status) => AuthResponse::json(status, &api_error_body())?.into(),
            Self::StructuralApi => AuthError::from_thrown(
                FieldMap::from([
                    ("name".into(), "APIError".into()),
                    ("statusCode".into(), 409.0.into()),
                    ("body".into(), api_error_body().into()),
                ])
                .into(),
            ),
            Self::BetterCallApi => AuthError::try_api_error(better_auth_core::ApiErrorInit {
                status: "CONFLICT".into(),
                body: api_error_body().into(),
                class: better_auth_core::ApiErrorClass::BetterCall,
                ..Default::default()
            })?,
        })
    }

    fn api_status(self) -> Option<u16> {
        match self {
            Self::Api(status) => Some(status),
            Self::StructuralApi | Self::BetterCallApi => Some(409),
            _ => None,
        }
    }
}

fn api_error_body() -> Value {
    json!({
        "code": "VALIDATOR_REJECTED",
        "message": "Validator rejected the key",
        "details": {"retry": false, "reason": ["policy", "owner"]}
    })
}

fn error_pointer(error: &AuthError) -> usize {
    match error {
        AuthError::Internal(message)
        | AuthError::TypeError(message)
        | AuthError::RangeError(message) => message.as_ptr() as usize,
        _ => 0,
    }
}

#[derive(Default)]
struct Trace {
    events: Mutex<Vec<Value>>,
    original: AtomicUsize,
}

impl Trace {
    fn push(&self, event: Value) -> AuthResult<()> {
        self.events
            .lock()
            .map_err(|_| AuthError::internal("Validator trace lock poisoned"))?
            .push(event);
        Ok(())
    }
}

impl LogSink for Trace {
    #[expect(
        clippy::expect_used,
        reason = "The contract requires the original AuthError and an available trace capture."
    )]
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> better_auth_core::AuthResult<()> {
        assert_eq!(level, LogLevel::Error);
        assert_eq!(arguments.len(), 1);
        let error = match arguments.first() {
            Some(LogArgument::Error(error)) => error.downcast_ref::<AuthError>(),
            _ => None,
        }
        .expect("Validator error must retain its original type");
        assert_eq!(error_pointer(error), self.original.load(Ordering::SeqCst));
        self.push(json!(["log", "error", message.to_string(), true]))
            .expect("Validator trace lock is not poisoned");
        Ok(())
    }
}

struct RejectingValidator {
    failure: Failure,
    trace: Arc<Trace>,
}

#[async_trait]
impl ApiKeyValidator for RejectingValidator {
    async fn validate(&self, key: &str, ctx: ApiKeyEndpoint<'_>) -> AuthResult<bool> {
        self.trace
            .push(json!(["validator:enter", key, ctx.body.json()?]))?;
        let updated = ctx
            .api_keys
            .update_api_key_record(
                &"key-id".to_owned().into(),
                [
                    ("name".into(), "After".into()),
                    ("updatedAt".into(), date().into()),
                ]
                .into(),
            )
            .await?;
        assert_eq!(updated, Some(key_fields("After")));
        self.trace.push(json!(["validator:persisted"]))?;
        let error = self.failure.error()?;
        self.trace
            .original
            .store(error_pointer(&error), Ordering::SeqCst);
        Err(error)
    }
}

fn date() -> FieldDate {
    FieldDate::from_milliseconds(1_893_456_000_000.0)
}

fn key_fields(name: &str) -> FieldMap {
    [
        ("id".into(), "key-id".into()),
        ("name".into(), name.into()),
        ("start".into(), FieldValue::Null),
        ("prefix".into(), FieldValue::Null),
        ("key".into(), "validator-secret".into()),
        ("referenceId".into(), "owner".into()),
        ("configId".into(), "default".into()),
        ("refillInterval".into(), FieldValue::Null),
        ("refillAmount".into(), FieldValue::Null),
        ("lastRefillAt".into(), FieldValue::Null),
        ("enabled".into(), true.into()),
        ("rateLimitEnabled".into(), true.into()),
        ("rateLimitTimeWindow".into(), 60_000.into()),
        ("rateLimitMax".into(), 3.into()),
        ("requestCount".into(), 0.into()),
        ("remaining".into(), 5.into()),
        ("lastRequest".into(), FieldValue::Null),
        ("expiresAt".into(), FieldValue::Null),
        ("createdAt".into(), date().into()),
        ("updatedAt".into(), date().into()),
        ("permissions".into(), FieldValue::Null),
        ("metadata".into(), FieldValue::Null),
    ]
    .into()
}

fn stored_key_fields(name: &str) -> FieldMap {
    let mut fields = key_fields(name);
    let _ = fields.insert("metadata".into(), "null".into());
    fields
}

#[tokio::test]
async fn validator_errors_preserve_catch_scope_response_and_committed_callback_write()
-> AuthResult<()> {
    for failure in [
        Failure::Ordinary,
        Failure::CyclicJson,
        Failure::Range,
        Failure::DataClone,
        Failure::Api(403),
        Failure::Api(500),
        Failure::StructuralApi,
        Failure::BetterCallApi,
    ] {
        for scoped in [false, true] {
            let trace = Arc::new(Trace::default());
            let mut config = AuthConfig::default();
            config.logger = better_auth_core::LoggerConfig {
                log: Some(trace.clone()),
                ..Default::default()
            }
            .into();
            let config = Arc::new(config);
            let store = Arc::new(EphemeralStore::new(config.clone()));
            assert_eq!(
                store.create_api_key_record(key_fields("Before")).await?,
                Some(key_fields("Before"))
            );
            assert_eq!(
                store.plugin_storage_rows(EntityRole::ApiKey)?,
                [stored_key_fields("Before")]
            );
            let ctx = AuthContext::new(config, store.clone()).expect("fixture context initializes");
            let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
                disable_key_hashing: true,
                custom_api_key_validator: Some(Arc::new(RejectingValidator {
                    failure,
                    trace: trace.clone(),
                })),
                ..Default::default()
            });
            let error = match plugin
                .verify_api_key(
                    &VerifyApiKey {
                        key: "validator-secret",
                        config_id: scoped.then_some("default"),
                        permissions: None,
                    },
                    &ctx,
                )
                .await
            {
                Err(error) => error,
                Ok(key) => {
                    return Err(AuthError::internal(format!(
                        "Validator must reject {failure:?}, got {key:?}"
                    )));
                }
            };
            trace.push(json!([if scoped {
                "consumer:threw"
            } else {
                "consumer:returned"
            }]))?;
            if scoped {
                let ApiKeyVerificationError::Endpoint(error) = error else {
                    return Err(AuthError::internal(format!(
                        "Scoped validator must escape the catch boundary: {error:?}"
                    )));
                };
                assert_eq!(error_pointer(&error), trace.original.load(Ordering::SeqCst));
                if let Some(status) = failure.api_status() {
                    let response = error.to_auth_response().expect("fixture response succeeds");
                    assert_eq!(
                        response.api_error_status()?,
                        better_auth_core::SchemaValue::Typed(status)
                    );
                    assert_eq!(response.api_error_body()?.json()?, Some(api_error_body()));
                } else {
                    assert!(!error.is_api_error().unwrap());
                }
            } else {
                let is_api = failure.api_status().is_some();
                assert_eq!(
                    matches!(error, ApiKeyVerificationError::Rejected(_)),
                    is_api
                );
                let response = error.into_response()?;
                assert_eq!(response.status, 200);
                assert_eq!(
                    response.body.json()?,
                    Some(json!({
                        "valid": false,
                        "error": if is_api { api_error_body() } else { json!({
                            "code": "INVALID_API_KEY",
                            "message": {"code": "INVALID_API_KEY", "message": "Invalid API key."}
                        }) },
                        "key": null
                    }))
                );
            }
            assert_eq!(
                store.plugin_storage_rows(EntityRole::ApiKey)?,
                [stored_key_fields("After")]
            );
            let body = if scoped {
                json!({"key": "validator-secret", "configId": "default"})
            } else {
                json!({"key": "validator-secret"})
            };
            let mut expected = vec![
                json!(["validator:enter", "validator-secret", body]),
                json!(["validator:persisted"]),
            ];
            if !scoped {
                expected.push(json!(["log", "error", "Failed to validate API key:", true]));
            }
            expected.push(json!([if scoped {
                "consumer:threw"
            } else {
                "consumer:returned"
            }]));
            assert_eq!(
                *trace
                    .events
                    .lock()
                    .map_err(|_| AuthError::internal("Validator trace lock poisoned"))?,
                expected,
                "{failure:?}, scoped={scoped}"
            );
        }
    }
    Ok(())
}
