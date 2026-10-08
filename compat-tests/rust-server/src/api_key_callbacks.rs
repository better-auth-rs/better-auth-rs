use axum::{
    Json, Router,
    routing::{get, post},
};
use better_auth::plugins::api_key::{
    ApiKeyConfig, ApiKeyDefaultPermissions, ApiKeyEndpoint, ApiKeyGenerator, ApiKeyGetter,
    ApiKeyPermissions, ApiKeyPlugin, ApiKeyStorage, ApiKeyValidator, ApiKeyVerificationError,
    CreateKeyRequest, RateLimitDefaults, UpdateKeyRequest, VerifyApiKey,
};
use better_auth::{AuthError, BetterAuth};
use better_auth_core::{
    AuthResult,
    store::{CacheAdapter, MemoryCacheAdapter},
};
use serde::Serialize;
use serde_json::value::{RawValue, to_raw_value};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct State {
    events: Vec<Value>,
    control: serde_json::Map<String, Value>,
    counter: usize,
    gets: usize,
}

#[derive(Clone, Default)]
pub(super) struct ApiKeyCallbacks {
    state: Arc<Mutex<State>>,
    config_id: String,
    cache: Arc<MemoryCacheAdapter>,
}

fn fail(state: &State, kind: &str) -> AuthResult<()> {
    match state
        .control
        .get(&format!("{kind}Mode"))
        .and_then(Value::as_str)
    {
        Some("api-error") => Err(AuthError::Upstream {
            status: 403,
            code: "CALLBACK_REJECTED",
            message: "Callback rejected",
        }),
        Some("error") => Err(AuthError::internal("Callback failed")),
        _ => Ok(()),
    }
}

impl ApiKeyCallbacks {
    pub(super) fn apply(&self, profile: &str, original: ApiKeyPlugin) -> ApiKeyPlugin {
        if profile != "api-key-callbacks" {
            return original;
        }
        let config = |id: &str| {
            let callback = Arc::new(Self {
                state: self.state.clone(),
                config_id: id.into(),
                cache: self.cache.clone(),
            });
            ApiKeyConfig {
                config_id: id.into(),
                key_length: 12,
                storage: if id == "callback-cache" {
                    ApiKeyStorage::SecondaryStorage
                } else {
                    ApiKeyStorage::Database
                },
                custom_storage: (id == "callback-cache").then(|| {
                    self.cache.clone() as Arc<dyn better_auth_core::store::SecondaryStorage>
                }),
                store_starting_characters: id != "no-start",
                prefix: Some("generated_".into()),
                enable_metadata: true,
                rate_limit: RateLimitDefaults {
                    enabled: false,
                    ..Default::default()
                },
                enable_session_for_api_keys: id == "callback-session",
                custom_api_key_getter: (id == "callback-session")
                    .then(|| callback.clone() as Arc<dyn ApiKeyGetter>),
                custom_key_generator: Some(callback.clone()),
                custom_api_key_validator: Some(callback.clone()),
                default_permissions_callback: Some(callback),
                ..Default::default()
            }
        };
        ApiKeyPlugin::with_config(config("default"))
            .configuration(config("named"))
            .configuration(config("callback-session"))
            .configuration(config("callback-cache"))
            .configuration(config("no-start"))
    }

    pub(super) async fn reset(&self) {
        self.cache.clear().await.unwrap();
        *self.state.lock().unwrap() = State::default();
    }

    pub(super) fn router(
        &self,
        auth: Arc<BetterAuth<crate::TestSchema>>,
        plugin: ApiKeyPlugin,
    ) -> Router {
        let read = self.clone();
        let update = self.clone();
        Router::new()
            .route(
                "/__test/api-key-callbacks/control",
                get(move || {
                    let fixture = read.clone();
                    async move { Json(json!({"events":fixture.state.lock().unwrap().events})) }
                })
                .post(move |Json(body): Json<Value>| {
                    let fixture = update.clone();
                    async move {
                        let mut state = fixture.state.lock().unwrap();
                        state.control.extend(body.as_object().unwrap().clone());
                        if body.get("clear") != Some(&Value::Bool(false)) {
                            state.events.clear();
                            state.gets = 0;
                        }
                        Json(json!({"events":state.events}))
                    }
                }),
            )
            .route(
                "/__test/api-key-callbacks/call",
                post(move |Json(body): Json<Value>| {
                    let auth = auth.clone();
                    let plugin = plugin.clone();
                    async move {
                        let input = &body["input"];
                        let result = match body["operation"].as_str() {
                            Some("create") => {
                                let input: CreateKeyRequest =
                                    serde_json::from_value(input.clone()).unwrap();
                                plugin
                                    .create_key(auth.context(), &input)
                                    .await
                                    .and_then(|value| to_raw_value(&value).map_err(Into::into))
                            }
                            Some("update") => {
                                let input: UpdateKeyRequest =
                                    serde_json::from_value(input.clone()).unwrap();
                                plugin
                                    .update_key(auth.context(), &input)
                                    .await
                                    .and_then(|value| to_raw_value(&value).map_err(Into::into))
                            }
                            _ => match plugin
                                .verify_api_key(
                                    &VerifyApiKey {
                                        key: input["key"].as_str().unwrap(),
                                        config_id: input.get("configId").and_then(Value::as_str),
                                        permissions: input.get("permissions"),
                                    },
                                    auth.context(),
                                )
                                .await
                            {
                                Ok(key) => to_raw_value(&Verified {
                                    valid: true,
                                    error: None,
                                    key,
                                })
                                .map_err(Into::into),
                                Err(ApiKeyVerificationError::Validation(error)) => {
                                    to_raw_value(&json!({"valid":false,"error":error,"key":null}))
                                        .map_err(Into::into)
                                }
                                Err(ApiKeyVerificationError::Endpoint(error)) => Err(error),
                                Err(
                                    error @ (ApiKeyVerificationError::Internal(_)
                                    | ApiKeyVerificationError::Rejected(_)),
                                ) => error.into_response().and_then(|response| {
                                    serde_json::from_slice(&response.body.bytes()?)
                                        .map_err(Into::into)
                                }),
                            },
                        };
                        Json(match result {
                            Ok(result) => NativeResult::Result { result },
                            Err(AuthError::Internal(message)) => NativeResult::Error { message },
                            Err(error) => {
                                let response = error.to_auth_response();
                                NativeResult::Thrown {
                                    status: response.status,
                                    body: serde_json::from_slice(
                                        &response
                                            .body
                                            .bytes()
                                            .expect("The fixture response must serialize"),
                                    )
                                    .unwrap(),
                                }
                            }
                        })
                    }
                }),
            )
    }
}

#[async_trait::async_trait]
impl ApiKeyGenerator for ApiKeyCallbacks {
    async fn generate(&self, length: usize, prefix: Option<&str>) -> AuthResult<String> {
        tokio::task::yield_now().await;
        let mut state = self.state.lock().unwrap();
        state.events.push(
            json!({"event":"generate","configId":self.config_id,"length":length,"prefix":prefix}),
        );
        fail(&state, "generator")?;
        if let Some(key) = state.control.get("generatedKey").and_then(Value::as_str) {
            return Ok(key.to_owned());
        }
        state.counter += 1;
        Ok(format!(
            "{}custom_{}_{}",
            prefix.unwrap_or_default(),
            state.counter,
            "k".repeat(length)
        ))
    }
}

impl ApiKeyGetter for ApiKeyCallbacks {
    fn get(&self, ctx: ApiKeyEndpoint<'_>) -> AuthResult<Option<String>> {
        let mut state = self.state.lock().unwrap();
        state.gets += 1;
        state
            .events
            .push(json!({"event":"get","path":ctx.path,"hasRequest":ctx.request.is_some()}));
        fail(&state, "getter")?;
        let mode = state.control.get("getterMode").and_then(Value::as_str);
        if mode == Some("second-error") && state.gets % 2 == 0 {
            return Err(AuthError::internal("Callback failed"));
        }
        if mode == Some("second-api-error") && state.gets % 2 == 0 {
            return Err(AuthError::Upstream {
                status: 403,
                code: "CALLBACK_REJECTED",
                message: "Callback rejected",
            });
        }
        if mode == Some("none") || (mode == Some("second-none") && state.gets % 2 == 0) {
            return Ok(None);
        }
        Ok(state
            .control
            .get("nativeKey")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                ctx.request
                    .and_then(|request| request.headers.get("x-callback-key"))
                    .cloned()
            }))
    }
}

#[async_trait::async_trait]
impl ApiKeyValidator for ApiKeyCallbacks {
    async fn validate(&self, key: &str, ctx: ApiKeyEndpoint<'_>) -> AuthResult<bool> {
        tokio::task::yield_now().await;
        let mut state = self.state.lock().unwrap();
        state.events.push(json!({"event":"validate","configId":self.config_id,"key":key,"path":ctx.path,"hasRequest":ctx.request.is_some()}));
        fail(&state, "validator")?;
        Ok(state.control.get("validatorMode").and_then(Value::as_str) != Some("deny"))
    }
}

#[async_trait::async_trait]
impl ApiKeyDefaultPermissions for ApiKeyCallbacks {
    async fn permissions(
        &self,
        reference_id: &better_auth::FieldValue,
        ctx: ApiKeyEndpoint<'_>,
    ) -> AuthResult<ApiKeyPermissions> {
        tokio::task::yield_now().await;
        let mut state = self.state.lock().unwrap();
        state.events.push(
            json!({"event":"permissions","configId":self.config_id,"referenceId":reference_id.json()?,
            "path":ctx.path,"hasRequest":ctx.request.is_some(),"name":ctx.body.get("name"),
            "expiresIn":ctx.body.get("expiresIn"),"remaining":ctx.body.get("remaining")}),
        );
        fail(&state, "permissions")?;
        let action = if ctx.body.get("name").and_then(Value::as_str) == Some("Native") {
            "native"
        } else {
            "read"
        };
        Ok([("nodes".into(), vec![action.into()])].into())
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum NativeResult {
    Result { result: Box<RawValue> },
    Error { message: String },
    Thrown { status: u16, body: Value },
}

#[derive(Serialize)]
struct Verified {
    valid: bool,
    error: Option<()>,
    key: better_auth_core::wire::ApiKeyView,
}
