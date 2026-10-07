use axum::{
    Json, Router,
    routing::{get, post},
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::plugins::endpoint_context::EndpointContext;
use better_auth::plugins::phone_number::{PhoneNumberCallbacks, PhoneNumberPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_core::endpoint_input::EndpointInputPatch;
use better_auth_core::observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks};
use better_auth_core::store::{AuthTransaction, transaction};
use better_auth_core::{
    AuthContext, AuthRequest, AuthResponse, BeforeRequestAction, CreateVerification, FieldValue,
    HttpMethod, NativeRequest,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct State {
    mode: String,
    events: Vec<Value>,
}
#[derive(Clone, Default)]
struct Trace(Arc<Mutex<State>>);
impl Trace {
    fn mode(&self) -> String {
        self.0.lock().unwrap().mode.clone()
    }
    fn record(&self, phase: &str, request: &AuthRequest) -> AuthResult<()> {
        let ambient = better_auth_core::hooks::current_request_hook_context()
            .and_then(|scope| scope.path)
            .map(Value::String)
            .unwrap_or(json!({"$undefined":true}));
        self.0.lock().unwrap().events.push(json!({
            "phase":phase,"path":request.path(),"ambient":ambient,
            "body":request.input_body()?.unwrap_or(json!({"$undefined":true})),
            "request":request.original_request().and_then(AuthRequest::url).map(|url|url.path()),
            "header":request.header("x-literal"),
        }));
        Ok(())
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema> BeforeEndpointHook<S> for Trace {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.record("before", request)?;
        Ok(match self.mode().as_str() {
            "patch" => Some(BeforeRequestAction::MergeContext(EndpointInputPatch {
                body: Some(json!({"code":"123456","patched":true})),
                ..Default::default()
            })),
            "stop" => Some(BeforeRequestAction::Respond(AuthResponse::json(
                200,
                &json!({"status":false}),
            )?)),
            _ => None,
        })
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema> AfterEndpointHook<S> for Trace {
    async fn after(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.record("after", request)?;
        match self.mode().as_str() {
            "replace" => {
                response.replace_returned(AuthResponse::json(200, &json!({"status":false}))?)
            }
            "after-error" => {
                return Err(AuthResponse::json(
                    400,
                    &json!({"code":"AFTER_ERROR","message":"after rejected"}),
                )?
                .into());
            }
            _ => (),
        }
        Ok(())
    }
}

pub(super) async fn router(profile: &str, base: &str) -> AuthResult<Router> {
    let mut config = AuthConfig::new("phone-native-fixture-secret-longer-than-32");
    config.base_url = base.to_owned().into();
    if profile.ends_with("sqlite") {
        use better_auth_seaorm::store::__private_test_support::{
            bundled_schema::BundledSchema, migrator,
        };
        let db = better_auth_seaorm::Database::connect("sqlite::memory:")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        migrator::run_migrations(&db)
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let store = better_auth_seaorm::SeaOrmStore::<BundledSchema>::new(config.clone(), db);
        build(
            BetterAuth::<BundledSchema>::new(config).store(store),
            profile,
        )
        .await
    } else {
        build(BetterAuth::stateless(config), profile).await
    }
}

async fn build<S: AuthSchema>(builder: AuthBuilder<S>, profile: &str) -> AuthResult<Router> {
    let trace = Trace::default();
    let validator = trace.clone();
    let verified = trace.clone();
    let plugin = PhoneNumberPlugin::new()
        .allowed_attempts(2)
        .phone_number_validator(move |_| {
            validator
                .0
                .lock()
                .unwrap()
                .events
                .push(json!({"phase":"validator"}));
            async { Ok(false) }
        });
    let mut callbacks = PhoneNumberCallbacks::<S>::default().on_verification(move |_, _| {
        verified
            .0
            .lock()
            .unwrap()
            .events
            .push(json!({"phase":"verified"}));
        Box::pin(async { Ok(()) })
    });
    if profile.ends_with("custom") {
        let verify = trace.clone();
        callbacks = callbacks.verify_otp(move |_, ctx| {
            let result = (|| {
                let scope = better_auth_core::hooks::current_request_hook_context().unwrap();
                verify.record("verify", &scope.request)?;
                assert_eq!(ctx.path, Some("virtual:"));
                match verify.mode().as_str() {
                    "custom-error" => Err(AuthError::internal("verifier failed")),
                    "custom-api" => Err(AuthResponse::json(
                        403,
                        &json!({"code":"VERIFIER_ERROR","message":"verifier rejected"}),
                    )?
                    .into()),
                    "custom-false" => Ok(false),
                    _ => Ok(true),
                }
            })();
            Box::pin(async move { result })
        });
    }
    let auth = Arc::new(
        builder
            .hooks(EndpointHooks {
                before: Some(Arc::new(trace.clone())),
                after: Some(Arc::new(trace.clone())),
            })
            .plugin(plugin.callbacks(callbacks))
            .build()
            .await?,
    );
    let app = auth.clone().axum_router().with_state(auth.clone());
    Ok(Router::new()
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/__health", get(|| async { Json(json!({"status":"ok"})) }))
        .route(
            "/__test/reset-state",
            post(|| async { Json(json!({"success":true})) }),
        )
        .route(
            "/__test/phone-native",
            post(move |Json(input): Json<Value>| {
                let auth = auth.clone();
                let trace = trace.clone();
                async move {
                    let result = control(auth, &trace, input).await;
                    Json(result.unwrap_or_else(|error| json!({"fixtureError":error.to_string()})))
                }
            }),
        )
        .merge(app))
}

async fn seed<S: AuthSchema>(
    auth: &BetterAuth<S>,
    input: &Value,
    tx: Option<&dyn AuthTransaction<S>>,
) -> AuthResult<()> {
    let identifier = input["phone"].as_str().unwrap();
    let record = CreateVerification {
        identifier: identifier.into(),
        value: input["value"].as_str().unwrap_or("123456:0").into(),
        expires_at: (Utc::now()
            + Duration::seconds(if input["expired"] == true { -60 } else { 600 }))
        .into(),
        ..Default::default()
    };
    match tx {
        Some(tx) => {
            tx.delete_verification_by_identifier(identifier).await?;
            let _ = tx.create_verification(record).await?;
        }
        None => {
            auth.store()
                .delete_verification_by_identifier(identifier)
                .await?;
            let _ = auth.store().create_verification(record).await?;
        }
    }
    Ok(())
}

async fn invoke<S: AuthSchema>(
    auth: &BetterAuth<S>,
    input: &Value,
    tx: Option<&dyn AuthTransaction<S>>,
) -> AuthResult<bool> {
    let headers: Option<HashMap<String, String>> = input
        .get("headers")
        .cloned()
        .map(serde_json::from_value)
        .transpose()?;
    let request = input["request"].as_bool().filter(|value| *value).map(|_| {
        AuthRequest::new(HttpMethod::Get, "/original").with_url(
            auth.context()
                .base_url()
                .parse::<url::Url>()
                .unwrap()
                .join("/original")
                .unwrap(),
        )
    });
    let mut endpoint = EndpointContext::native(None, None, FieldValue::Null, auth.context());
    endpoint.transaction = tx;
    endpoint
        .phone_number()?
        .with_request(NativeRequest {
            request: request.as_ref(),
            headers: headers.as_ref(),
        })
        .consume(input.get("body").cloned())
        .await
}

async fn control<S: AuthSchema>(
    auth: Arc<BetterAuth<S>>,
    trace: &Trace,
    input: Value,
) -> AuthResult<Value> {
    {
        let mut state = trace.0.lock().unwrap();
        state.mode = input["mode"].as_str().unwrap_or("normal").into();
        state.events.clear();
    }
    if input["action"] == "seed" {
        seed(&auth, &input, None).await?;
        return Ok(json!({"status":true}));
    }
    let result = if input["action"] == "transaction" {
        let store = auth.store().clone();
        let auth = auth.clone();
        let owned_input = input.clone();
        let trace = trace.clone();
        transaction(store.as_ref(), move |tx| {
            Box::pin(async move {
                seed(&auth, &owned_input, Some(tx)).await?;
                let value = invoke(&auth, &owned_input, Some(tx)).await?;
                let remains = tx
                    .get_verification_including_expired(owned_input["phone"].as_str().unwrap())
                    .await?
                    .is_some();
                trace
                    .0
                    .lock()
                    .unwrap()
                    .events
                    .push(json!({"phase":"transaction","remains":remains}));
                if owned_input["rollback"] == true {
                    return Err(AuthError::internal("rollback requested"));
                }
                Ok(value)
            })
        })
        .await
    } else {
        invoke(&auth, &input, None).await
    };
    let result = match result {
        Ok(status) => json!({"result":{"status":status}}),
        Err(error) if error.is_api_error() => {
            let response = error.to_auth_response();
            json!({"error":{"status":response.status,"body":serde_json::from_slice::<Value>(&response.body.bytes()?)?}})
        }
        Err(AuthError::Internal(message)) => json!({"error":{"ordinary":true,"message":message}}),
        Err(error) => return Err(error),
    };
    let stored = auth
        .store()
        .get_verification_including_expired(input["phone"].as_str().unwrap_or_default())
        .await?;
    let (_, users) = auth.store().list_users(Default::default()).await?;
    let mut result = result.as_object().unwrap().clone();
    result.insert(
        "stored".into(),
        stored
            .map(|row| row.value.json())
            .transpose()?
            .flatten()
            .unwrap_or(Value::Null),
    );
    result.insert("events".into(), json!(trace.0.lock().unwrap().events));
    result.insert("users".into(), json!(users));
    Ok(Value::Object(result))
}
