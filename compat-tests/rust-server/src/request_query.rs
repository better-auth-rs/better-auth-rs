mod body;
mod oauth;
use body::{BodyBefore, BodyTrace};
use std::{
    any::Any,
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use better_auth::{
    AuthBuilder, AuthConfig, BetterAuth, PasswordHasher,
    integrations::axum::AxumIntegration,
    plugins::{
        AccountManagementPlugin, AdminPlugin, ApiKeyPlugin, DeviceAuthorizationPlugin,
        EmailOtpPlugin, EmailPasswordPlugin, EmailVerificationPlugin, MagicLinkPlugin,
        MultiSessionPlugin, OneTapPlugin, OneTimeTokenPlugin, OrganizationPlugin, PasskeyPlugin,
        PasswordManagementPlugin, PhoneNumberPlugin, SessionManagementPlugin, SiwePlugin,
        TwoFactorPlugin, UserManagementPlugin, UsernamePlugin,
    },
};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, BeforeRequestAction, FieldMap, HttpMethod, hooks::current_request_hook_context,
    middleware::RateLimitConfig, store::StatelessSchema,
};
use serde_json::{Value, json};

type Events = Arc<Mutex<Vec<Value>>>;
#[derive(Clone)]
struct Trace(Events, BodyTrace);

fn snapshot(value: &Option<Value>) -> Value {
    value.clone().unwrap_or_else(|| json!({"$undefined":true}))
}
fn request_url(request: &AuthRequest) -> Option<String> {
    request.url().map(|url| match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    })
}
fn original_url(request: &AuthRequest) -> Option<String> {
    request
        .original_request()
        .map(request_url)
        .unwrap_or_else(|| {
            current_request_hook_context()
                .filter(|context| context.is_http)
                .and_then(|_| request_url(request))
        })
}
impl Trace {
    fn record(&self, phase: &str, req: &AuthRequest) {
        let context = current_request_hook_context().unwrap();
        self.0.lock().unwrap().push(json!({"phase":phase,"path":context.path,"query":snapshot(&context.query),"url":original_url(req)}));
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Trace {
    fn name(&self) -> &'static str {
        "request-query"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/query/raw", "rawQuery"),
            AuthRoute::get("/query/validated", "validatedQuery")
                .query_validator(better_auth_core::query::session_query),
        ]
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.record("before", req);
        self.1.current("plugin.before", None);
        Ok(None)
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if !matches!(req.path(), "/query/raw" | "/query/validated") {
            return Ok(None);
        }
        self.record("endpoint", req);
        Ok(Some(AuthResponse::json(
            200,
            &json!({"query":snapshot(&req.query),"url":original_url(req)}),
        )?))
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.record("after", req);
        self.1.current("after", Some(response));
        Ok(())
    }
}

struct Hasher(BodyTrace);
#[async_trait::async_trait]
impl PasswordHasher for Hasher {
    async fn hash(&self, _: &str) -> AuthResult<String> {
        self.0.current("hash", None);
        Ok("fixture-hash".into())
    }
    async fn verify(&self, _: &str, password: &str) -> AuthResult<bool> {
        self.0.current("verify", None);
        Ok(password == "fixture-password")
    }
}
fn configure<S: AuthSchema>(
    builder: AuthBuilder<S>,
    events: Events,
    body: BodyTrace,
    profile: &str,
) -> AuthBuilder<S> {
    let mut verification = EmailVerificationPlugin::new();
    if profile != "request-change-email-no-sender" {
        verification = verification.custom_send_verification_email(Arc::new(body.clone()));
    }
    if profile == "request-change-email-no-confirmation" {
        verification = verification.verification_token_expiry(chrono::Duration::seconds(90));
    }
    let mut management = UserManagementPlugin::new()
        .delete_user_enabled(true)
        .change_email_enabled(profile != "request-change-email-disabled")
        .update_without_verification(true);
    if profile.starts_with("request-change-email")
        && profile != "request-change-email-no-confirmation"
    {
        management = management.send_change_email_confirmation(Arc::new(body.clone()));
    }
    let builder = builder.plugin(BodyBefore(body.clone()));
    let builder = if profile.starts_with("request-security-") {
        let device_index = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let device_code_index = device_index.clone();
        let device_body = body.clone();
        let siwe_body = body.clone();
        builder
            .plugin(MagicLinkPlugin::new().custom_send_magic_link(Arc::new(body.clone())))
            .plugin(OneTapPlugin::new().client_id(vec!["request-security-client".into()]))
            .plugin(
                DeviceAuthorizationPlugin::new()
                    .generate_device_code_with(move || {
                        let index =
                            device_code_index.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        async move { Ok(format!("request-device-{index}")) }
                    })
                    .generate_user_code_with(move || {
                        let index = device_index.load(std::sync::atomic::Ordering::SeqCst);
                        async move { Ok(format!("REQ2345{index}")) }
                    })
                    .on_device_auth_request(move |_, _| {
                        device_body.current("device.sender", None);
                        async { Ok(()) }
                    }),
            )
            .plugin(
                SiwePlugin::new(
                    "localhost",
                    move || {
                        siwe_body.current("siwe.nonce", None);
                        async { Ok("REQUESTNONCE2345".into()) }
                    },
                    |_| async { Ok(false) },
                )
                .anonymous(false),
            )
    } else {
        builder
    };
    let builder = if profile.starts_with("request-otp-") {
        let sender = body.clone();
        let reset = body.clone();
        builder
            .plugin(EmailOtpPlugin::new().change_email(true).generate_otp(Arc::new(|_, _| Some("123456".into()))).sender(Arc::new(body.clone())))
            .plugin(PhoneNumberPlugin::new()
                .sign_up_on_verification(|phone| format!("{phone}@phone.test"))
                .callbacks::<S>(better_auth::plugins::phone_number::PhoneNumberCallbacks::default()
                .send_otp(move |message, _| {
                    sender.current("phone.otp.sender", None);
                    sender.1.lock().unwrap().push(json!({"kind":"phone-otp","phoneNumber":message.phone_number,"code":message.code}));
                    Ok(Some(Box::pin(async { Ok(()) })))
                })
                .send_password_reset_otp(move |message, _| {
                    reset.current("phone.reset.sender", None);
                    reset.1.lock().unwrap().push(json!({"kind":"phone-reset","phoneNumber":message.phone_number,"code":message.code}));
                    Ok(Some(Box::pin(async { Ok(()) })))
                })))
    } else {
        builder
    };
    let builder = if profile.starts_with("request-two-factor-") {
        let nested = profile
            .contains("nested")
            .then_some(true)
            .or_else(|| profile.contains("passwordless").then_some(false));
        let plugin = TwoFactorPlugin::new().allow_passwordless(profile.contains("passwordless"));
        let plugin = if let Some(allow) = nested {
            plugin.totp_allow_passwordless(allow)
        } else {
            plugin
        };
        builder.plugin(
            plugin
                .backup_code_options(better_auth::plugins::two_factor::BackupCodeOptions {
                    generate: Some(Arc::new(|| {
                        vec!["first-recovery".into(), "second-recovery".into()]
                    })),
                    allow_passwordless: nested,
                    ..Default::default()
                })
                .custom_send_otp(Arc::new(body.clone())),
        )
    } else {
        builder
    };
    let builder = if profile.starts_with("request-plugin-") {
        builder
            .plugin(UsernamePlugin::new(Default::default()))
            .plugin(MultiSessionPlugin::new())
            .plugin(OneTimeTokenPlugin::new())
    } else {
        builder
    };
    let builder =
        if profile.starts_with("request-plugin-") || profile.starts_with("request-change-email") {
            builder.plugin(verification)
        } else {
            builder
        };
    builder
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(Hasher(body.clone()))))
        .plugin(SessionManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .plugin(AdminPlugin::new().default_role("admin".to_owned()))
        .plugin(OrganizationPlugin::with_config(
            better_auth::plugins::OrganizationConfig {
                hooks: Some(Arc::new(body.clone())),
                teams: better_auth::plugins::organization::OrganizationTeamsConfig {
                    enabled: true,
                    ..Default::default()
                },
                dynamic_access_control: true,
                ac: Some(HashMap::from([(
                    "organization".into(),
                    vec!["update".into(), "delete".into()],
                )])),
                ..Default::default()
            },
        ))
        .plugin(ApiKeyPlugin::with_config(
            if profile.starts_with("request-api-key-") {
                better_auth::plugins::api_key::ApiKeyConfig {
                    enable_metadata: true,
                    default_permissions_callback: Some(Arc::new(body.clone())),
                    ..Default::default()
                }
            } else {
                Default::default()
            },
        ))
        .plugin(PasskeyPlugin::new())
        .plugin(PasswordManagementPlugin::new().send_reset_password(Arc::new(body.clone())))
        .plugin(management)
        .plugin(oauth::plugin(profile, body.clone()))
        .plugin(Trace(events, body))
}
fn wire(response: AuthResult<AuthResponse>) -> Response {
    let response = response.unwrap_or_else(|error| error.to_auth_response());
    let mut output = (
        StatusCode::from_u16(response.status).unwrap(),
        response
            .body
            .into_bytes()
            .expect("The fixture response must serialize"),
    )
        .into_response();
    for (name, value) in response.headers.iter() {
        output.headers_mut().append(
            name.parse::<axum::http::HeaderName>().unwrap(),
            value.parse().unwrap(),
        );
    }
    output
}

fn routes<S: AuthSchema>(auth: Arc<BetterAuth<S>>, events: Events, body: BodyTrace) -> Router {
    let email_events = body.1.clone();
    let controls = Router::new()
        .route(
            "/__test/api-key-verify",
            post({
                let auth = auth.clone();
                move |Json(input): Json<Value>| {
                    let auth = auth.clone();
                    async move {
                        let plugin = auth
                            .plugins()
                            .iter()
                            .find_map(|plugin| {
                                (plugin.as_ref() as &dyn Any).downcast_ref::<ApiKeyPlugin>()
                            })
                            .unwrap();
                        let result = plugin
                            .verify_api_key(
                                &better_auth::plugins::api_key::VerifyApiKey {
                                    key: input["key"].as_str().unwrap(),
                                    config_id: input.get("configId").and_then(Value::as_str),
                                    permissions: input.get("permissions"),
                                },
                                auth.context(),
                            )
                            .await;
                        #[derive(serde::Serialize)]
                        struct Verified<T: serde::Serialize> {
                            valid: bool,
                            error: Option<Value>,
                            key: T,
                        }
                        wire(match result {
                            Ok(key) => AuthResponse::json(
                                200,
                                &Verified {
                                    valid: true,
                                    error: None,
                                    key,
                                },
                            )
                            ,
                            Err(error) => error.into_response(),
                        })
                    }
                }
            }),
        )
        .route(
            "/__test/oauth-account",
            post({
                let auth=auth.clone();
                move |Json(input):Json<Value>| {
                    let auth=auth.clone();
                    async move {
                        wire(auth.store().get_account("google",input["accountId"].as_str().unwrap()).await.and_then(|account| {
                            AuthResponse::json(200,&account.map(|account|json!({"accessToken":account.access_token,"refreshToken":account.refresh_token,"idToken":account.id_token,"scope":account.scope,"expiresAt":account.access_token_expires_at})))
                        }))
                    }
                }
            }),
        )
        .route(
            "/__test/device-record",
            post({
                let auth = auth.clone();
                move |Json(input): Json<Value>| {
                    let auth = auth.clone();
                    async move {
                        wire(
                            auth.store()
                                .get_device_code_by_device_code(
                                    input["deviceCode"].as_str().unwrap(),
                                )
                                .await
                                .and_then(|record| {
                                    AuthResponse::json(200, &record)
                                }),
                        )
                    }
                }
            }),
        )
        .route(
            "/__test/email-events",
            get({
                let events = email_events.clone();
                move || {
                    let events = events.clone();
                    async move { Json(json!({"events":events.lock().unwrap().clone()})) }
                }
            })
            .post(move || {
                let events = email_events.clone();
                async move {
                    events.lock().unwrap().clear();
                    Json(json!({"events":[]}))
                }
            }),
        )
        .route(
            "/__test/query-user-verified",
            post({
                let auth = auth.clone();
                move |Json(input): Json<Value>| {
                    let auth = auth.clone();
                    async move {
                        wire(
                            auth.store()
                                .update_user(
                                    input["id"].as_str().unwrap(),
                                    better_auth_core::UpdateUser {
                                        email_verified: Some(
                                            input["emailVerified"].as_bool().unwrap(),
                                        ),
                                        ..Default::default()
                                    },
                                )
                                .await
                                .and_then(|_| {
                                    AuthResponse::json(200, &json!({"success":true}))
                                }),
                        )
                    }
                }
            }),
        )
        .route(
            "/__test/body-events",
            get({
                let body = body.clone();
                move || {
                    let body = body.clone();
                    async move { Json(json!({"events":body.0.lock().unwrap().clone()})) }
                }
            })
            .post(move || {
                let body = body.clone();
                async move {
                    body.0.lock().unwrap().clear();
                    Json(json!({"events":[]}))
                }
            }),
        )
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/__health", get(|| async { Json(json!({"status":"ok"})) }))
        .route(
            "/__test/reset-state",
            post({
                let events = events.clone();
                move || {
                    let events = events.clone();
                    async move {
                        events.lock().unwrap().clear();
                        Json(json!({"success":true}))
                    }
                }
            }),
        )
        .route(
            "/__test/query-events",
            get({
                let events = events.clone();
                move || {
                    let events = events.clone();
                    async move { Json(json!({"events":events.lock().unwrap().clone()})) }
                }
            })
            .post(move || {
                let events = events.clone();
                async move {
                    events.lock().unwrap().clear();
                    Json(json!({"events":[]}))
                }
            }),
        )
        .route(
            "/__test/query-native",
            post({
                let auth = auth.clone();
                move |Json(input): Json<Value>| {
                    let auth = auth.clone();
                    async move {
                        let original = input.get("request").and_then(Value::as_str).map(|url| {
                            let mut request = AuthRequest::new(HttpMethod::Get, "/original")
                                .with_url(url.parse().unwrap());
                            if let Some(body) = input.get("requestBody").and_then(Value::as_str) {
                                request.body = Some(body.as_bytes().to_vec());
                            }
                            request
                        });
                        let headers = input
                            .get("headers")
                            .cloned()
                            .map(serde_json::from_value::<HashMap<String, String>>)
                            .transpose()
                            .unwrap();
                        if matches!(input["path"].as_str(), Some("generateTOTP" | "viewBackupCodes")) {
                            let result = async {
                                let api = auth.two_factor()?.with_request(better_auth_core::NativeRequest { request: original.as_ref(), headers: headers.as_ref() });
                                if input["path"] == "generateTOTP" {
                                    AuthResponse::json(200, &json!({"code":api.generate_totp(input.get("body").cloned()).await?}))
                                } else {
                                    Ok(AuthResponse::native(200, FieldMap::from([
                                        ("status".into(), true.into()),
                                        ("backupCodes".into(), api.view_backup_codes(input.get("body").cloned()).await?),
                                    ]).into()))
                                }
                            }.await;
                            return wire(result);
                        }
                        wire(
                            auth.call_endpoint(
                                if input.get("method").and_then(Value::as_str) == Some("POST") {
                                    HttpMethod::Post
                                } else {
                                    HttpMethod::Get
                                },
                                input["path"].as_str().unwrap(),
                                better_auth::server_api::EndpointInput {
                                    request: original,
                                    headers,
                                    query: input.get("query").cloned(),
                                    body: input.get("body").cloned(),
                                    ..Default::default()
                                },
                            )
                            .await,
                        )
                    }
                }
            }),
        )
        .route(
            "/__test/query-member",
            post({
                let auth = auth.clone();
                move |Json(input): Json<Value>| {
                    let auth = auth.clone();
                    async move {
                        let plugin = auth
                            .plugins()
                            .iter()
                            .find_map(|plugin| {
                                (plugin.as_ref() as &dyn Any).downcast_ref::<OrganizationPlugin>()
                            })
                            .unwrap();
                        let result = plugin
                            .add_member(
                                serde_json::from_value(input).unwrap(),
                                None,
                                auth.context(),
                            )
                            .await;
                        wire(
                            result.and_then(|value| {
                                AuthResponse::json(200, &value)
                            }),
                        )
                    }
                }
            }),
        )
        .route(
            "/__test/query-user",
            post({
                let auth = auth.clone();
                move |Json(input): Json<Value>| {
                    let auth = auth.clone();
                    async move {
                        let result = auth
                            .store()
                            .update_user(
                                input["id"].as_str().unwrap(),
                                better_auth_core::UpdateUser {
                                    name: Some(input["name"].as_str().unwrap().to_owned()).into(),
                                    ..Default::default()
                                },
                            )
                            .await;
                        wire(result.and_then(|_| {
                            AuthResponse::json(200, &json!({"success":true}))
                        }))
                    }
                }
            }),
        );
    auth.clone().axum_router().with_state(auth).merge(controls)
}

pub async fn router(profile: &str, base_url: &str) -> AuthResult<Router> {
    let mut config =
        AuthConfig::new("query-fixture-secret-with-at-least-32-characters").base_url(base_url);
    config.session.cookie_cache = Some(better_auth::config::CookieCacheConfig {
        enabled: Some(true),
        max_age: Some(chrono::Duration::seconds(3600)),
        ..Default::default()
    });
    let events = Arc::new(Mutex::new(Vec::new()));
    let body = BodyTrace::default();
    if profile.ends_with("-sqlite") || profile.starts_with("request-change-email") {
        use better_auth_seaorm::store::__private_test_support::{
            bundled_schema::BundledSchema, migrator::run_migrations,
        };
        let db = better_auth_seaorm::Database::connect("sqlite::memory:")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        run_migrations(&db)
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let store = better_auth_seaorm::SeaOrmStore::<BundledSchema>::new(config.clone(), db);
        let auth = configure(
            BetterAuth::<BundledSchema>::new(config).store(store),
            events.clone(),
            body.clone(),
            profile,
        )
        .build()
        .await?;
        Ok(routes(Arc::new(auth), events, body))
    } else {
        let auth = configure(
            BetterAuth::<StatelessSchema>::stateless(config),
            events.clone(),
            body.clone(),
            profile,
        )
        .build()
        .await?;
        Ok(routes(Arc::new(auth), events, body))
    }
}
