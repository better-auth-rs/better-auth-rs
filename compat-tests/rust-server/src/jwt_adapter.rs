use axum::{
    Json, Router,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth::plugins::{
    EmailPasswordPlugin, JwtAlgorithm, JwtCallOverrides, JwtCallbacks, JwtKeyOptions, JwtPlugin,
    JwtPluginConfig, JwtTokenOptions, SessionManagementPlugin, endpoint_context::EndpointContext,
};
use better_auth::{
    AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth,
    server_api::EndpointInput,
};
use better_auth_core::{
    AuthRequest, AuthResponse, AuthUser, FromFieldMap, HttpMethod, Jwk,
    config::{CookieCacheConfig, CookieCacheStrategy},
    middleware::RateLimitConfig,
    utils::password::PasswordHasher,
};
use better_auth_seaorm::{
    Database, SeaOrmStore,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

type Auth = BetterAuth<BundledSchema>;

pub(super) struct Hasher;
#[async_trait::async_trait]
impl PasswordHasher for Hasher {
    async fn hash(&self, _: &str) -> AuthResult<String> {
        Ok("fixture-hash".into())
    }
    async fn verify(&self, _: &str, _: &str) -> AuthResult<bool> {
        Ok(true)
    }
}

fn context<S: AuthSchema>(
    endpoint: &EndpointContext<'_, S>,
    native_context: bool,
) -> AuthResult<Value> {
    let mut keys = endpoint
        .body
        .as_object()
        .map(|body| body.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    keys.sort();
    let mut value = json!({"path":endpoint.path,"request":endpoint.request.is_some(),"headers":endpoint.headers().is_some(),"bodyKeys":keys,"session":endpoint.session.is_some(),"newSession":endpoint.new_session()?.is_some()});
    if native_context {
        value["baseURL"] = endpoint.auth.base_url().into();
        value["requestURL"] = endpoint
            .request
            .and_then(|request| request.url().map(url::Url::as_str))
            .into();
        value["suppliedHeader"] = endpoint
            .headers()
            .and_then(|headers| headers.get("x-source"))
            .cloned()
            .into();
    }
    Ok(value)
}

pub(super) async fn invoke(
    auth: &Auth,
    base: &str,
    path: &str,
    body: Option<Value>,
    native: bool,
    cookie: Option<String>,
) -> AuthResult<AuthResponse> {
    let method = if body.is_some() {
        HttpMethod::Post
    } else {
        HttpMethod::Get
    };
    if native {
        let mut headers = body.as_ref().map(|_| HashMap::new());
        if let Some(cookie) = cookie {
            headers
                .get_or_insert_default()
                .insert("cookie".into(), cookie);
        }
        return auth
            .call_endpoint(
                method,
                path,
                EndpointInput {
                    headers,
                    body,
                    ..Default::default()
                },
            )
            .await;
    }
    let mut request = AuthRequest::new(method, format!("/api/auth{path}"))
        .with_url(url::Url::parse(&format!("{base}/api/auth{path}")).unwrap());
    if let Some(body) = body {
        request
            .headers
            .insert("content-type".into(), "application/json".into());
        request.body = Some(serde_json::to_vec(&body)?);
    }
    if let Some(cookie) = cookie {
        request.headers.insert("cookie".into(), cookie);
    }
    auth.handle_request(request).await
}

async fn run(base: &str, input: Value) -> AuthResult<Value> {
    let events = Arc::new(Mutex::new(Vec::<Value>::new()));
    let fail_read = Arc::new(AtomicBool::new(input["failure"] == "read"));
    let fail_create = input["failure"] == "create";
    let native_context = input["operation"] == "native-context";
    let mut callbacks = JwtCallbacks::<BundledSchema>::default();
    if input["adapter"] != "create-only" {
        let events = events.clone();
        let fail_read = fail_read.clone();
        let empty = input["empty"] == true;
        callbacks = callbacks.get_jwks(move |endpoint| {
            let events = events.clone();
            let fail_read = fail_read.clone();
            Box::pin(async move {
                events
                    .lock()
                    .unwrap()
                    .push(json!({"event":"get","context":context(endpoint, native_context)?}));
                if fail_read.load(Ordering::SeqCst) {
                    return Err(AuthError::internal("JWT adapter read failed"));
                }
                if empty {
                    return Ok(None);
                }
                let keys = match endpoint.transaction {
                    Some(transaction) => transaction.list_jwks().await?,
                    None => endpoint.auth.database.list_jwks().await?,
                };
                Ok(Some(keys))
            })
        });
    }
    if input["adapter"] != "get-only" {
        let events = events.clone();
        let no_store = input["noStore"] == true;
        callbacks = callbacks.create_jwk(move |data, endpoint| {
            let events = events.clone();
            Box::pin(async move {
                let mut fields = vec!["alg", "createdAt", "privateKey", "publicKey"];
                if data.crv.is_some() { fields.push("crv"); }
                if data.expires_at.is_some() { fields.push("expiresAt"); }
                fields.sort();
                events.lock().unwrap().push(json!({"event":"create","fields":fields,"date":true,"context":context(endpoint, native_context)?}));
                if fail_create { return Err(AuthError::internal("JWT adapter create failed")); }
                if no_store { return Ok(Some(Jwk {id:"unstored-key".into(),public_key:data.public_key.into(),private_key:data.private_key.into(),created_at:data.created_at.into(),expires_at:data.expires_at.into(),alg:Some(data.alg).into(),crv:data.crv.into(),additional_fields:data.additional_fields})); }
                let data = data.into_adapter_fields()?;
                match endpoint.transaction {
                    Some(transaction) => transaction.create_jwk_record(data).await?,
                    None => endpoint.auth.database.create_jwk_record(data).await?,
                }.map(Jwk::from_field_values).transpose()
            })
        });
    }
    let mut config = AuthConfig::new("jwt-adapter-fixture-secret-at-least-thirty-two-characters")
        .base_url(base.to_owned());
    if native_context {
        config.base_url = better_auth_core::BaseUrl::Dynamic(better_auth_core::DynamicBaseUrl {
            allowed_hosts: vec!["*.example".into()],
            fallback: input["fallback"].as_str().map(str::to_owned),
            protocol: None,
        });
    }
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        strategy: Some(CookieCacheStrategy::Jwt),
        ..Default::default()
    });
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let store = SeaOrmStore::<BundledSchema>::new(Arc::new(config.clone()), database);
    let auth = AuthBuilder::new(config)
        .store(store)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(
            JwtPlugin::with_config(JwtPluginConfig {
                session_cookie_cache: input["operation"] == "cookie",
                disable_private_key_encryption: matches!(
                    input["operation"].as_str(),
                    Some("verify-claims" | "override")
                ),
                issuer: (input["operation"] == "override").then(|| "registered-issuer".into()),
                audience: (input["operation"] == "override").then(|| "registered-audience".into()),
                expiration_time: if input["operation"] == "override" {
                    2000000000_i64.into()
                } else {
                    chrono::Duration::minutes(15).into()
                },
                algorithm: Some(if input["operation"] == "override" {
                    JwtAlgorithm::Es256
                } else {
                    JwtAlgorithm::EdDsa
                }),
                rotation_interval: (input["operation"] == "override")
                    .then(|| chrono::Duration::hours(1)),
                ..Default::default()
            })
            .callbacks(callbacks),
        )
        .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(Hasher)))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let output: AuthResult<Value> = async {
        match input["operation"].as_str().unwrap() {
            "discovery" => {
                let response = invoke(&auth, base, "/jwks", None, input["transport"] != "http", None).await?;
                let body: Option<Value> = if response.body.is_empty() {None} else {Some(serde_json::from_slice(&response.body.bytes()?)?)};
                Ok(json!({"status":response.status,"keys":body.and_then(|body|body["keys"].as_array().map(Vec::len))}))
            }
            "sign" => {
                let token = auth.jwt()?.sign(serde_json::from_value(json!({"sub":"fixture-user"}))?).await?;
                Ok(json!({"signed":token.split('.').count()==3}))
            }
            "sign-claims" => {
                let token = auth.jwt()?.sign(serde_json::from_value(input["claims"].clone())?).await?;
                let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap()).unwrap())?;
                Ok(json!({"claims":claims}))
            }
            "native-context" => {
                let request = input["request"].as_str().map(|url| {
                    let mut request = AuthRequest::new(HttpMethod::Get, "/input").with_url(url.parse().unwrap());
                    request.headers.insert("x-source".into(), "request".into());
                    request
                });
                let headers: Option<HashMap<String,String>> = input.get("headers").cloned().map(serde_json::from_value).transpose()?;
                let token = auth.jwt()?.with_request(better_auth_core::NativeRequest {request:request.as_ref(),headers:headers.as_ref()}).sign(serde_json::from_value(json!({"sub":"user","iat":100}))?).await?;
                let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap()).unwrap())?;
                Ok(json!({"claims":claims}))
            }
            "native-token" => {
                let signup = invoke(&auth, base, "/sign-up/email", Some(json!({"name":"JWT headers","email":"jwt-headers@example.com","password":"fixture-password"})), true, None).await?;
                let user: Value = serde_json::from_slice(&signup.body.bytes()?)?;
                let cookie = signup.headers.get_all("set-cookie")
                    .filter(|value| value.starts_with("better-auth.session_token="))
                    .filter_map(|value| value.split(';').next())
                    .collect::<Vec<_>>().join("; ");
                let cases = [
                    ("omitted", None),
                    ("empty", Some(HashMap::new())),
                    ("lowercase", Some(HashMap::from([("cookie".into(), cookie.clone())]))),
                    ("mixed-case", Some(HashMap::from([("Cookie".into(), cookie)]))),
                ];
                let mut results = Vec::new();
                for (name, headers) in cases {
                    let response = match auth.call_endpoint(HttpMethod::Get, "/token", EndpointInput {headers, ..Default::default()}).await {
                        Ok(response) => response,
                        Err(error) => error.to_auth_response(),
                    };
                    let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
                    let body = match body["token"].as_str() {
                        Some(token) => {
                            let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap()).unwrap())?;
                            json!({"token":true,"subjectMatches":claims["sub"] == user["user"]["id"]})
                        }
                        None => body,
                    };
                    results.push(json!({"name":name,"status":response.status,"body":body,"events":std::mem::take(&mut *events.lock().unwrap())}));
                }
                Ok(json!({"signupStatus":signup.status,"results":results}))
            }
            "override" => {
                let options = &input["overrides"];
                let mut overrides = JwtCallOverrides {
                    jwt: options.get("jwt").map(|jwt| JwtTokenOptions { issuer: jwt["issuer"].as_str().map(str::to_owned), ..Default::default() }),
                    jwks: options.get("jwks").map(|_| JwtKeyOptions::default()),
                    adapter: options.get("adapter").map(|_| JwtCallbacks::default()),
                };
                if input["overrideCreate"] == true {
                    let events = events.clone();
                    overrides.adapter = Some(JwtCallbacks::default().create_jwk(move |key, endpoint| {
                        let events = events.clone();
                        Box::pin(async move {
                            events.lock().unwrap().push(json!({"event":"override-create","context":context(endpoint, false)?}));
                            endpoint.auth.database.create_jwk_record(key.into_adapter_fields()?).await?.map(Jwk::from_field_values).transpose()
                        })
                    }));
                }
                let token = auth.jwt()?.sign_with_overrides(serde_json::from_value(json!({"sub":"user","iat":100}))?, overrides).await?;
                let decode = |part: &str| serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap();
                let parts = token.split('.').collect::<Vec<_>>();
                let claims = decode(parts[1]);
                let algorithm = decode(parts[0])["alg"].clone();
                let key = auth.store().list_jwks().await?.remove(0);
                let first_events = std::mem::take(&mut *events.lock().unwrap());
                let next = auth.jwt()?.sign(serde_json::from_value(json!({"sub":"next","iat":100}))?).await;
                let next_failed = next.is_err();
                let next_claims = next.ok().map(|token| decode(token.split('.').nth(1).unwrap()));
                Ok(json!({"claims":claims,"algorithm":algorithm,"encrypted":serde_json::from_str::<Value>(key.private_key.typed()?)?.is_string(),"rotating":key.expires_at.typed()?.is_some(),"firstEvents":first_events,"nextClaims":next_claims,"nextFailed":next_failed}))
            }
            "verify" => {
                let header = input.get("header").cloned().unwrap_or_else(|| json!({"alg":"EdDSA","kid":"missing"}));
                let encoded = input["headerEncoded"].as_str().map(str::to_owned).unwrap_or(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?));
                let token = if input["malformed"] == true {"a.b".into()} else {format!("{encoded}.e30.c2ln")};
                Ok(json!({"payload":auth.jwt()?.verify(&token,None).await?}))
            }
            "verify-claims" => {
                auth.jwt()?.sign(serde_json::from_value(json!({"sub":"seed"}))?).await?;
                let key = auth.store().list_jwks().await?.remove(0);
                let private_key = josekit::jwk::Jwk::from_bytes(key.private_key.typed()?.as_bytes()).unwrap();
                let mut payload = serde_json::Map::from_iter([("iss".into(), base.into()), ("aud".into(), base.into())]);
                payload.extend(input["claims"].as_object().unwrap().clone());
                let mut header = josekit::jws::JwsHeader::new();
                header.set_algorithm("EdDSA");
                header.set_key_id(key.id.typed()?.clone());
                let token = josekit::jws::serialize_compact(&serde_json::to_vec(&payload)?, &header, &josekit::jws::EdDSA.signer_from_jwk(&private_key).unwrap()).unwrap();
                events.lock().unwrap().clear();
                Ok(json!({"accepted":auth.jwt()?.verify(&token, None).await?.is_some()}))
            }
            "cookie" => {
                let response = invoke(&auth, base, "/sign-up/email", Some(json!({"name":"JWT fixture","email":"jwt@example.com","password":"fixture-password"})), input["transport"] != "http", None).await?;
                let mut result = json!({"status":response.status,"cache":response.headers.get_all("set-cookie").any(|cookie|cookie.starts_with("better-auth.session_data="))});
                if input["verifyFailure"] == true && response.status == 200 {
                    fail_read.store(true,Ordering::SeqCst);
                    let cookies = response.headers.get_all("set-cookie").filter(|cookie| cookie.starts_with("better-auth.session_token=") || cookie.starts_with("better-auth.session_data=")).map(|cookie| {
                        let cookie = cookie.split(';').next().unwrap();
                        if let Some(header) = input.get("verifyHeader")
                            && let Some(value) = cookie.strip_prefix("better-auth.session_data=") {
                            let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
                            let mut parts = value.split('.').collect::<Vec<_>>();
                            parts[0] = &header;
                            return format!("better-auth.session_data={}", parts.join("."));
                        }
                        cookie.to_owned()
                    }).collect::<Vec<_>>().join("; ");
                    let user = auth.store().get_user_by_email("jwt@example.com").await?.unwrap();
                    auth.store().delete_user_sessions(user.id().typed().unwrap()).await?;
                    events.lock().unwrap().push(json!({"event":"verify-cookie"}));
                    let response = invoke(&auth,base,"/get-session",None,false,Some(cookies)).await?;
                    result["verifyStatus"] = response.status.into();
                    result["verifiedSession"] = (!serde_json::from_slice::<Value>(&response.body.bytes()?)?.is_null()).into();
                }
                Ok(result)
            }
            _ => unreachable!(),
        }
    }.await;
    let output = match output {
        Ok(output) => output,
        Err(AuthError::Internal(message)) => json!({"thrown":true,"message":message}),
        Err(error @ AuthError::Response(_)) => {
            let body: Value = serde_json::from_slice(&error.to_auth_response().body.bytes()?)?;
            json!({"thrown":true,"message":body["message"]})
        }
        Err(error) => json!({"thrown":true,"message":error.to_string()}),
    };
    let events = events.lock().unwrap().clone();
    Ok(json!({"events":events,"output":output,"rows":auth.store().list_jwks().await?.len()}))
}

pub fn router(base_url: &str) -> Router {
    let session_base = base_url.to_owned();
    let base_url = base_url.to_owned();
    Router::new()
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/__health", get(|| async { Json(json!({"status":"ok"})) }))
        .route(
            "/__test/reset-state",
            post(|| async { Json(json!({"success":true})) }),
        )
        .route(
            "/__test/jwt-session",
            post(move |Json(input): Json<Value>| {
                let base = session_base.clone();
                async move { Json(super::jwt_session::run(&base, input).await.unwrap()) }
            }),
        )
        .route(
            "/__test/jwt-adapter",
            post(move |Json(input): Json<Value>| {
                let base = base_url.clone();
                async move { Json(run(&base, input).await.unwrap()) }
            }),
        )
}
