use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    routing::{get, post},
};
use better_auth::{AuthConfig, BetterAuth, server_api::EndpointInput};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, BaseUrl, BaseUrlProtocol, BeforeRequestAction, DynamicBaseUrl, HttpMethod,
    TrustedValues, TrustedValuesResolver, middleware::RateLimitConfig, store::StatelessSchema,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Call {
    id: String,
    transport: String,
    method: Option<String>,
    url: Option<String>,
    request_headers: Option<HashMap<String, String>>,
    headers: Option<HashMap<String, String>>,
    native_request: Option<bool>,
    raw_body: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OriginSource {
    id: String,
    values: Vec<String>,
    dynamic: bool,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Input {
    #[serde(rename = "baseURL")]
    base_url: Option<Value>,
    base_path: Option<String>,
    proxy: Option<bool>,
    cross_subdomain: Option<bool>,
    default_cookie_domain: Option<String>,
    session_cookie_domain: Option<String>,
    origins: Option<Vec<String>>,
    providers: Option<Vec<String>>,
    plugin_origins: Option<Vec<OriginSource>>,
    parallel: Option<bool>,
    calls: Vec<Call>,
}

#[derive(Clone)]
struct Fixture {
    events: Arc<Mutex<Vec<Value>>>,
    barriers: Arc<Mutex<HashMap<String, Arc<tokio::sync::Barrier>>>>,
    concurrent: usize,
}

fn header<'a>(request: &'a AuthRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
}
fn request_value(request: Option<&AuthRequest>) -> Value {
    request.map_or(Value::Null, |request| json!({
        "id":header(request,"x-probe-id"), "url":request.url().map(url::Url::as_str), "method":format!("{:?}",request.method).to_uppercase(),
        "host":header(request,"host"), "forwardedHost":header(request,"x-forwarded-host"), "forwardedProto":header(request,"x-forwarded-proto"),"tenant":header(request,"x-tenant")
    }))
}
fn original(request: &AuthRequest) -> Option<&AuthRequest> {
    request.original_request().or_else(|| {
        better_auth_core::hooks::current_request_hook_context()
            .is_some_and(|context| context.is_http)
            .then_some(request)
    })
}
fn context_value(context: &AuthContext<StatelessSchema>) -> Value {
    let cookie = context
        .create_auth_cookie("session_token", Default::default())
        .unwrap();
    let option_url = match &context.config.base_url {
        BaseUrl::Static(value) => json!(value),
        BaseUrl::Dynamic(policy) => {
            let mut value = json!({"allowedHosts":policy.allowed_hosts});
            if let Some(fallback) = &policy.fallback {
                value["fallback"] = json!(fallback);
            }
            if let Some(protocol) = policy.protocol {
                value["protocol"] = json!(match protocol {
                    BaseUrlProtocol::Http => "http",
                    BaseUrlProtocol::Https => "https",
                    BaseUrlProtocol::Auto => "auto",
                });
            }
            value
        }
        BaseUrl::Auto => Value::Null,
    };
    json!({"baseURL":context.base_url(),"optionURL":option_url,"origins":context.trusted_origins(),"providers":context.trusted_providers(),"cookie":{"name":cookie.name,"secure":cookie.attributes.secure,"domain":cookie.attributes.domain}})
}
fn error_value(error: AuthError) -> Value {
    if error.is_api_error() {
        let response = error.to_auth_response();
        json!({"thrown":true,"kind":"APIError","status":response.status,"body":serde_json::from_slice::<Value>(&response.body.bytes().expect("The fixture response must serialize")).unwrap_or(Value::Null)})
    } else {
        let (kind, message) = match error {
            AuthError::Config(message) => ("BetterAuthError", message),
            AuthError::Internal(message) => ("Error", message),
            other => ("Error", other.to_string()),
        };
        json!({"thrown":true,"kind":kind,"message":message})
    }
}
impl Fixture {
    fn record(&self, stage: &str, request: Option<&AuthRequest>, base_url: Option<&str>) {
        let mut value = json!({"stage":stage,"request":request_value(request)});
        if let Some(url) = base_url {
            value["baseURL"] = url.into();
        }
        self.events.lock().unwrap().push(value);
    }
    async fn rendezvous(&self, stage: &str, request: Option<&AuthRequest>) {
        if self.concurrent == 0 || request.is_none() {
            return;
        }
        let barrier = self
            .barriers
            .lock()
            .unwrap()
            .entry(stage.into())
            .or_insert_with(|| Arc::new(tokio::sync::Barrier::new(self.concurrent)))
            .clone();
        barrier.wait().await;
    }
}
struct Trust {
    fixture: Fixture,
    stage: &'static str,
    source: Option<OriginSource>,
}
#[async_trait::async_trait]
impl TrustedValuesResolver for Trust {
    async fn resolve(&self, request: Option<&AuthRequest>) -> AuthResult<Vec<String>> {
        if let Some(source) = &self.source {
            self.fixture
                .record(&format!("origins:{}", source.id), request, None);
            return Ok(source.values.clone());
        }
        self.fixture.record(self.stage, request, None);
        self.fixture.rendezvous(self.stage, request).await;
        let failure = request.and_then(|request| header(request, "x-fail-trust"));
        if failure == Some(format!("{}-api", self.stage).as_str()) {
            return Err(AuthResponse::json(400,&json!({"code":"TRUST_CALLBACK_REJECTED","message":format!("{} rejected",self.stage)}))?.into());
        }
        if failure == Some(format!("{}-ordinary", self.stage).as_str()) {
            return Err(AuthError::internal(format!("{} failed", self.stage)));
        }
        let tenant = request.and_then(|request| header(request, "x-tenant"));
        Ok(vec![if self.stage == "origins" {
            format!("https://{}.frontend.test", tenant.unwrap_or("initial"))
        } else {
            format!("{}-provider", tenant.unwrap_or("initial"))
        }])
    }
}
struct OriginPlugin {
    fixture: Fixture,
    source: OriginSource,
}
#[async_trait::async_trait]
impl AuthPlugin<StatelessSchema> for OriginPlugin {
    fn name(&self) -> &'static str {
        "origin-source"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![]
    }
    async fn on_init(&self, context: &mut AuthInitContext<StatelessSchema>) -> AuthResult<()> {
        self.fixture
            .record(&format!("init:{}", self.source.id), None, None);
        let source = if self.source.dynamic {
            TrustedValues::Dynamic(Arc::new(Trust {
                fixture: self.fixture.clone(),
                stage: "origins",
                source: Some(self.source.clone()),
            }))
        } else {
            self.source.values.clone().into()
        };
        let config = Arc::make_mut(&mut context.config);
        config.trusted_origins = Some(TrustedValues::merge(vec![
            config.trusted_origins.clone().unwrap_or_default(),
            source,
        ]));
        Ok(())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}
#[async_trait::async_trait]
impl AuthPlugin<StatelessSchema> for Fixture {
    fn name(&self) -> &'static str {
        "dynamic-context-probe"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/context-probe", "dynamicProbe"),
            AuthRoute::post("/context-probe", "dynamicPost"),
        ]
    }
    async fn on_http_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        self.record("onRequest", Some(request), Some(context.base_url()));
        Ok(None)
    }
    async fn before_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.record("before", original(request), Some(context.base_url()));
        Ok(None)
    }
    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if request.path() != "/context-probe" {
            return Ok(None);
        }
        let before = context_value(context);
        self.record("endpoint", original(request), Some(context.base_url()));
        self.rendezvous("endpoint", original(request)).await;
        Ok(Some(AuthResponse::json(
            200,
            &json!({"before":before,"after":context_value(context),"request":request_value(original(request)),"headersTenant":request.endpoint_headers().and_then(|headers|headers.get("x-tenant"))}),
        )?))
    }
    async fn after_request(
        &self,
        request: &AuthRequest,
        _: &mut AuthResponse,
        context: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        self.record("after", original(request), Some(context.base_url()));
        Ok(())
    }
}
async fn invoke(auth: &BetterAuth<StatelessSchema>, fixture: &Fixture, call: &Call) -> Value {
    let event_start = fixture.events.lock().unwrap().len();
    let method = if call.method.as_deref() == Some("POST") {
        HttpMethod::Post
    } else {
        HttpMethod::Get
    };
    let url = url::Url::parse(
        call.url
            .as_deref()
            .unwrap_or("https://a.tenant.test/api/auth/context-probe"),
    )
    .unwrap();
    let mut request = AuthRequest::new(method.clone(), url.path()).with_url(url);
    request.headers = call.request_headers.clone().unwrap_or_default();
    request.headers.insert("x-probe-id".into(), call.id.clone());
    if method == HttpMethod::Post {
        request
            .headers
            .entry("content-type".into())
            .or_insert_with(|| "application/json".into());
        request.body = Some(call.raw_body.as_deref().unwrap_or("{}").as_bytes().to_vec());
    }
    let result = if call.transport == "http" {
        auth.handle_request(request).await
    } else {
        let headers = call.headers.clone().map(|mut headers| {
            headers.insert("x-probe-id".into(), call.id.clone());
            headers
        });
        auth.call_endpoint(
            method.clone(),
            "/context-probe",
            EndpointInput {
                headers,
                request: call.native_request.unwrap_or(false).then_some(request),
                body: (method == HttpMethod::Post).then(|| json!({})),
                ..Default::default()
            },
        )
        .await
    };
    let output = match result {
        Ok(response) => {
            json!({"thrown":false,"status":response.status,"body":if response.body.is_empty(){Value::Null}else{serde_json::from_slice::<Value>(&response.body.bytes().expect("The fixture response must serialize")).unwrap()}})
        }
        Err(error) => error_value(error),
    };
    let events = fixture.events.lock().unwrap();
    let events = if fixture.concurrent > 0 {
        events
            .iter()
            .filter(|event| event["request"]["id"] == call.id)
            .cloned()
            .collect::<Vec<_>>()
    } else {
        events[event_start..].to_vec()
    };
    json!({"id":call.id,"output":output,"events":events})
}
async fn run(input: Input) -> AuthResult<Value> {
    let fixture = Fixture {
        events: Default::default(),
        barriers: Default::default(),
        concurrent: if input.parallel.unwrap_or(false) {
            input.calls.len()
        } else {
            0
        },
    };
    let mut config =
        AuthConfig::new("dynamic-context-fixture-secret-at-least-thirty-two-characters");
    if let Some(value) = &input.base_url {
        config.base_url = if let Some(value) = value.as_str() {
            value.into()
        } else {
            BaseUrl::Dynamic(DynamicBaseUrl {
                allowed_hosts: serde_json::from_value(value["allowedHosts"].clone())?,
                fallback: value["fallback"].as_str().map(str::to_owned),
                protocol: value["protocol"].as_str().map(|protocol| match protocol {
                    "http" => BaseUrlProtocol::Http,
                    "https" => BaseUrlProtocol::Https,
                    _ => BaseUrlProtocol::Auto,
                }),
            })
        };
    }
    if let Some(path) = input.base_path {
        config.base_path = path;
    }
    config.advanced.trusted_proxy_headers = input.proxy.unwrap_or(false);
    config.advanced.cross_sub_domain_cookies =
        input
            .cross_subdomain
            .unwrap_or(false)
            .then_some(better_auth_core::CrossSubDomainConfig {
                enabled: Some(true),
                ..Default::default()
            });
    config.advanced.default_cookie_attributes.domain = input.default_cookie_domain;
    if let Some(domain) = input.session_cookie_domain {
        config.advanced.cookies.get_or_insert_default().insert(
            "session_token".into(),
            better_auth_core::CookieOverride {
                name: None,
                attributes: better_auth_core::CookieAttributes {
                    domain: Some(domain),
                    ..Default::default()
                },
            },
        );
    }
    config.trusted_origins = Some(input.origins.map(TrustedValues::from).unwrap_or_else(|| {
        TrustedValues::Dynamic(Arc::new(Trust {
            fixture: fixture.clone(),
            stage: "origins",
            source: None,
        }))
    }));
    config.account.account_linking.trusted_providers =
        Some(input.providers.map(TrustedValues::from).unwrap_or_else(|| {
            TrustedValues::Dynamic(Arc::new(Trust {
                fixture: fixture.clone(),
                stage: "providers",
                source: None,
            }))
        }));
    let mut builder =
        BetterAuth::stateless(config).rate_limit(RateLimitConfig::new().enabled(false));
    for source in input.plugin_origins.unwrap_or_default() {
        builder = builder.plugin(OriginPlugin {
            fixture: fixture.clone(),
            source,
        });
    }
    let auth = match builder.plugin(fixture.clone()).build().await {
        Ok(auth) => auth,
        Err(error) => {
            return Ok(
                json!({"initializationError":error_value(error),"events":fixture.events.lock().unwrap().clone()}),
            );
        }
    };
    let auth = Arc::new(auth);
    let initialized = context_value(auth.context());
    let init_events = std::mem::take(&mut *fixture.events.lock().unwrap());
    let mut calls = Vec::new();
    if input.parallel.unwrap_or(false) {
        let mut pending = Vec::new();
        for call in &input.calls {
            let auth = auth.clone();
            let fixture = fixture.clone();
            let call = call.clone();
            pending.push(tokio::spawn(
                async move { invoke(&auth, &fixture, &call).await },
            ));
        }
        for call in pending {
            calls.push(call.await.unwrap());
        }
    } else {
        for call in &input.calls {
            calls.push(invoke(&auth, &fixture, call).await);
        }
    }
    Ok(
        json!({"initialized":initialized,"initEvents":init_events,"calls":calls,"final":context_value(auth.context())}),
    )
}
pub fn router() -> Router {
    Router::new()
        .route(
            "/__test/dynamic-cookies",
            post(|| async { crate::dynamic_cookies::run().await.map(Json) }),
        )
        .route(
            "/__test/dynamic-oauth",
            post(|| async { crate::dynamic_oauth::run().await.map(Json) }),
        )
        .route(
            "/__test/dynamic-native",
            post(|Json(input): Json<Value>| async move {
                crate::dynamic_native::run(input).await.map(Json)
            }),
        )
        .route(
            "/__test/organization-metadata",
            post(|Json(input): Json<Value>| async move {
                crate::organization_metadata::run(input).await.map(Json)
            }),
        )
        .route("/__test/id-policy", post(|Json(input): Json<Value>| async move {
            crate::id_policy::run(input).await.map(Json)
        }))
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/__health", get(|| async { Json(json!({"status":"ok"})) }))
        .route(
            "/__test/reset-state",
            post(|| async { Json(json!({"success":true})) }),
        )
        .route(
            "/__test/dynamic-context",
            post(|Json(input): Json<Input>| async move { run(input).await.map(Json) }),
        )
}
