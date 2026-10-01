mod body;
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
        AccountManagementPlugin, AdminPlugin, ApiKeyPlugin, EmailPasswordPlugin, OAuthPlugin,
        OrganizationPlugin, PasskeyPlugin, PasswordManagementPlugin, SessionManagementPlugin,
        UserManagementPlugin,
    },
};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, BeforeRequestAction, HttpMethod, hooks::current_request_hook_context,
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
) -> AuthBuilder<S> {
    builder
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(BodyBefore(body.clone()))
        .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(Hasher(body.clone()))))
        .plugin(SessionManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .plugin(AdminPlugin::new().default_role("admin".to_owned()))
        .plugin(OrganizationPlugin::with_config(
            better_auth::plugins::OrganizationConfig {
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
        .plugin(ApiKeyPlugin::with_config(Default::default()))
        .plugin(PasskeyPlugin::new())
        .plugin(PasswordManagementPlugin::new().send_reset_password(Arc::new(body.clone())))
        .plugin(
            UserManagementPlugin::new()
                .delete_user_enabled(true)
                .change_email_enabled(true)
                .update_without_verification(true),
        )
        .plugin(OAuthPlugin::new())
        .plugin(Trace(events, body))
}
fn wire(response: AuthResult<AuthResponse>) -> Response {
    let response = response.unwrap_or_else(|error| error.to_auth_response());
    let mut output = (
        StatusCode::from_u16(response.status).unwrap(),
        response.body,
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
    let controls = Router::new()
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
                                AuthResponse::json(200, &value).map_err(Into::into)
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
                                    name: Some(input["name"].as_str().unwrap().to_owned()),
                                    ..Default::default()
                                },
                            )
                            .await;
                        wire(result.and_then(|_| {
                            AuthResponse::json(200, &json!({"success":true})).map_err(Into::into)
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
    if profile == "request-query-sqlite" {
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
        )
        .build()
        .await?;
        Ok(routes(Arc::new(auth), events, body))
    } else {
        let auth = configure(
            BetterAuth::<StatelessSchema>::stateless(config),
            events.clone(),
            body.clone(),
        )
        .build()
        .await?;
        Ok(routes(Arc::new(auth), events, body))
    }
}
