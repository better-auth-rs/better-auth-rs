use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    routing::{get, post},
};
use better_auth::{AuthConfig, BetterAuth, integrations::axum::AxumIntegration};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    BeforeRequestAction, hooks::current_request_hook_context, middleware::RateLimitConfig,
    store::StatelessSchema,
};
use serde_json::{Value, json};

pub(crate) type Events = Arc<Mutex<Vec<Value>>>;

#[derive(Clone)]
struct Fixture {
    events: Arc<Mutex<Vec<Value>>>,
    later: bool,
}

fn request_url(request: &AuthRequest) -> Option<String> {
    request.url().map(|url| {
        let mut result = url.path().to_owned();
        if let Some(query) = url.query() {
            result.push('?');
            result.push_str(query);
        }
        result
    })
}

impl Fixture {
    fn record(&self, value: Value) {
        self.events.lock().unwrap().push(value);
    }

    fn endpoint_event(&self, phase: &str, request: &AuthRequest) -> AuthResult<Value> {
        let context = current_request_hook_context()
            .ok_or_else(|| AuthError::internal("Missing trailing slash hook context"))?;
        let event = json!({
            "phase": phase, "path": context.path, "url": request_url(request),
            "method": format!("{:?}", request.method()).to_uppercase(),
            "params": context.params,
        });
        self.record(event.clone());
        Ok(event)
    }
}

#[async_trait::async_trait]
impl AuthPlugin<StatelessSchema> for Fixture {
    fn name(&self) -> &'static str {
        if self.later {
            "trailing-slashes-later-response"
        } else {
            "trailing-slashes-fixture"
        }
    }

    fn routes(&self) -> Vec<AuthRoute> {
        if self.later {
            return Vec::new();
        }
        [
            ("/probe", "probe"),
            ("/declared/", "declared"),
            ("/dynamic/{id}", "dynamic"),
            ("/disabled", "disabled"),
            ("/disabled-slash-config", "disabledSlashConfig"),
            ("/disabled-declared/", "disabledDeclared"),
            ("/", "root"),
            ("/replace-response", "replace"),
            ("/response-chain", "responseChain"),
        ]
        .into_iter()
        .flat_map(|(path, operation)| {
            [
                AuthRoute::get(path, format!("{operation}Get")),
                AuthRoute::post(path, format!("{operation}Post")),
            ]
        })
        .collect()
    }

    async fn on_http_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if self.later {
            return Ok(None);
        }
        self.record(json!({"phase":"http", "url":request_url(request), "method":format!("{:?}", request.method()).to_uppercase()}));
        if request
            .url()
            .is_some_and(|url| url.path() == "/api/auth/early")
        {
            return Ok(Some(AuthResponse::json(202, &json!({"early":true}))?));
        }
        Ok(None)
    }

    async fn on_http_response(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        let replacing = request
            .url()
            .is_some_and(|url| url.path() == "/api/auth/replace-response");
        if self.later {
            if replacing {
                self.record(json!({"phase":"later-response"}));
            }
            if request
                .url()
                .is_some_and(|url| url.path() == "/api/auth/response-chain")
            {
                self.record(json!({"phase":"later-response","header":response.headers.get("x-response-chain")}));
                let _ = response
                    .headers
                    .insert("x-response-chain".to_owned(), "second".to_owned());
            }
            return Ok(None);
        }
        self.record(json!({"phase":"response", "status":response.status}));
        if replacing {
            return Ok(Some(AuthResponse::json(202, &json!({"replaced":true}))?));
        }
        if request
            .url()
            .is_some_and(|url| url.path() == "/api/auth/response-chain")
        {
            let _ = response
                .headers
                .insert("x-response-chain".to_owned(), "first".to_owned());
        }
        Ok(None)
    }

    async fn before_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if !self.later {
            let _ = self.endpoint_event("before", request)?;
        }
        Ok(None)
    }

    async fn on_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if self.later
            || !self
                .routes()
                .iter()
                .any(|route| route.matches(request.method(), request.path()))
        {
            return Ok(None);
        }
        let mut event = self.endpoint_event("endpoint", request)?;
        event["body"] = request.parsed_http_body().cloned().unwrap_or(Value::Null);
        event["query"] = serde_json::to_value(&request.query)?;
        Ok(Some(AuthResponse::json(200, &event)?))
    }

    async fn after_request(
        &self,
        request: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        if !self.later {
            let _ = self.endpoint_event("after", request)?;
        }
        Ok(())
    }
}

pub(crate) async fn auth(
    profile: &str,
    base_url: &str,
) -> AuthResult<(Arc<BetterAuth<StatelessSchema>>, Events)> {
    let mut config = AuthConfig::new("trailing-slashes-fixture-secret-with-at-least-32-characters")
        .base_url(base_url);
    config.advanced.skip_trailing_slashes = profile == "trailing-slashes-true";
    config.disabled_paths = [
        "/disabled",
        "/disabled-slash-config/",
        "/disabled-declared",
        "/dynamic/blocked",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let events = Arc::new(Mutex::new(Vec::new()));
    let fixture = Fixture {
        events: events.clone(),
        later: false,
    };
    let auth = Arc::new(
        BetterAuth::stateless(config)
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(fixture.clone())
            .plugin(Fixture {
                later: true,
                ..fixture
            })
            .build()
            .await?,
    );
    Ok((auth, events))
}

pub(crate) async fn router(profile: &str, base_url: &str) -> AuthResult<Router> {
    let (auth, events) = auth(profile, base_url).await?;
    let controls = Router::new()
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
            "/__test/trailing-slashes",
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
        );
    Ok(auth.clone().axum_router().with_state(auth).merge(controls))
}
