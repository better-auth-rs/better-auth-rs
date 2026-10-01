use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    routing::{get, post},
};
use better_auth::{
    AuthConfig, BetterAuth,
    config::{ApiErrorConfig, ApiErrorHandler, ApiErrorTask},
    plugins::{email_password::EmailPasswordPlugin, oauth::OAuthPlugin},
    server_api::EndpointInput,
};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    BeforeRequestAction, HttpMethod, middleware::RateLimitConfig, store::StatelessSchema,
};
use serde_json::{Value, json};
use tokio::sync::Notify;

#[derive(Clone)]
struct Fixture {
    input: Value,
    events: Arc<Mutex<Vec<String>>>,
    released: Arc<Notify>,
    finished: Arc<Notify>,
}

impl Fixture {
    fn record(&self, event: &str) {
        self.events.lock().unwrap().push(event.to_owned());
    }
    fn failure(&self) -> AuthError {
        match self.input["kind"].as_str() {
            Some("found") => AuthError::redirect("/target"),
            Some("numeric302") => AuthResponse::new(302)
                .with_header("location", "/target")
                .with_header("content-type", "application/json")
                .into(),
            Some("redirect307") => AuthResponse::new(307)
                .with_header("location", "/target")
                .with_header("content-type", "application/json")
                .into(),
            Some("api") => AuthResponse::json(400, &json!({"code":"FIXTURE","message":"invalid"}))
                .unwrap()
                .into(),
            _ => AuthError::internal("original failure"),
        }
    }
}

impl ApiErrorHandler<StatelessSchema> for Fixture {
    fn on_error(
        &self,
        _: &AuthError,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<ApiErrorTask>> {
        if self.input["callback"] == "async" {
            let state = self.clone();
            return Ok(Some(Box::pin(async move {
                state.record("callback-start");
                state.released.notified().await;
                state.record("callback-finish");
                state.finished.notify_one();
                Ok(())
            })));
        }
        self.record("callback");
        match self.input["callback"].as_str() {
            Some("throw") => Err(AuthError::internal("callback failure")),
            Some("throw-api") => {
                Err(AuthResponse::json(502, &json!({"message":"callback failure"}))?.into())
            }
            _ => Ok(None),
        }
    }
}

#[async_trait::async_trait]
impl AuthPlugin<StatelessSchema> for Fixture {
    fn name(&self) -> &'static str {
        "api-error-fixture"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/fixture-error", "fixtureError")]
    }
    async fn on_http_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if self.input["phase"] == "onRequest" {
            self.record("onRequest");
            return Err(self.failure());
        }
        Ok(None)
    }
    async fn on_http_response(
        &self,
        _: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if self.input["phase"] == "onResponse" {
            self.record("onResponse");
            return Err(self.failure());
        }
        Ok(None)
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if req.path() == "/fixture-error" {
            self.record("before");
            if self.input["phase"] == "before" {
                return Err(self.failure());
            }
        }
        Ok(None)
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.path() != "/fixture-error" {
            return Ok(None);
        }
        self.record("handler");
        if self.input["phase"] == "handler" {
            return Err(self.failure());
        }
        Ok(Some(AuthResponse::json(200, &json!({"ok":true}))?))
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        if req.path() == "/fixture-error" {
            self.record("after");
            if self.input["phase"] == "after" {
                return Err(self.failure());
            }
        }
        Ok(())
    }
}

fn observe(response: AuthResponse, input: &Value, native: bool) -> Value {
    let body = String::from_utf8(response.body).unwrap();
    if native && input["page"] != true {
        return json!({"thrown":false,"value":serde_json::from_str::<Value>(&body).unwrap()});
    }
    let mut value = json!({"thrown":false,"status":response.status,"location":response.headers.get("location"),"contentType":response.headers.get("content-type")});
    if response
        .headers
        .get("content-type")
        .is_some_and(|value| value == "text/html")
    {
        value["matches"] = input["needles"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|needle| json!(body.contains(needle.as_str().unwrap())))
            .collect();
    } else {
        value["body"] = if !body.is_empty()
            && response
                .headers
                .get("content-type")
                .is_some_and(|value| value.contains("application/json"))
        {
            serde_json::from_str(&body).unwrap()
        } else {
            body.into()
        };
    }
    value
}

async fn run(base_url: &str, input: Value) -> AuthResult<Value> {
    let fixture = Fixture {
        input: input.clone(),
        events: Arc::new(Mutex::new(Vec::new())),
        released: Arc::new(Notify::new()),
        finished: Arc::new(Notify::new()),
    };
    let mut config = AuthConfig::new("api-error-fixture-secret-at-least-thirty-two-characters")
        .base_url(base_url);
    config.api_error = serde_json::from_value::<ApiErrorConfig>(
        json!({"throw":input["throw"].as_bool().unwrap_or(false),"errorURL":input["errorURL"],"customizeDefaultErrorPage":input["customize"]}),
    )?;
    let mut builder = BetterAuth::stateless(config)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(OAuthPlugin::new())
        .plugin(fixture.clone());
    if input["callback"].is_string() {
        builder = builder.on_api_error(Arc::new(fixture.clone()));
    }
    let auth = builder.build().await?;
    let endpoint = if input["oauth"] == true {
        "/callback/mock"
    } else if input["page"] == true {
        "/error"
    } else if input["bodyCase"].is_string() {
        "/sign-in/email"
    } else {
        "/fixture-error"
    };
    let method = if input["bodyCase"].is_string() {
        HttpMethod::Post
    } else {
        HttpMethod::Get
    };
    let mut req = AuthRequest::new(method.clone(), format!("/api/auth{endpoint}")).with_url(
        url::Url::parse(&format!(
            "{base_url}/api/auth{endpoint}{}",
            input["query"].as_str().unwrap_or_default()
        ))
        .unwrap(),
    );
    if let Some(case) = input["bodyCase"].as_str() {
        let _ = req.headers.insert("origin".into(), base_url.to_owned());
        let _ = req.headers.insert(
            "content-type".into(),
            if case == "media" {
                "text/plain"
            } else {
                "application/json"
            }
            .into(),
        );
        req.body = Some(match case {
            "malformed" => b"{".to_vec(),
            "media" => b"bad".to_vec(),
            _ => serde_json::to_vec(&json!({"email":"invalid","password":"password"}))?,
        });
    }
    let native = input["transport"] == "native";
    let result = if native {
        let mut options = EndpointInput::default();
        if input["nativeRequest"] == true {
            options.request = Some(req);
        }
        if let Some(query) = input["nativeQuery"].as_object() {
            options.query = Some(Value::Object(query.clone()));
        }
        auth.call_endpoint(method, endpoint, options).await
    } else {
        auth.handle_request(req).await
    };
    let output = match result {
        Ok(response) => observe(response, &input, native),
        Err(error) if error.is_api_error() => {
            let response = error.to_auth_response();
            let body = if response.body.is_empty() {
                Value::String(String::new())
            } else {
                serde_json::from_slice(&response.body)?
            };
            json!({"thrown":true,"status":response.status,"body":body,"location":response.headers.get("location")})
        }
        Err(AuthError::Internal(message))
            if message == "original failure" || message == "callback failure" =>
        {
            json!({"thrown":true,"message":message})
        }
        Err(_) => json!({"thrown":true,"message":"runtime error"}),
    };
    let events = fixture.events.lock().unwrap().clone();
    if events.iter().any(|event| event == "callback-start") {
        fixture.released.notify_one();
        fixture.finished.notified().await;
    }
    let completed = fixture.events.lock().unwrap().clone();
    Ok(json!({"output":output,"events":events,"completed":completed}))
}

pub fn router(base_url: &str) -> Router {
    let base_url = base_url.to_owned();
    Router::new()
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/__health", get(|| async { Json(json!({"status":"ok"})) }))
        .route(
            "/__test/reset-state",
            post(|| async { Json(json!({"success":true})) }),
        )
        .route(
            "/__test/api-error",
            post(move |Json(input): Json<Value>| {
                let base_url = base_url.clone();
                async move { run(&base_url, input).await.map(Json) }
            }),
        )
}
