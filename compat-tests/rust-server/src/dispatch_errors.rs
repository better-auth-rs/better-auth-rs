use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    routing::{get, post},
};
use better_auth::{AuthConfig, BetterAuth, server_api::EndpointInput};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    BeforeRequestAction, CreateVerification, Headers, HttpMethod, config::CookieCacheConfig,
    middleware::RateLimitConfig, store::StatelessSchema,
};
use serde_json::{Value, json};

#[derive(Clone)]
struct Fixture {
    input: Value,
    events: Arc<Mutex<Vec<Value>>>,
    later: bool,
}

fn observed_headers(headers: &Headers) -> Value {
    json!({
        "priority": headers.get("x-priority"), "later": headers.get("x-later-hook"),
        "location": headers.get("location"),
        "cookies": headers.get_all("set-cookie").map(|value| value.split('=').next().unwrap()).collect::<Vec<_>>()
    })
}

fn observe(response: AuthResponse, thrown: bool) -> Value {
    let mut value = observed_headers(&response.headers);
    value["thrown"] = thrown.into();
    value["status"] = response.status.into();
    value["body"] = String::from_utf8(response.body).unwrap().into();
    value
}

fn observe_error(error: AuthError) -> Value {
    let response = error.to_auth_response();
    let explicit = observed_headers(response.api_error_headers().unwrap_or(&response.headers));
    let captured = response.captured_headers().map(observed_headers);
    let mut output = observe(response, true);
    if let Some(captured) = &captured {
        output
            .as_object_mut()
            .unwrap()
            .extend(captured.as_object().unwrap().clone());
    }
    output["errorHeaders"] = explicit;
    output["contextHeaders"] = captured.unwrap_or(Value::Null);
    output
}

impl Fixture {
    fn record(&self, value: Value) {
        self.events.lock().unwrap().push(value);
    }
    fn failure(&self) -> AuthError {
        if self.input["mode"] == "ordinary-error" {
            return AuthError::internal("Fixture ordinary failure");
        }
        let response = if self.input["mode"] == "redirect" {
            AuthResponse::new(302)
        } else {
            AuthResponse::json(
                if self.input["mode"] == "api-500" {
                    500
                } else {
                    400
                },
                &json!({"code":"FIXTURE_REJECTED","message":"Fixture rejected"}),
            )
            .unwrap()
        };
        response
            .with_header("x-priority", "explicit-error")
            .with_appended_header("set-cookie", "explicit_error_cookie=1; Path=/")
            .with_header("location", "/explicit-error")
            .into()
    }
    fn mutate(request: &AuthRequest, label: &str) -> AuthResult<()> {
        request.set_response_header("x-priority", label.to_owned())?;
        request.append_response_header("set-cookie", format!("{label}_cookie=1; Path=/"))
    }
}

#[async_trait::async_trait]
impl AuthPlugin<StatelessSchema> for Fixture {
    fn name(&self) -> &'static str {
        if self.later {
            "fixture-later"
        } else {
            "fixture-first"
        }
    }
    fn routes(&self) -> Vec<AuthRoute> {
        if self.later {
            vec![]
        } else {
            vec![AuthRoute::get("/fixture-probe", "fixtureProbe")]
        }
    }
    async fn on_http_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if self.later {
            return Ok(None);
        }
        self.record(json!({"hook":"http"}));
        if self.input["phase"] == "http" {
            return Err(self.failure());
        }
        Ok(None)
    }
    async fn before_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if self.later {
            return Ok(None);
        }
        self.record(json!({"hook":"before"}));
        if self.input["phase"] != "before" {
            return Ok(None);
        }
        Self::mutate(request, "before")?;
        if self.input["mode"] == "response" {
            return Ok(Some(BeforeRequestAction::Respond(AuthResponse::json(
                200,
                &json!({"early":true}),
            )?)));
        }
        Err(self.failure())
    }
    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<StatelessSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if self.later || request.path() != "/fixture-probe" {
            return Ok(None);
        }
        self.record(json!({"hook":"endpoint"}));
        context
            .database
            .create_verification(CreateVerification {
                identifier: "fixture-write".into(),
                value: "persisted".into(),
                expires_at: (chrono::Utc::now() + chrono::Duration::seconds(60)).into(),
                ..Default::default()
            })
            .await?;
        Self::mutate(request, "endpoint")?;
        if self.input["phase"] == "endpoint" || self.input["endpointError"] == true {
            if self.input["phase"] == "endpoint" && self.input["mode"] == "response" {
                return Ok(Some(AuthResponse::json(400, &json!({"response":true}))?));
            }
            return Err(self.failure());
        }
        Ok(Some(AuthResponse::json(200, &json!({"accepted":true}))?))
    }
    async fn after_request(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<StatelessSchema>,
    ) -> AuthResult<()> {
        if self.later {
            let mut value = observed_headers(&response.headers);
            value["hook"] = "after-later".into();
            value["apiError"] = response.is_api_error().into();
            self.record(value);
            request.set_response_header("x-later-hook", "ran".to_owned())?;
        } else {
            self.record(json!({"hook":"after-first","apiError":response.is_api_error()}));
            if self.input["phase"] == "after" {
                Self::mutate(request, "after")?;
                if self.input["mode"] == "response" {
                    response.replace_json(&json!({"recovered":true}))?;
                } else {
                    return Err(self.failure());
                }
            }
        }
        Ok(())
    }
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
            "/__test/dispatch-errors",
            post(move |Json(input): Json<Value>| {
                let base_url = base_url.clone();
                async move {
                    let events = Arc::new(Mutex::new(Vec::new()));
                    let mut config =
                        AuthConfig::new("dispatch-fixture-secret-at-least-thirty-two-characters")
                            .base_url(base_url.clone());
                    config.session.cookie_cache = Some(CookieCacheConfig {
                        enabled: Some(false),
                        ..Default::default()
                    });
                    let auth = BetterAuth::stateless(config)
                        .rate_limit(RateLimitConfig::new().enabled(false))
                        .plugin(Fixture {
                            input: input.clone(),
                            events: events.clone(),
                            later: false,
                        })
                        .plugin(Fixture {
                            input: input.clone(),
                            events: events.clone(),
                            later: true,
                        })
                        .build()
                        .await?;
                    let result = if input["transport"] == "native" {
                        auth.call_endpoint(
                            HttpMethod::Get,
                            "/fixture-probe",
                            EndpointInput::default(),
                        )
                        .await
                    } else {
                        auth.handle_request(
                            AuthRequest::new(HttpMethod::Get, "/api/auth/fixture-probe").with_url(
                                url::Url::parse(&format!("{base_url}/api/auth/fixture-probe"))
                                    .unwrap(),
                            ),
                        )
                        .await
                    };
                    let output = match result {
                        Ok(response) => observe(response, false),
                        Err(AuthError::Internal(message)) => {
                            json!({"thrown":true,"message":message})
                        }
                        Err(error) if error.is_api_error() => observe_error(error),
                        Err(error) => return Err(error),
                    };
                    let persisted = auth
                        .store()
                        .get_verification_by_identifier("fixture-write")
                        .await?
                        .is_some();
                    let events = events.lock().unwrap().clone();
                    Ok::<_, AuthError>(Json(
                        json!({"output":output,"events":events,"persisted":persisted}),
                    ))
                }
            }),
        )
}
