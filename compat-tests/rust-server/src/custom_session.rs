use std::sync::{Arc, Mutex};

use axum::{Json, Router, routing::get};
use better_auth::{
    AuthConfig, AuthError, AuthResult,
    plugins::{CustomSessionCallback, CustomSessionInput, CustomSessionPlugin},
};
use better_auth_core::{
    AuthContext, AuthRequest,
    config::{CookieCacheConfig, CookieCacheVersion},
};
use serde_json::{Value, json};

use super::TestSchema;

#[derive(Default)]
struct State {
    events: Vec<Value>,
    fail_read: bool,
}

#[derive(Clone)]
pub(super) struct CustomSessionFixture {
    state: Arc<Mutex<State>>,
    barrier: Arc<tokio::sync::Barrier>,
    profile: String,
}

impl CustomSessionFixture {
    pub fn new(profile: &str) -> Self {
        Self {
            state: Arc::default(),
            barrier: Arc::new(tokio::sync::Barrier::new(2)),
            profile: profile.into(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.profile.starts_with("custom-session")
    }

    pub fn configure(&self, config: &mut AuthConfig) {
        if !self.enabled() {
            return;
        }
        config.session.defer_session_refresh = self.profile == "custom-session-deferred";
        let state = self.state.clone();
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: Some(true),
            version: CookieCacheVersion::dynamic(move |_| {
                let state = state.clone();
                async move {
                    if state.lock().unwrap().fail_read {
                        return Err(AuthError::internal("Session read failed"));
                    }
                    Ok("1".into())
                }
            }),
            ..Default::default()
        });
    }

    pub fn plugin(&self) -> CustomSessionPlugin<TestSchema> {
        CustomSessionPlugin::new(self.clone())
            .mutate_list_device_sessions(self.profile == "custom-session-list")
    }

    pub fn reset(&self) {
        *self.state.lock().unwrap() = State::default();
    }

    pub fn router(&self) -> Router {
        let read = self.clone();
        let update = self.clone();
        Router::new().route(
            "/__test/custom-session",
            get(move || {
                let fixture = read.clone();
                async move { Json(json!({ "events": fixture.state.lock().unwrap().events })) }
            })
            .post(move |Json(body): Json<Value>| {
                let fixture = update.clone();
                async move {
                    let mut state = fixture.state.lock().unwrap();
                    if let Some(fail_read) = body["failRead"].as_bool() {
                        state.fail_read = fail_read;
                    }
                    if body["clear"] == true {
                        state.events.clear();
                    }
                    Json(json!({ "events": state.events }))
                }
            }),
        )
    }
}

#[async_trait::async_trait]
impl CustomSessionCallback<TestSchema> for CustomSessionFixture {
    async fn customize(
        &self,
        input: CustomSessionInput,
        request: &AuthRequest,
        context: &AuthContext<TestSchema>,
    ) -> AuthResult<Value> {
        let mode = request.headers.get("x-custom-mode").map(String::as_str);
        let user = input.data.user_view()?;
        let exists = context
            .database
            .get_user_by_id(user.id.typed().unwrap())
            .await?
            .is_some();
        request.append_response_header("x-customized", "true".into())?;
        self.state.lock().unwrap().events.push(json!({ "path": request.path(), "name": user.name, "exists": exists, "tag": request.headers.get("x-app-tag"), "needsRefresh": input.needs_refresh }));
        if mode == Some("partial-reject") {
            if user.name.typed()?.as_deref() == Some("First") {
                return Err(AuthError::Upstream {
                    status: 403,
                    code: "CUSTOM_SESSION_REJECTED",
                    message: "Custom session rejected",
                });
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            self.state
                .lock()
                .unwrap()
                .events
                .push(json!({ "completed": user.name }));
        }
        if mode == Some("reject") {
            return Err(AuthError::Upstream {
                status: 403,
                code: "CUSTOM_SESSION_REJECTED",
                message: "Custom session rejected",
            });
        }
        if mode == Some("null") {
            return Ok(Value::Null);
        }
        if mode == Some("barrier") {
            self.barrier.wait().await;
        }
        let mut value = serde_json::to_value(input.data)?;
        value["marker"] = "custom-session".into();
        if let Some(needs_refresh) = input.needs_refresh {
            value["needsRefresh"] = needs_refresh.into();
        }
        Ok(value)
    }
}
