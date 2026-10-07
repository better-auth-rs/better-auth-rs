use axum::{Json, Router, routing::get};
use better_auth::{
    AuthConfig, AuthError,
    config::{CookieCacheConfig, CookieCacheStrategy, CookieCacheVersion, UserFieldConfig},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

struct State {
    version: String,
    fail: bool,
    events: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: "1".into(),
            fail: false,
            events: Vec::new(),
        }
    }
}

#[derive(Clone, Default)]
pub(super) struct CookieVersionFixture(Arc<Mutex<State>>);

impl CookieVersionFixture {
    pub(super) fn configure(&self, profile: &str, config: &mut AuthConfig) {
        if !profile.starts_with("cookie-version-") {
            return;
        }
        let state = self.0.clone();
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: Some(true),
            strategy: Some(if profile.ends_with("jwe") {
                CookieCacheStrategy::Jwe
            } else if profile.ends_with("jwt") {
                CookieCacheStrategy::Jwt
            } else {
                CookieCacheStrategy::Compact
            }),
            version: CookieCacheVersion::dynamic(move |data| {
                let state = state.clone();
                async move {
                    let mut state = state.lock().unwrap();
                    state.events.push(json!({ "sessionId": data.session.id, "userId": data.user.id, "name": data.user.name, "hiddenSession": data.session.additional_fields.get("internalNote"), "hiddenUser": data.user.additional_fields.get("secretNote") }));
                    if state.fail {
                        return Err(AuthError::internal("Cookie version failed"));
                    }
                    Ok(state.version.clone())
                }
            }),
            ..Default::default()
        });
        config.user.fields_mut().insert(
            "secretNote".into(),
            UserFieldConfig {
                returned: Some(false),
                default_value: Some("user-secret".into()),
                ..Default::default()
            },
        );
        config.session.fields_mut().insert(
            "internalNote".into(),
            UserFieldConfig {
                returned: Some(false),
                default_value: Some("session-secret".into()),
                ..Default::default()
            },
        );
    }

    pub(super) fn reset(&self) {
        *self.0.lock().unwrap() = State::default();
    }

    pub(super) fn router(&self) -> Router {
        let read = self.clone();
        let update = self.clone();
        Router::new().route(
            "/__test/cookie-version",
            get(move || {
                let fixture = read.clone();
                async move { Json(json!({ "events": fixture.0.lock().unwrap().events })) }
            })
            .post(move |Json(body): Json<Value>| {
                let fixture = update.clone();
                async move {
                    let mut state = fixture.0.lock().unwrap();
                    if let Some(version) = body["version"].as_str() {
                        state.version = version.into();
                    }
                    if let Some(fail) = body["fail"].as_bool() {
                        state.fail = fail;
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
