use super::TestSchema;
use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Bytes,
    http::HeaderMap,
    routing::{get, post},
};
use better_auth::plugins::oauth::{GenericOAuthConfig, OAuthPlugin};
use better_auth::seaorm::{HookControl, SeaOrmHookContext, SeaOrmHooks};
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, AuthVerification,
    CreateVerification, HttpMethod, OAuthStateStrategy,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct State {
    fail: bool,
    events: Vec<Value>,
}

#[derive(Clone)]
pub(super) struct OAuthPopupFixture {
    enabled: bool,
    base_url: String,
    state: Arc<Mutex<State>>,
}

impl OAuthPopupFixture {
    pub fn new(profile: &str, base_url: &str) -> Self {
        Self {
            enabled: profile.starts_with("oauth-popup-"),
            base_url: base_url.into(),
            state: Default::default(),
        }
    }
    pub fn configure(&self, profile: &str, config: &mut AuthConfig) {
        if !self.enabled {
            return;
        }
        config.trusted_origins = better_auth_core::TrustedValues::merge(vec![config.trusted_origins.clone(), vec!["https://embed.example".into()].into()]);
        config.session.bearer = Some(Default::default());
        config.account.store_state_strategy = Some(if profile == "oauth-popup-cookie" {
            OAuthStateStrategy::Cookie
        } else {
            OAuthStateStrategy::Database
        });
    }
    pub fn oauth(&self, mut plugin: OAuthPlugin) -> OAuthPlugin {
        if self.enabled {
            for provider in ["popup", "popup-broken"] {
                plugin = plugin.add_generic_provider(
                    provider,
                    GenericOAuthConfig {
                        client_id: "popup-client".into(),
                        client_secret: Some("popup-secret".into()),
                        authorization_url: Some(if provider == "popup" {
                            format!("{}/__test/oauth-popup/authorize", self.base_url)
                        } else {
                            "not a url".into()
                        }),
                        token_url: Some(format!("{}/__test/oauth-popup/token", self.base_url)),
                        user_info_url: Some(format!(
                            "{}/__test/oauth-popup/userinfo",
                            self.base_url
                        )),
                        scopes: vec!["email".into()],
                        pkce: true,
                        ..Default::default()
                    },
                );
            }
        }
        plugin
    }
    pub fn hooks(&self) -> Arc<dyn SeaOrmHooks<TestSchema>> {
        Arc::new(self.clone())
    }
    pub fn reset(&self) {
        *self.state.lock().unwrap() = State::default();
    }
    pub fn router(&self, auth: Arc<BetterAuth<TestSchema>>) -> Router {
        let control = self.clone();
        let token = self.clone();
        let userinfo = self.clone();
        Router::new()
            .route("/__test/oauth-popup", post(move |Json(body): Json<Value>| {
                let fixture = control.clone(); let auth = auth.clone(); async move {
                    { let mut state = fixture.state.lock().unwrap(); if let Some(fail) = body.get("stateFailure").and_then(Value::as_bool) { state.fail = fail; } if body.get("clear") == Some(&Value::Bool(true)) { state.events.clear(); } }
                    let value = if let Some(state) = body.get("state").and_then(Value::as_str) { auth.store().get_verification_by_identifier(state).await?.map(|record| record.value().to_owned()) } else { None };
                    let events = fixture.state.lock().unwrap().events.clone();
                    Ok::<_, AuthError>(Json(json!({ "events": events, "value": value })))
                }
            }))
            .route("/__test/oauth-popup/token", post(move |body: Bytes| { let fixture = token.clone(); async move {
                let fields: std::collections::HashMap<_, _> = url::form_urlencoded::parse(&body).into_owned().collect();
                fixture.state.lock().unwrap().events.push(json!({ "event": "token", "code": fields.get("code"), "verifierLength": fields.get("code_verifier").map(String::len) }));
                Json(json!({ "access_token": "popup-access", "token_type": "Bearer", "expires_in": 3600 }))
            }}))
            .route("/__test/oauth-popup/userinfo", get(move |headers: HeaderMap| { let fixture = userinfo.clone(); async move {
                fixture.state.lock().unwrap().events.push(json!({ "event": "userinfo", "authorization": headers.get("authorization").and_then(|value| value.to_str().ok()) }));
                Json(json!({ "id": "popup-user", "email": "popup@example.com", "emailVerified": true, "name": "Popup User", "image": null }))
            }}))
    }
}

#[async_trait]
impl AuthPlugin<TestSchema> for OAuthPopupFixture {
    fn name(&self) -> &'static str {
        "popup-probe"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        if self.enabled {
            vec![AuthRoute::get("/oauth2/callback/probe", "popup_probe")]
        } else {
            vec![]
        }
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        _: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if !self.enabled
            || req.method() != &HttpMethod::Get
            || req.path() != "/oauth2/callback/probe"
        {
            return Ok(None);
        }
        let mode = req.query.get("mode").map(String::as_str);
        if mode == Some("plain") {
            return Ok(Some(AuthResponse::json(200, &json!({ "ordinary": true }))?));
        }
        let mut response = AuthResponse::new(302)
            .with_header("Content-Type", "application/json")
            .with_header(
                "Location",
                req.query
                    .get("target")
                    .map(String::as_str)
                    .unwrap_or("/done"),
            );
        if mode == Some("token") {
            response.headers.append(
                "Set-Cookie",
                "better-auth.session_token=raw%2Btoken.signature%3D; Path=/; HttpOnly",
            );
        }
        if mode == Some("combined") {
            response.headers.append("Set-Cookie", "other=value; Expires=Wed, 21 Oct 2030 07:28:00 GMT, better-auth.session_token=first%2Btoken; Path=/");
        }
        Ok(Some(response))
    }
}

#[async_trait]
impl SeaOrmHooks<TestSchema> for OAuthPopupFixture {
    async fn before_create_verification(
        &self,
        _: &mut CreateVerification,
        _: &SeaOrmHookContext<'_, TestSchema>,
    ) -> AuthResult<HookControl> {
        if self.enabled && self.state.lock().unwrap().fail {
            return Err(AuthError::internal("Popup state unavailable"));
        }
        Ok(HookControl::Continue)
    }
}
