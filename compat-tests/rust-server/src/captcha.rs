use super::TestSchema;
use axum::{
    Json, Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use better_auth::plugins::{
    captcha::{
        BotIdChecker, BotIdRequestValidator, BotIdVerification, CaptchaPlugin, CaptchaProvider,
    },
    email_password::EmailPasswordPlugin,
};
use better_auth::{AuthConfig, BetterAuth};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    BeforeRequestAction, HttpMethod,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(super) struct CaptchaFixture {
    mode: Arc<Mutex<Value>>,
    events: Arc<Mutex<Vec<Value>>>,
}
impl CaptchaFixture {
    pub fn rate_limit(
        profile: &str,
        config: better_auth::middleware::RateLimitConfig,
    ) -> better_auth::middleware::RateLimitConfig {
        if matches!(profile, "captcha-rate-limit" | "captcha-hcaptcha") {
            config
                .enabled(true)
                .default_limit(std::time::Duration::from_secs(60), 1)
                .endpoint("/sign-in/email", std::time::Duration::from_secs(60), 1)
        } else {
            config
        }
    }
    fn event(&self, event: Value) {
        self.events.lock().unwrap().push(event);
    }
    pub fn configure(&self, profile: &str, config: &mut AuthConfig) {
        if profile == "captcha-turnstile" {
            config.advanced.ip_address.headers =
                Some(vec!["x-client-ip".into(), "x-forwarded-for".into()]);
            config.advanced.ip_address.trusted_proxies = vec!["10.0.0.0/8".into()];
            config.advanced.ip_address.ipv6_subnet = 60.9;
        } else if profile == "captcha-hcaptcha" {
            config.advanced.ip_address.disable_ip_tracking = Some(true);
        } else if profile == "captcha-captchafox" {
            config.advanced.ip_address.ipv6_subnet = 128.0;
        }
    }
    pub fn plugin(&self, profile: &str, base_url: &str) -> CaptchaPlugin {
        let secret = if profile == "captcha-empty-secret" {
            ""
        } else {
            "fixture-secret"
        }
        .into();
        let provider = match profile {
            "captcha-recaptcha" => CaptchaProvider::GoogleRecaptcha {
                secret_key: secret,
                min_score: 0.5,
                expected_action: Some("login".into()),
                allowed_hostnames: vec!["auth.example.test".into()],
            },
            "captcha-hcaptcha" => CaptchaProvider::HCaptcha {
                secret_key: secret,
                site_key: Some("fixture-site".into()),
            },
            "captcha-captchafox" => CaptchaProvider::CaptchaFox {
                secret_key: secret,
                site_key: Some("fixture-site".into()),
            },
            "captcha-botid" | "captcha-botid-default" => CaptchaProvider::VercelBotId {
                check_bot_id: Arc::new(self.clone()),
                validate_request: (profile == "captcha-botid")
                    .then(|| Arc::new(self.clone()) as Arc<dyn BotIdRequestValidator>),
            },
            _ => CaptchaProvider::CloudflareTurnstile {
                secret_key: secret,
                expected_action: Some("login".into()),
                allowed_hostnames: vec!["auth.example.test".into()],
            },
        };
        let plugin = CaptchaPlugin::new(provider)
            .site_verify_url_override(format!("{base_url}/__test/captcha/siteverify"));
        if profile == "captcha-paths" {
            plugin.endpoints(
                ["/sign-in/*", "/protected/**", "/literal?", "/sign-up/email"]
                    .map(str::to_owned)
                    .to_vec(),
            )
        } else {
            plugin
        }
    }
    pub async fn reset(&self) {
        *self.mode.lock().unwrap() = Value::Null;
        self.events.lock().unwrap().clear();
    }
    pub fn router(&self, auth: Arc<BetterAuth<TestSchema>>) -> Router {
        let control = self.clone();
        let provider = self.clone();
        Router::new().route("/__test/captcha/control", post(move |Json(body): Json<Value>| { let fixture=control.clone(); async move {
            if body.get("clear").and_then(Value::as_bool)==Some(true) { fixture.events.lock().unwrap().clear(); }
            if let Some(mode)=body.get("mode") { *fixture.mode.lock().unwrap()=mode.clone(); }
            Json(json!(&*fixture.events.lock().unwrap()))
        }})).route("/__test/captcha/native", post(move |Json(body):Json<Value>| {let auth=auth.clone();async move {
            let mut request=AuthRequest::new(HttpMethod::Post,"/sign-up/email");
            request.body=Some(serde_json::to_vec(&body).unwrap());
            request.headers.insert("content-type".into(),"application/json".into());
            let response=match EmailPasswordPlugin::new().on_request(&request,auth.context()).await {
                Ok(Some(response))=>response, Err(error)=>error.to_auth_response(), Ok(None)=>AuthResponse::new(404),
            };
            Json(json!({"status":response.status,"body":serde_json::from_slice::<Value>(&response.body).unwrap()}))
        }})).route("/__test/captcha/siteverify",post(move |headers:HeaderMap,body:Bytes|{let fixture=provider.clone();async move {
            let content_type=headers.get("content-type").unwrap().to_str().unwrap();
            let body:Value=if content_type.contains("application/json") {serde_json::from_slice(&body).unwrap()}
                else {serde_json::to_value(url::form_urlencoded::parse(&body).into_owned().collect::<std::collections::BTreeMap<_,_>>()).unwrap()};
            fixture.event(json!({"phase":"provider","type":content_type,"body":body}));
            let mode=fixture.mode.lock().unwrap().clone(); delay(&mode,"delay").await;
            let status=StatusCode::from_u16(mode.get("status").and_then(Value::as_u64).unwrap_or(200) as u16).unwrap();
            if let Some(text)=mode.get("text").and_then(Value::as_str) { return (status,[("content-type","text/plain")],text.to_owned()).into_response(); }
            (status,Json(mode.get("data").cloned().unwrap_or_else(||json!({"success":true,"action":"login","hostname":"auth.example.test","score":0.8})))).into_response()
        }}))
    }
}
async fn delay(mode: &Value, key: &str) {
    if let Some(delay) = mode.get(key).and_then(Value::as_u64) {
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
    }
}
#[async_trait::async_trait]
impl BotIdChecker for CaptchaFixture {
    async fn check(&self) -> AuthResult<BotIdVerification> {
        self.event(json!({"phase":"check"}));
        let mode = self.mode.lock().unwrap().clone();
        delay(&mode, "delay").await;
        if mode.get("throw").and_then(Value::as_bool) == Some(true) {
            return Err(AuthError::internal("fixture BotID failure"));
        }
        self.event(json!({"phase":"checked"}));
        Ok(serde_json::from_value(
            mode.get("verification")
                .cloned()
                .unwrap_or_else(|| json!({"isBot":false})),
        )?)
    }
}
#[async_trait::async_trait]
impl BotIdRequestValidator for CaptchaFixture {
    async fn validate(
        &self,
        request: &AuthRequest,
        verification: &BotIdVerification,
    ) -> AuthResult<bool> {
        let header = request.headers.get("x-bot-allow");
        self.event(json!({"phase":"validate","path":request.url().map_or(request.path(), |url| url.path()),"header":header,"verification":verification}));
        let mode = self.mode.lock().unwrap().clone();
        delay(&mode, "validatorDelay").await;
        if mode.get("validatorThrow").and_then(Value::as_bool) == Some(true) {
            return Err(AuthError::internal("fixture validator failure"));
        }
        Ok(!verification.is_bot
            || (verification.is_verified_bot == Some(true)
                && header.map(String::as_str) == Some("yes")))
    }
}
#[async_trait::async_trait]
impl AuthPlugin<TestSchema> for CaptchaFixture {
    fn name(&self) -> &'static str {
        "captcha-observer"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        _: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if observed(req) {
            self.event(json!({"phase":"before"}));
        }
        Ok(None)
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<TestSchema>,
    ) -> AuthResult<()> {
        if observed(req) {
            self.event(json!({"phase":"after"}));
        }
        Ok(())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn observed(req: &AuthRequest) -> bool {
    matches!(
        req.path(),
        "/sign-up/email" | "/sign-in/email" | "/request-password-reset"
    )
}
