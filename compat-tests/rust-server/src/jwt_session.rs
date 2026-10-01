use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth::plugins::{
    EmailPasswordPlugin, JwtCallbacks, JwtPlugin, JwtPluginConfig, SessionManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthSchema, middleware::RateLimitConfig,
};
use better_auth_seaorm::{
    Database, SeaOrmStore,
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

struct ReplaceResponse(bool);

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for ReplaceResponse {
    fn name(&self) -> &'static str {
        "replace-session-response"
    }
    fn routes(&self) -> Vec<better_auth_core::AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        if self.0 && request.path() == "/get-session" {
            response.replace_json(&json!({"replaced":true}))?;
        }
        Ok(())
    }
}

pub async fn run(base: &str, input: Value) -> AuthResult<Value> {
    let events = Arc::new(Mutex::new(Vec::<Value>::new()));
    let payload_events = events.clone();
    let read_events = events.clone();
    let jwt_config = JwtPluginConfig {
        define_payload: Some(Arc::new(move |data| {
            let events = payload_events.clone();
            Box::pin(async move {
                let expires = chrono::DateTime::parse_from_rfc3339(
                    data["session"]["expiresAt"].as_str().unwrap(),
                )
                .unwrap();
                let payload =
                    json!({"name":data["user"]["name"],"expired":expires < chrono::Utc::now()});
                events.lock().unwrap().push(
                    json!({"event":"payload","name":payload["name"],"expired":payload["expired"]}),
                );
                Ok(serde_json::from_value(payload)?)
            })
        })),
        ..Default::default()
    };
    let callbacks = JwtCallbacks::<BundledSchema>::default().get_jwks(move |endpoint| {
        let events = read_events.clone();
        Box::pin(async move {
            events.lock().unwrap().push(json!({"event":"get","path":endpoint.path,"session":endpoint.session.is_some(),"newSession":endpoint.new_session()?.is_some()}));
            endpoint.auth.database.list_jwks().await.map(Some)
        })
    });
    let config = AuthConfig::new("jwt-session-fixture-secret-at-least-thirty-two-characters")
        .base_url(base.to_owned());
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let store = SeaOrmStore::<BundledSchema>::new(Arc::new(config.clone()), database);
    let auth = AuthBuilder::new(config)
        .store(store)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(ReplaceResponse(input["state"] == "replaced"))
        .plugin(JwtPlugin::with_config(jwt_config).callbacks(callbacks))
        .plugin(EmailPasswordPlugin::new().password_hasher(Arc::new(super::jwt_adapter::Hasher)))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let signup = super::jwt_adapter::invoke(&auth, base, "/sign-up/email", Some(json!({"name":"Original user","email":"snapshot@example.com","password":"fixture-password"})), true, None).await?;
    let body: Value = serde_json::from_slice(&signup.body)?;
    let token = body["token"].as_str().unwrap();
    if input["state"] == "expired" {
        auth.store()
            .update_session_expiry(token, chrono::Utc::now() - chrono::Duration::minutes(1))
            .await?;
    }
    if input["state"] == "revoked" {
        auth.store().delete_session(token).await?;
    }
    let cookies = signup
        .headers
        .get_all("set-cookie")
        .map(|cookie| cookie.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    events.lock().unwrap().clear();
    let response = super::jwt_adapter::invoke(
        &auth,
        base,
        "/get-session",
        None,
        input["transport"] == "native",
        Some(cookies),
    )
    .await?;
    let body: Value = serde_json::from_slice(&response.body)?;
    let claims = response.headers.get("set-auth-jwt").map(|token| {
        let payload: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(token.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        json!({"name":payload["name"],"expired":payload["expired"]})
    });
    let events = events.lock().unwrap().clone();
    Ok(
        json!({"status":response.status,"body":if body.is_null(){"null"}else if body["replaced"]==true{"replaced"}else{"session"},"jwt":claims,"events":events,"storedSessions":usize::from(auth.store().get_session(token).await?.is_some())}),
    )
}
