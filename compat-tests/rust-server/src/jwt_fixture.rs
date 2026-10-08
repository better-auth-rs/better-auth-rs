use super::TestSchema;
use axum::{
    Json, Router,
    response::IntoResponse,
    routing::{get, post},
};
use better_auth::{
    AuthConfig, BetterAuth,
    plugins::{JwtAlgorithm, JwtExpiration, JwtKeyPairConfig, JwtPlugin, JwtSigningOptions},
};
use better_auth_core::{AuthContext, AuthPlugin, AuthRequest, HttpMethod};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Clone)]
pub struct JwtFixture {
    remote: Arc<AuthContext<TestSchema>>,
    profile: String,
}

impl JwtFixture {
    pub async fn new(
        config: &AuthConfig,
        profile: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await?;
        let store = SeaOrmStore::<TestSchema>::new(config.clone(), database);
        Ok(Self {
            remote: Arc::new(AuthContext::new(Arc::new(config.clone()), Arc::new(store))),
            profile: profile.into(),
        })
    }

    pub fn plugin(&self) -> JwtPlugin {
        let plugin = JwtPlugin::new().key_pair_configs(vec![
            JwtKeyPairConfig::new(JwtAlgorithm::Ps256),
            JwtKeyPairConfig::new(JwtAlgorithm::Es512),
        ]);
        match self.profile.as_str() {
            "jwt-claims" => plugin.audience(vec!["service-a".into(), "service-b".into()].into()).expiration_time(JwtExpiration::At("2000000000.5".parse().unwrap())),
            "jwt-date" => plugin.audience(vec!["service-a".into(), "service-b".into()].into()).expiration_time(chrono::DateTime::from_timestamp(2_000_000_000, 123_000_000).unwrap()),
            "jwt-relative" => plugin.audience(vec!["service-a".into(), "service-b".into()].into()).expiration_time(chrono::Duration::milliseconds(1500)),
            "organization-jwt" => plugin.session_cookie_cache(true).define_payload(Arc::new(|session| Box::pin(async move { Ok(serde_json::from_value(session)?) }))).get_subject(Arc::new(|session| Box::pin(async move { Ok(session["session"]["id"].as_str().unwrap().to_owned()) }))),
            "jwt-ps256" => plugin.algorithm(JwtAlgorithm::Ps256).modulus_length(3072),
            "jwt-es512" => plugin.algorithm(JwtAlgorithm::Es512),
            "jwt-cache" | "cookie-version-plugin-jwt" => plugin.session_cookie_cache(true).issuer("ordinary-issuer".into()).audience("ordinary-audience".into()),
            "jwt-advanced" => plugin.define_payload(Arc::new(|session| Box::pin(async move { Ok(serde_json::from_value(json!({"sessionId": session["session"]["id"], "userId": session["user"]["id"], "sessionUserId": session["session"]["userId"], "userAgent": session["session"]["userAgent"]}))?) }))).get_subject(Arc::new(|session| Box::pin(async move { Ok(session["session"]["id"].as_str().unwrap().to_owned()) }))),
            "jwt-remote" => {
                let remote = self.remote.clone();
                plugin.algorithm(JwtAlgorithm::EdDsa).remote_url(format!("{}/__test/jwt/remote-jwks", self.remote.config.base_url.as_static().unwrap_or(""))).custom_sign(Arc::new(move |payload, options| {
                    let remote = remote.clone();
                    Box::pin(async move { JwtPlugin::new().sign_with_options(payload, &options, &remote).await })
                }))
            }
            _ => plugin,
        }
    }

    pub fn router(self, auth: Arc<BetterAuth<TestSchema>>) -> Router {
        let remote = self.remote.clone();
        Router::new().route("/__test/jwt/remote-jwks", get(move || {
            let remote = remote.clone();
            async move {
                let response = JwtPlugin::new().on_request(&AuthRequest::new(HttpMethod::Get, "/jwks"), &remote).await.unwrap().unwrap();
                Json(serde_json::from_slice::<Value>(&response.body.bytes().expect("The fixture response must serialize")).unwrap())
            }
        })).route("/__test/jwt/action", post(move |Json(body): Json<Value>| {
            let auth = auth.clone();
            let fixture = self.clone();
            async move {
                let plugin = fixture.plugin();
                let ctx = auth.context();
                let result: better_auth::AuthResult<Value> = async {
                    match body["action"].as_str().unwrap() {
                        "verify" => Ok(json!({"payload": plugin.verify(body["token"].as_str().unwrap(), body["issuer"].as_str(), ctx).await?})),
                        "sign" => {
                            let options = JwtSigningOptions { key_id: body["kid"].as_str().map(str::to_owned), algorithm: body["alg"].as_str().map(|alg| match alg { "PS256" => JwtAlgorithm::Ps256, "ES512" => JwtAlgorithm::Es512, "RS256" => JwtAlgorithm::Rs256, _ => JwtAlgorithm::EdDsa }), header: body.get("header").and_then(Value::as_object).cloned().unwrap_or_default() };
                            Ok(json!({"token": plugin.sign_with_options(body["payload"].as_object().unwrap().clone(), &options, ctx).await?}))
                        }
                        "expired" => {
                            let key = JwtPlugin::new().rotation_interval(chrono::Duration::seconds(-1)).create_key_pair(JwtKeyPairConfig::new(JwtAlgorithm::EdDsa), ctx).await?.ok_or_else(|| better_auth::AuthError::internal("Cannot read properties of null (reading 'id')"))?;
                            Ok(json!({"kid": key.id}))
                        }
                        "rotate" => {
                            let target = if fixture.profile == "jwt-remote" { fixture.remote.as_ref() } else { ctx };
                            let key = JwtPlugin::new().create_key_pair(JwtKeyPairConfig::new(JwtAlgorithm::EdDsa), target).await?.ok_or_else(|| better_auth::AuthError::internal("Cannot read properties of null (reading 'id')"))?;
                            Ok(json!({"kid": key.id}))
                        }
                        "revoke" => { ctx.database.delete_session(body["token"].as_str().unwrap()).await?; Ok(json!({"status": true})) }
                        _ => unreachable!(),
                    }
                }.await;
                match result { Ok(value) => Json(value).into_response(), Err(error) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"message": error.to_string()}))).into_response() }
            }
        }))
    }
}
