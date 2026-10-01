use super::TestSchema;
use async_trait::async_trait;
use axum::{Json, Router, routing::post};
use better_auth::plugins::email_otp::{
    EmailOtpCallbacks, EmailOtpCodec, EmailOtpPlugin, EmailOtpStorage, EmailOtpType,
};
use better_auth::{AuthBuilder, AuthError, AuthResult, BetterAuth};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
#[derive(Default, serde::Serialize)]
struct State {
    generated: u32,
    sent: u32,
    encoded: u32,
    decoded: u32,
    fail: String,
    events: Vec<Value>,
}
#[derive(Clone, Default)]
pub(super) struct EmailOtpNativeFixture {
    state: Arc<Mutex<State>>,
}
fn rejected() -> AuthError {
    AuthError::Upstream {
        status: 400,
        code: "NATIVE_OTP_REJECTED",
        message: "Native OTP rejected",
    }
}
#[async_trait]
impl EmailOtpCodec for EmailOtpNativeFixture {
    async fn encode(&self, otp: &str) -> AuthResult<String> {
        let mut state = self.state.lock().unwrap();
        state.encoded += 1;
        if state.fail == "encode" {
            return Err(rejected());
        }
        Ok(format!("sealed:{otp}"))
    }
    async fn decode(&self, stored: &str) -> AuthResult<String> {
        let mut state = self.state.lock().unwrap();
        state.decoded += 1;
        if state.fail == "decode" {
            return Err(rejected());
        }
        stored
            .strip_prefix("sealed:")
            .map(str::to_owned)
            .ok_or_else(rejected)
    }
}
impl EmailOtpNativeFixture {
    pub(super) fn builder(
        &self,
        profile: &str,
        builder: AuthBuilder<TestSchema>,
    ) -> AuthBuilder<TestSchema> {
        if !profile.starts_with("email-otp-native") {
            return builder;
        }
        let storage = match profile {
            "email-otp-native-hash" => EmailOtpStorage::Hashed,
            "email-otp-native-encrypted" => EmailOtpStorage::Encrypted,
            "email-otp-native-custom-hash" => {
                let fixture = self.clone();
                EmailOtpStorage::CustomHash(Arc::new(move |otp| {
                    let fixture = fixture.clone();
                    Box::pin(async move {
                        let mut state = fixture.state.lock().unwrap();
                        state.encoded += 1;
                        if state.fail == "encode" {
                            return Err(rejected());
                        }
                        Ok(format!("hash:{otp}"))
                    })
                }))
            }
            "email-otp-native-custom-encrypted" => {
                EmailOtpStorage::CustomEncryption(Arc::new(self.clone()))
            }
            _ => EmailOtpStorage::Plain,
        };
        let generator = self.clone();
        let sender = self.clone();
        builder.plugin(EmailOtpPlugin::new().disable_sign_up(true).reuse_otp(true).storage(storage).callbacks(EmailOtpCallbacks::<TestSchema>::default()
   .generate(move |email,kind,endpoint|{let mut state=generator.state.lock().unwrap();state.generated+=1;state.events.push(json!({"data":{"email":email,"type":kind},"body":endpoint.body,"path":endpoint.path,"hasRequest":endpoint.request.is_some()}));if state.fail=="generate"{return Err(rejected());}Ok(Some(format!("{:06}:tail",state.generated)))})
   .send(move |_,_|{let sender=sender.clone();Ok(Some(Box::pin(async move{sender.state.lock().unwrap().sent+=1;Ok(())})))})))
    }
    pub(super) fn reset(&self) {
        *self.state.lock().unwrap() = State::default();
    }
    pub(super) fn router(&self, auth: Arc<BetterAuth<TestSchema>>) -> Router {
        let fixture = self.clone();
        Router::new().route(
            "/__test/email-otp-native",
            post(move |Json(body): Json<Value>| {
                let fixture = fixture.clone();
                let auth = auth.clone();
                async move {
                    if let Some(fail) = body["fail"].as_str() {
                        fixture.state.lock().unwrap().fail = fail.into();
                    }
                    let kind: EmailOtpType = serde_json::from_value(
                        body.get("type")
                            .cloned()
                            .unwrap_or_else(|| json!("sign-in")),
                    )?;
                    let email = body["email"].as_str().unwrap_or("Missing@Example.com");
                    let api = auth.email_otp()?;
                    if body["action"] == "create" {
                        return Ok::<_, AuthError>(Json(json!(api.create(email, kind).await?)));
                    }
                    if body["action"] == "get" {
                        return Ok(Json(json!({"otp":api.get(email,kind).await?})));
                    }
                    let identifier = format!(
                        "{}-otp-{}",
                        serde_json::to_value(kind)?.as_str().unwrap(),
                        email.to_lowercase()
                    );
                    if body["action"] == "expire" {
                        auth.store()
                            .update_verification_by_identifier(
                                &identifier,
                                None,
                                Some(chrono::Utc::now() - chrono::Duration::seconds(1)),
                            )
                            .await?;
                    }
                    if body["action"] == "tamper" {
                        auth.store()
                            .update_verification_by_identifier(
                                &identifier,
                                Some("broken:0".into()),
                                None,
                            )
                            .await?;
                    }
                    let record = auth
                        .store()
                        .get_verification_including_expired(&identifier)
                        .await?;
                    let mut state = serde_json::to_value(&*fixture.state.lock().unwrap())?;
                    state["exists"] = json!(record.is_some());
                    state["expiresAt"] = json!(
                        record
                            .as_ref()
                            .map(|record| record.expires_at.typed().map(|value| value.to_rfc3339()))
                            .transpose()?
                    );
                    state["attempts"] = json!(
                        record
                            .as_ref()
                            .map(|record| record.value.typed())
                            .transpose()?
                            .and_then(|value| value.rsplit_once(':'))
                            .and_then(|(_, attempts)| attempts.parse::<u32>().ok())
                    );
                    Ok(Json(state))
                }
            }),
        )
    }
}
