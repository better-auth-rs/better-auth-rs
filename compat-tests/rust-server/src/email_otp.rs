use axum::{routing::post, Json, Router};
use better_auth::__private_core::store::VerificationStore;
use better_auth::{
    plugins::email_otp::{EmailOtpMessage, EmailOtpPlugin, EmailOtpStorage, SendEmailOtp},
    AuthError, AuthResult,
};
use better_auth_seaorm::SeaOrmStore;
use chrono::{Duration, Utc};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Default)]
struct State {
    outbox: HashMap<String, Vec<EmailOtpMessage>>,
    fails: bool,
}

#[derive(Default, Clone)]
pub(super) struct EmailOtpFixture {
    state: Arc<Mutex<State>>,
}

#[async_trait::async_trait]
impl SendEmailOtp for EmailOtpFixture {
    async fn send(&self, message: &EmailOtpMessage) -> AuthResult<()> {
        let mut state = self.state.lock().await;
        if state.fails {
            return Err(AuthError::internal("compat OTP sender failure"));
        }
        state
            .outbox
            .entry(message.email.clone())
            .or_default()
            .push(message.clone());
        Ok(())
    }
}

impl EmailOtpFixture {
    pub(super) fn plugin(&self, profile: &str) -> EmailOtpPlugin {
        EmailOtpPlugin::new()
            .sender(Arc::new(self.clone()))
            .change_email(true)
            .verify_current_email(true)
            .disable_sign_up(profile == "email-otp-options")
            .storage(if profile == "email-otp-options" {
                EmailOtpStorage::Hashed
            } else if profile == "email-otp-reuse" {
                EmailOtpStorage::Encrypted
            } else {
                EmailOtpStorage::Plain
            })
            .reuse_otp(matches!(profile, "email-otp-options" | "email-otp-reuse"))
            .send_verification_on_sign_up(profile == "email-otp-options")
            .override_default_email_verification(matches!(profile, "email-otp" | "email-otp-reuse"))
    }
    pub(super) async fn reset(&self) {
        *self.state.lock().await = State::default();
    }
    pub(super) fn router(&self, store: Arc<SeaOrmStore<super::TestSchema>>) -> Router {
        let fixture = self.clone();
        Router::new().route(
            "/__test/email-otp",
            post(move |Json(body): Json<serde_json::Value>| {
                let fixture = fixture.clone();
                let store = store.clone();
                async move {
                    match body["action"].as_str() {
                        Some("expire") => {
                            let identifier = format!(
                                "{}-otp-{}",
                                body["type"].as_str().unwrap(),
                                body["email"].as_str().unwrap()
                            );
                            store
                                .update_verification_by_identifier(
                                    &identifier,
                                    None,
                                    Some(Utc::now() - Duration::seconds(1)),
                                )
                                .await
                                .unwrap();
                            Json(serde_json::json!({"success": true}))
                        }
                        Some("fail") => {
                            fixture.state.lock().await.fails = body["fail"].as_bool().unwrap();
                            Json(serde_json::json!({"success": true}))
                        }
                        _ => Json(
                            serde_json::to_value(
                                fixture
                                    .state
                                    .lock()
                                    .await
                                    .outbox
                                    .get(body["email"].as_str().unwrap())
                                    .cloned()
                                    .unwrap_or_default(),
                            )
                            .unwrap(),
                        ),
                    }
                }
            }),
        )
    }
}
