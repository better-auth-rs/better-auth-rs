use super::TestSchema;
use async_trait::async_trait;
use axum::{Json, Router, routing::post};
use better_auth::plugins::{
    EmailPasswordPlugin,
    email_otp::{EmailOtpPlugin, EmailOtpType},
    endpoint_context::EndpointContext,
    user_admission::{UserValidationData, UserValidationRejection, ValidateUserInfo},
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::PasswordHasher;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct State {
    deny: bool,
    events: Vec<Value>,
}

#[derive(Clone, Default)]
pub(super) struct EmailOtpTransactionFixture {
    state: Arc<Mutex<State>>,
}

struct FixtureHasher;
#[async_trait]
impl PasswordHasher for FixtureHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        Ok(format!("fixture:{password}"))
    }
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        Ok(hash == format!("fixture:{password}"))
    }
}

#[async_trait]
impl ValidateUserInfo<TestSchema> for EmailOtpTransactionFixture {
    async fn validate(
        &self,
        data: &UserValidationData,
        endpoint: &EndpointContext<'_, TestSchema>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        let email = data.user["email"].as_str().unwrap();
        let api = endpoint.email_otp()?;
        let before = api.get(email, EmailOtpType::SignIn).await?;
        let created = api.create(email, EmailOtpType::SignIn).await?;
        let read_back = api.get(email, EmailOtpType::SignIn).await?;
        let mut state = self.state.lock().unwrap();
        state
            .events
            .push(json!({"before":before,"created":created,"readBack":read_back}));
        Ok(state
            .deny
            .then(|| UserValidationRejection::new("otp_admission_denied")))
    }
}

impl EmailOtpTransactionFixture {
    pub(super) fn configure(profile: &str, config: &mut AuthConfig) {
        if profile == "email-otp-transaction" {
            config.verification.store_identifier.default =
                better_auth_core::config::VerificationIdentifierStorage::Hashed;
        }
    }

    pub(super) fn password(profile: &str, plugin: EmailPasswordPlugin) -> EmailPasswordPlugin {
        if profile == "email-otp-transaction" {
            plugin.password_hasher(Arc::new(FixtureHasher))
        } else {
            plugin
        }
    }

    pub(super) fn builder(
        &self,
        profile: &str,
        builder: AuthBuilder<TestSchema>,
    ) -> AuthBuilder<TestSchema> {
        if profile != "email-otp-transaction" {
            return builder;
        }
        builder
            .validate_user_info(Arc::new(self.clone()))
            .plugin(EmailOtpPlugin::new().generate_otp(Arc::new(|_, _| Some("123456".into()))))
    }

    pub(super) fn reset(&self) {
        *self.state.lock().unwrap() = State::default();
    }

    pub(super) fn router(&self, auth: Arc<BetterAuth<TestSchema>>) -> Router {
        let fixture = self.clone();
        Router::new().route("/__test/email-otp-transaction", post(move |Json(body): Json<Value>| {
            let fixture = fixture.clone();
            let auth = auth.clone();
            async move {
                if let Some(deny) = body["deny"].as_bool() {
                    fixture.state.lock().unwrap().deny = deny;
                }
                let email = body["email"].as_str().unwrap_or("missing@example.com");
                let identifier = format!("sign-in-otp-{}", email.to_lowercase());
                let record = auth.store().get_verification_including_expired(&identifier).await?;
                let otp = auth.email_otp()?.get(email, EmailOtpType::SignIn).await?;
                let exists = auth.store().get_user_by_email(email).await?.is_some();
                Ok::<_, AuthError>(Json(json!({
                    "events":fixture.state.lock().unwrap().events,
                    "otp":otp,"userExists":exists,
                    "identifierHashed":record.as_ref().map(|record|record.identifier!=identifier),
                })))
            }
        }))
    }
}
