use super::TestSchema;
use async_trait::async_trait;
use axum::{Json, Router, routing::post};
use better_auth::plugins::{
    EmailPasswordPlugin,
    anonymous::AnonymousPlugin,
    email_otp::{EmailOtpMessage, EmailOtpPlugin, SendEmailOtp},
    endpoint_context::EndpointContext,
    magic_link::{MagicLinkMessage, MagicLinkPlugin, SendMagicLink},
    phone_number::PhoneNumberPlugin,
    user_admission::{UserValidationData, UserValidationRejection, ValidateUserInfo},
};
use better_auth::{AuthBuilder, AuthError, AuthResult, BetterAuth};
use better_auth_core::{AuthUser, CreateUser, FieldValue, PasswordHasher, UpdateUser};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
#[derive(Default)]
struct State {
    mode: String,
    events: Vec<Value>,
    magic_url: Option<String>,
}
#[derive(Clone, Default)]
pub(super) struct UserAdmissionFixture {
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
impl ValidateUserInfo<TestSchema> for UserAdmissionFixture {
    async fn validate(
        &self,
        data: &UserValidationData,
        endpoint: &EndpointContext<'_, TestSchema>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        let exists = if let Some(email) = data.user.get("email").and_then(FieldValue::as_str) {
            match endpoint.transaction {
                Some(tx) => tx.get_user_by_email(email).await?.is_some(),
                None => endpoint
                    .auth
                    .database
                    .get_user_by_email(email)
                    .await?
                    .is_some(),
            }
        } else {
            false
        };
        let mode = {
            let user = data.user.json()?;
            let body = endpoint.body.json()?.unwrap_or(Value::Null);
            let mut state = self.state.lock().unwrap();
            state.events.push(json!({
            "source":data.source,"email":user.get("email"),"name":user.get("name"),
            "emailVerified":user.get("emailVerified"),"hasId":data.user.contains_key("id"),"hasCreatedAt":data.user.contains_key("createdAt"),
            "hasUpdatedAt":data.user.contains_key("updatedAt"),"role":user.get("role"),
            "existing":exists,"path":endpoint.path,"tag":endpoint.request.and_then(|request|request.headers.get("x-admission-tag")),
            "customBody":body.get("customBody"),"sessionEmail":endpoint.session.as_ref().and_then(|(user,_)|user.email.as_ref()),
            "username":user.get("username"),"bodyUsername":body.get("username"),"bodyDisplayUsername":body.get("displayUsername"),
        }));
            state.mode.clone()
        };
        if mode == "rollback" {
            let user = CreateUser::new()
                .with_email("admission-audit@example.com")
                .with_name("Audit");
            match endpoint.transaction {
                Some(tx) => {
                    let _ = tx.create_user(user).await?;
                }
                None => {
                    let _ = endpoint.auth.database.create_user(user).await?;
                }
            }
        }
        match mode.as_str() {
            "throw" => Err(AuthError::internal("private admission failure")),
            "deny" | "rollback" => Ok(Some(
                UserValidationRejection::new("application_denied")
                    .with_description("Application denied user"),
            )),
            "bare" => Ok(Some(UserValidationRejection::new("application_denied"))),
            "empty" => Ok(Some(UserValidationRejection::new(""))),
            _ => Ok(None),
        }
    }
}
#[async_trait]
impl SendEmailOtp for UserAdmissionFixture {
    async fn send(&self, _: &EmailOtpMessage) -> AuthResult<()> {
        Ok(())
    }
}
#[async_trait]
impl SendMagicLink for UserAdmissionFixture {
    async fn send(&self, message: &MagicLinkMessage) -> AuthResult<()> {
        self.state.lock().unwrap().magic_url = Some(message.url.clone());
        Ok(())
    }
}
impl UserAdmissionFixture {
    pub(super) fn password(
        &self,
        profile: &str,
        plugin: EmailPasswordPlugin,
    ) -> EmailPasswordPlugin {
        if !profile.starts_with("user-admission") {
            return plugin;
        }
        plugin
            .password_hasher(Arc::new(FixtureHasher))
            .auto_sign_in(profile != "user-admission-protected")
    }
    pub(super) fn builder(
        &self,
        profile: &str,
        builder: AuthBuilder<TestSchema>,
    ) -> AuthBuilder<TestSchema> {
        if !profile.starts_with("user-admission") {
            return builder;
        }
        builder
            .validate_user_info(Arc::new(self.clone()))
            .plugin(
                EmailOtpPlugin::new()
                    .generate_otp(Arc::new(|_, _| Some("123456".into())))
                    .sender(Arc::new(self.clone())),
            )
            .plugin(
                PhoneNumberPlugin::new()
                    .send_otp(|_, _| Box::pin(async { Ok(()) }))
                    .verify_otp(|message, _| Box::pin(async move { Ok(message.code == "246810") }))
                    .sign_up_on_verification(|phone| format!("{phone}@phone.example.com")),
            )
            .plugin(MagicLinkPlugin::new().custom_send_magic_link(Arc::new(self.clone())))
            .plugin(
                AnonymousPlugin::new().generate_name(|_| async { Ok("Admission Guest".into()) }),
            )
    }
    pub(super) fn reset(&self) {
        *self.state.lock().unwrap() = State::default();
    }
    pub(super) fn router(&self, auth: Arc<BetterAuth<TestSchema>>) -> Router {
        let fixture = self.clone();
        Router::new().route("/__test/user-admission",post(move |Json(body):Json<Value>|{let fixture=fixture.clone();let auth=auth.clone();async move{
            {let mut state=fixture.state.lock().unwrap();if let Some(mode)=body["mode"].as_str(){state.mode=mode.into();}if body["clear"]==true{state.events.clear();}}
            let user=match body["email"].as_str(){Some(email)=>auth.store().get_user_by_email(email).await?,None=>None};
            if body["promote"]==true {if let Some(user)=&user{let _=auth.store().update_user(user.id().typed().unwrap(),UpdateUser{role:Some("admin".into()),email_verified:Some(true),..Default::default()}).await?;}}
            let accounts=match &user{Some(user)=>auth.store().get_user_accounts(user.id().typed().unwrap()).await?,None=>vec![]};
            let audit=auth.store().get_user_by_email("admission-audit@example.com").await?.is_some();
            let state=fixture.state.lock().unwrap();
            Ok::<_,AuthError>(Json(json!({"events":state.events,"magicURL":state.magic_url,"exists":user.is_some(),"auditExists":audit,"accounts":accounts.iter().map(|account|json!({"providerId":account.provider_id,"accessToken":account.access_token})).collect::<Vec<_>>()})))
        }}))
    }
}
