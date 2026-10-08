use super::TestSchema;
use axum::{Json, Router, routing::post};
use better_auth::{
    AuthError, AuthResult,
    plugins::{
        email_otp::{EmailOtpCallbacks, EmailOtpPlugin},
        endpoint_context::EndpointContext,
        phone_number::{PhoneNumberCallbacks, PhoneNumberPlugin},
    },
};
use better_auth_core::{AuthPlugin, AuthUser};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(super) struct OtpCallbacksFixture {
    events: Arc<Mutex<Vec<Value>>>,
}
impl OtpCallbacksFixture {
    fn event(&self, name: &str, data: Value, endpoint: &EndpointContext<'_, TestSchema>) {
        let request = endpoint.request;
        self.events.lock().unwrap().push(json!({
            "name":name, "data":data, "path":endpoint.path,
            "requestPath":request.map(|req| req.path()),
            "body":endpoint.body.json().expect("The callback body must serialize"), "header":request.and_then(|req| req.headers.get("x-callback-tag")),
            "basePath": endpoint.auth.config.base_path,
            "hasResponse":endpoint.response.is_some(),
            "sessionEmail":endpoint.session.as_ref().map(|(user,_)|&user.email),
        }));
    }
    fn fail(endpoint: &EndpointContext<'_, TestSchema>, name: &str) -> AuthResult<()> {
        if endpoint
            .request
            .and_then(|req| req.headers.get("x-callback-fail"))
            .map(String::as_str)
            == Some(name)
        {
            return Err(AuthError::Upstream {
                status: 400,
                code: "CALLBACK_REJECTED",
                message: "Callback rejected",
            });
        }
        Ok(())
    }
    pub(super) fn email(&self, profile: &str) -> impl AuthPlugin<TestSchema> {
        let generate = self.clone();
        let send = self.clone();
        EmailOtpPlugin::new().send_verification_on_sign_up(true)
            .override_default_email_verification(profile == "otp-callbacks-override")
            .change_email(true)
            .callbacks(EmailOtpCallbacks::<TestSchema>::default()
                .generate(move |email, kind, endpoint| {
                    generate.event("email.generate", json!({"email":email,"type":kind}), endpoint);
                    Self::fail(endpoint, "generate")?;
                    Ok(Some("123456".into()))
                })
                .send(move |message, endpoint| {
                    let fixture = send.clone();
                    let message = message.clone();
                    let endpoint = endpoint.to_owned();
                    Ok(Some(Box::pin(async move {
                        let endpoint = endpoint.as_endpoint();
                        let exists = match endpoint.transaction {
                            Some(transaction) => transaction.get_user_by_email(&message.email).await?,
                            None => endpoint.auth.database.get_user_by_email(&message.email).await?,
                        }.is_some();
                        fixture.event("email.send", json!({"email":message.email,"type":message.kind,"userExists":exists}), &endpoint);
                        Self::fail(&endpoint, "email-send")
                    })))
                }))
    }
    pub(super) fn phone(&self) -> impl AuthPlugin<TestSchema> {
        let send = self.clone();
        let reset = self.clone();
        let verify = self.clone();
        let verified = self.clone();
        PhoneNumberPlugin::new().sign_up_on_verification(|phone| format!("{phone}@phone.example.com"))
            .require_verification(true)
            .callbacks(PhoneNumberCallbacks::<TestSchema>::default()
                .send_otp(move |message, endpoint| { let fixture=send.clone(); let message=message.clone(); let endpoint=endpoint.to_owned(); Ok(Some(Box::pin(async move {
                    let endpoint=endpoint.as_endpoint();
                    let exists=endpoint.auth.database.get_user_by_phone_number(&message.phone_number).await?.is_some();
                    fixture.event("phone.send", json!({"phoneNumber":message.phone_number,"userExists":exists}), &endpoint);
                    Self::fail(&endpoint,"phone-send")
                }))) })
                .send_password_reset_otp(move |message, endpoint| { let fixture=reset.clone(); let message=message.clone(); let endpoint=endpoint.to_owned(); Ok(Some(Box::pin(async move {
                    let endpoint=endpoint.as_endpoint();
                    let exists=endpoint.auth.database.get_user_by_phone_number(&message.phone_number).await?.is_some();
                    fixture.event("phone.reset", json!({"phoneNumber":message.phone_number,"userExists":exists}), &endpoint);
                    Self::fail(&endpoint,"phone-reset")
                }))) })
                .verify_otp(move |message, endpoint| { let fixture=verify.clone(); Box::pin(async move {
                    fixture.event("phone.verify", json!({"phoneNumber":message.phone_number}), endpoint);
                    Self::fail(endpoint,"phone-verify")?;
                    Ok(message.code == "246810")
                }) })
                .on_verification(move |message, endpoint| { let fixture=verified.clone(); Box::pin(async move {
                    let user=endpoint.auth.database.get_user_by_id(message.user.id.typed().unwrap()).await?.unwrap();
                    fixture.event("phone.verified", json!({"phoneNumber":message.phone_number,"persistedVerified":user.phone_number_verified(),"name":message.user.name}), endpoint);
                    Self::fail(endpoint,"verified")
                }) }))
    }
    pub(super) async fn reset(&self) {
        self.events.lock().unwrap().clear();
    }
    pub(super) fn router(&self) -> Router {
        let fixture = self.clone();
        Router::new().route(
            "/__test/otp-callbacks",
            post(move |Json(body): Json<Value>| {
                let fixture = fixture.clone();
                async move {
                    let mut events = fixture.events.lock().unwrap();
                    if body["action"] == "clear" {
                        events.clear();
                    }
                    Json(json!(&*events))
                }
            }),
        )
    }
}
