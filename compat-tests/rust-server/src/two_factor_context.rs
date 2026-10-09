use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{Json, Router, routing::post};
use better_auth::plugins::two_factor::{TwoFactorCallbacks, TwoFactorPlugin};
use better_auth_core::{AuthError, AuthPlugin, AuthSchema, AuthUser};
use serde_json::{Value, json};

#[derive(Clone, Default)]
pub struct TwoFactorContextFixture {
    events: Arc<Mutex<Vec<Value>>>,
}

impl TwoFactorContextFixture {
    pub fn plugin<S: AuthSchema>(
        &self,
        profile: &str,
        plugin: TwoFactorPlugin,
        outbox: Arc<tokio::sync::Mutex<HashMap<String, String>>>,
    ) -> impl AuthPlugin<S> {
        let mut callbacks = TwoFactorCallbacks::<S>::default();
        if profile == "two-factor-context" {
            let fixture = self.clone();
            callbacks = callbacks.send(move |user, otp, endpoint| {
                let fixture = fixture.clone();
                let outbox = outbox.clone();
                let user = user.clone();
                let otp = otp.to_owned();
                let endpoint = endpoint.to_owned();
                Ok(Some(Box::pin(async move {
                    let endpoint = endpoint.as_endpoint();
                    let stored = endpoint.auth.database.get_user_by_id_value(user.model_property("id")?).await?.expect("callback user exists");
                    fixture.events.lock().unwrap().push(json!({
                        "user": { "id":user.model_property("id")?.json()?, "email":user.model_property("email")?.json()?, "secretNote":user.model_property("secretNote")?.json()? },
                        "databaseUser": { "id":stored.id(), "email":stored.email() },
                        "path": endpoint.path,
                        "requestPath": endpoint.request.map(|request| request.path()),
                        "body": endpoint.body.json()?,
                        "header": endpoint.request.and_then(|request| request.header("x-callback-tag")),
                        "sessionEmail": endpoint.session.as_ref().map(|data| data.user_field("email").json()).transpose()?.flatten(),
                        "hasResponse": endpoint.response.is_some(),
                        "otpLength": otp.len(),
                    }));
                    _ = outbox.lock().await.insert(user.model_property("email")?.as_str().expect("fixture email").to_owned(), otp.to_owned());
                    if endpoint.request.and_then(|request| request.header("x-callback-fail")).map(String::as_str) == Some("send") {
                        return Err(AuthError::Upstream { status: 503, code: "DELIVERY_UNAVAILABLE", message: "Fixture delivery unavailable" });
                    }
                    Ok(())
                })))
            });
        }
        plugin.callbacks(callbacks)
    }

    pub fn reset(&self) {
        self.events.lock().unwrap().clear();
    }

    pub fn router(&self) -> Router {
        let fixture = self.clone();
        Router::new().route(
            "/__test/two-factor-context",
            post(move |Json(body): Json<Value>| {
                let fixture = fixture.clone();
                async move {
                    if body.get("action").and_then(Value::as_str) == Some("clear") {
                        fixture.reset();
                    }
                    Json(fixture.events.lock().unwrap().clone())
                }
            }),
        )
    }
}
