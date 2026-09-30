use axum::{routing::get, Json, Router};
use better_auth::plugins::OneTapPlugin;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
pub(super) struct OneTapFixture {
    keys: Arc<Mutex<Value>>,
}

impl OneTapFixture {
    pub(super) fn plugin(&self, port: u16, profile: &str) -> OneTapPlugin {
        let plugin = OneTapPlugin::new()
            .google_jwks_url(format!("http://localhost:{port}/__test/one-tap-jwks"));
        if profile == "one-tap-options" {
            plugin
                .client_id(vec!["one-tap-client".into(), "one-tap-alternative".into()])
                .disable_signup(true)
        } else {
            plugin
        }
    }
    pub(super) async fn reset(&self) {
        *self.keys.lock().await = json!({ "keys": [] });
    }
    pub(super) fn router(&self) -> Router {
        let read = self.clone();
        let write = self.clone();
        Router::new().route(
            "/__test/one-tap-jwks",
            get(move || {
                let read = read.clone();
                async move { Json(read.keys.lock().await.clone()) }
            })
            .post(move |Json(keys): Json<Value>| {
                let write = write.clone();
                async move {
                    *write.keys.lock().await = keys;
                    Json(json!({"success": true}))
                }
            }),
        )
    }
}
