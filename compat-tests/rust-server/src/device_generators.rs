use std::sync::{Arc, Mutex};
use axum::{Json, Router, routing::post};
use better_auth::plugins::DeviceAuthorizationPlugin;
use better_auth_core::{AuthResponse, AuthResult};
use better_auth_seaorm::sea_orm::{DatabaseConnection, EntityTrait};
use better_auth_seaorm::store::entities::device_code;
use serde_json::{Value, json};

#[derive(Default)]
struct State { mode: String, events: Vec<String>, issued: usize }
#[derive(Clone, Default)]
pub(super) struct DeviceGenerators(Arc<Mutex<State>>);
impl DeviceGenerators {
    pub(super) fn reset(&self) { *self.0.lock().unwrap() = State::default(); }
    pub(super) fn apply(&self, profile: &str, plugin: DeviceAuthorizationPlugin) -> DeviceAuthorizationPlugin {
        if profile != "device-generators" { return plugin; }
        let device = self.clone(); let user = self.clone(); let validate = self.clone(); let hook = self.clone();
        plugin.validate_client(move |client| { let fixture = validate.clone(); async move {
            fixture.0.lock().unwrap().events.push("validate".into()); Ok(client != "deny")
        }}).on_device_auth_request(move |_, _| { let fixture = hook.clone(); async move {
            fixture.0.lock().unwrap().events.push("request".into()); Ok(())
        }}).generate_device_code_with(move || { let fixture = device.clone(); async move { fixture.generate("device").await } })
            .generate_user_code_with(move || { let fixture = user.clone(); async move { fixture.generate("user").await } })
    }
    async fn generate(&self, kind: &str) -> AuthResult<String> {
        let (mode, issued) = { let mut state = self.0.lock().unwrap(); state.events.push(format!("{kind}:start")); if kind == "device" {state.issued += 1;} (state.mode.clone(),state.issued) };
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        self.0.lock().unwrap().events.push(format!("{kind}:end"));
        if mode == format!("{kind}-error") { return Err(AuthResponse::json(500, &json!({"message":format!("{kind} generator failed")}))?.into()); }
        if mode == format!("{kind}-long") { return Ok("😀".repeat(192)); }
        if mode == "unicode" { return Ok("😀".repeat(191)); }
        if mode == "empty" { return Ok(String::new()); }
        if mode == "collision" && kind == "user" { return Ok("same-user".into()); }
        Ok(format!("async-{kind}-{issued}"))
    }
    pub(super) fn router(&self, database: DatabaseConnection) -> Router {
        let fixture = self.clone();
        Router::new().route("/__test/device-generators", post(move |Json(body):Json<Value>| { let fixture=fixture.clone();let database=database.clone();async move {
            {let mut state=fixture.0.lock().unwrap();if let Some(mode)=body["mode"].as_str(){state.mode=mode.into();}if body["clear"]==true{state.events.clear();}}
            let rows = device_code::Entity::find().all(&database).await.unwrap().len();
            Json(json!({"events":fixture.0.lock().unwrap().events,"rows":rows}))
        }}))
    }
}
