use super::TestSchema;
use axum::{Json, Router, routing::post};
use better_auth::plugins::admin::{
    AdminConfig, AdminPlugin, BannedUserMessage, access::RolePermissions,
};
use better_auth::seaorm::{SeaOrmHookContext, SeaOrmHooks};
use better_auth::{AuthError, AuthResult, BetterAuth};
use better_auth_core::{AuthPlugin, AuthRequest, AuthUser, FieldValue, HttpMethod, UpdateUser};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct State {
    mode: String,
    after_mode: String,
    events: Vec<Value>,
}
#[derive(Clone, Default)]
pub(super) struct AdminOptionsFixture {
    state: Arc<Mutex<State>>,
}

fn rejection(code: &'static str, message: &'static str) -> AuthError {
    AuthError::Upstream {
        status: 400,
        code,
        message,
    }
}

impl AdminOptionsFixture {
    pub(super) fn configure(&self, profile: &str, config: &mut better_auth_core::AuthConfig) {
        if !profile.starts_with("admin-") {
            return;
        }
        config.user.fields_mut().insert(
            "secretNote".into(),
            better_auth::config::UserFieldConfig {
                returned: Some(false),
                default_value: Some("admin-hidden".into()),
                ..Default::default()
            },
        );
    }
    pub(super) fn plugin(&self, profile: &str, plugin: AdminPlugin) -> AdminPlugin {
        if profile == "admin-empty-roles" {
            return plugin.roles(HashMap::new());
        }
        if profile != "admin-options" {
            return plugin;
        }
        let fixture = self.clone();
        plugin.admin_roles(vec!["admin".into()]).roles(HashMap::from([
            ("editor".into(), RolePermissions::new().allow("user", ["create", "get", "update", "impersonate"])),
            ("manager".into(), RolePermissions::new().allow("user", ["create", "get", "update", "set-role", "ban", "set-email", "impersonate", "impersonate-admins"])),
            ("admin".into(), RolePermissions::new().allow("user", ["create", "list", "get", "update", "set-role", "ban", "set-email", "impersonate", "impersonate-admins"])),
            ("user".into(), RolePermissions::new()),
        ])).banned_user_message(BannedUserMessage::callback(move |user| {
            let fixture = fixture.clone();
            Box::pin(async move {
                tokio::task::yield_now().await;
                let mode = {
                    let mut state = fixture.state.lock().unwrap();
                    state.events.push(json!({"event":"banned-message", "email":user.email, "reason":user.ban_reason, "secretNote":user.additional_fields.get("secretNote").map(FieldValue::json).transpose()?.flatten()}));
                    state.mode.clone()
                };
                match mode.as_str() {
                    "api-error" => Err(rejection("ADMIN_CALLBACK_REJECTED", "Admin callback rejected")),
                    "ordinary-error" => Err(AuthError::internal("private admin callback failure")),
                    _ => Ok(format!("Blocked: {}/{}", user.email.display_string()?, user.additional_fields.get("secretNote").and_then(FieldValue::as_str).unwrap_or_default())),
                }
            })
        }))
    }
    pub(super) fn reset(&self) {
        *self.state.lock().unwrap() = State::default();
    }
    pub(super) fn hooks(&self) -> Arc<dyn SeaOrmHooks<TestSchema>> {
        Arc::new(self.clone())
    }
    pub(super) fn router(&self, auth: Arc<BetterAuth<TestSchema>>) -> Router {
        let fixture = self.clone();
        Router::new().route("/__test/admin-options", post(move |Json(body): Json<Value>| {
            let fixture = fixture.clone(); let auth = auth.clone();
            async move {
                { let mut state = fixture.state.lock().unwrap();
                  if let Some(mode) = body.get("mode").and_then(Value::as_str) { state.mode = mode.into(); }
                  if let Some(mode) = body.get("afterMode").and_then(Value::as_str) { state.after_mode = mode.into(); }
                  if body.get("clear") == Some(&Value::Bool(true)) { state.events.clear(); }
                }
                if body.get("action").and_then(Value::as_str) == Some("validate") {
                    let options = body.get("options").cloned().unwrap_or_else(|| json!({}));
                    let mut config = AdminConfig::default();
                    if let Some(roles) = options.get("roles").and_then(Value::as_object) {
                        config.roles = Some(roles.keys().map(|name| (name.clone(), RolePermissions::new())).collect());
                    }
                    if let Some(roles) = options.get("adminRoles") { config.admin_roles = Some(serde_json::from_value(roles.clone())?); }
                    return Ok::<_, AuthError>(Json(match config.validate() {
                        Ok(()) => json!({"valid":true}),
                        Err(error) => {
                            let message = error.to_string();
                            json!({"valid":false,"message":message.strip_prefix("Configuration error: ").unwrap_or(&message)})
                        }
                    }));
                }
                match body.get("action").and_then(Value::as_str) {
                    Some("native-create") => {
                        let input = serde_json::from_value(body.get("input").cloned().unwrap_or(Value::Null))?;
                        let headers: Option<HashMap<String, String>> = body.get("headers").map(|value| serde_json::from_value(value.clone())).transpose()?;
                        let result = auth.admin()?.create_user(&input, headers.as_ref()).await;
                        return Ok(Json(match result {
                            Ok(user) => json!({"result":user}),
                            Err(error) => native_error(error)?,
                        }));
                    }
                    Some("native-sign-in") => {
                        let mut request = AuthRequest::new(HttpMethod::Post, "/sign-in/email");
                        request.body = Some(serde_json::to_vec(&body.get("input"))?);
                        let result = better_auth_core::with_request_hook_context(&request,
                            better_auth::plugins::EmailPasswordPlugin::new().on_request(&request, auth.context())
                        ).await;
                        return Ok(Json(match result {
                            Ok(Some(response)) => json!({"result":serde_json::from_slice::<Value>(&response.body.bytes()?)?}),
                            Ok(None) => return Err(AuthError::internal("Native sign-in route did not match")),
                            Err(error) => native_error(error)?,
                        }));
                    }
                    _ => {}
                }
                let mut user = match body.get("email").and_then(Value::as_str) { Some(email) => auth.store().get_user_by_email(email).await?, None => None };
                if let (Some(existing), Some(patch)) = (&user, body.get("patch")) {
                    user = Some(auth.store().update_user(existing.id().typed().unwrap(), UpdateUser {
                        role: patch.get("role").and_then(Value::as_str).map(str::to_owned),
                        banned: patch.get("banned").and_then(Value::as_bool),
                        ban_reason: patch.get("banReason").map(|value| serde_json::from_value(value.clone())).transpose()?,
                        ban_expires: patch.get("banExpires").map(|value| {
                            serde_json::from_value::<Option<chrono::DateTime<chrono::Utc>>>(value.clone())
                                .map(|date| date.map(Into::into))
                        }).transpose()?,
                        ..Default::default()
                    }).await?);
                }
                let sessions = match &user { Some(user) => auth.store().get_user_sessions(user.id().typed().unwrap()).await?.len(), None => 0 };
                let events = fixture.state.lock().unwrap().events.clone();
                let user = match user.as_ref() { Some(user) => Some(auth.context().internal_user_view(user).await?), None => None };
                let user = user.map(|user| Ok::<_, AuthError>(json!({"email":user.email,"role":user.role,"name":user.name,"banned":user.banned,"banReason":user.ban_reason,"hasBanExpires":user.ban_expires.is_truthy()?,"secretNote":user.additional_fields.get("secretNote").map(FieldValue::json).transpose()?.flatten()}))).transpose()?;
                Ok(Json(json!({"events":events,"user":user,"sessions":sessions})))
            }
        }))
    }
}

fn native_error(error: AuthError) -> AuthResult<Value> {
    if let AuthError::Internal(message) = error {
        return Ok(json!({"error":{"kind":"error","message":message}}));
    }
    let response = error.to_auth_response();
    let body = if response.body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&response.body.bytes()?)?
    };
    Ok(json!({"error":{"kind":"api","status":response.status,"body":body}}))
}

#[better_auth::database_hooks()]
impl SeaOrmHooks<TestSchema> for AdminOptionsFixture {
    async fn after_update_user(
        &self,
        user: Option<&better_auth_core::wire::UserView>,
        ctx: &SeaOrmHookContext<'_, TestSchema>,
    ) -> AuthResult<()> {
        let Some(user) = user else {
            return Ok(());
        };
        if !ctx.request.as_ref().is_some_and(|request| {
            request.path.as_deref() == Some("/admin/update-user")
                && request
                    .body
                    .as_object()
                    .and_then(|body| body.get("data"))
                    .and_then(FieldValue::as_object)
                    .and_then(|data| data.get("banned"))
                    == Some(&FieldValue::Bool(true))
        }) {
            return Ok(());
        }
        let query = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT COUNT(*) AS count FROM sessions WHERE user_id = ?",
            [user.id().typed()?.to_string().into()],
        );
        let row = match ctx.tx {
            Some(tx) => tx.query_one_raw(query).await,
            None => ctx.db.query_one_raw(query).await,
        }
        .map_err(|error| AuthError::internal(error.to_string()))?;
        let sessions: i64 = row
            .ok_or_else(|| AuthError::internal("Missing session count"))?
            .try_get("", "count")
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let mode = {
            let mut state = self.state.lock().unwrap();
            state
                .events
                .push(json!({"event":"user-updated","banned":user.banned(),"sessions":sessions}));
            state.after_mode.clone()
        };
        if mode == "reject" {
            return Err(rejection("AFTER_UPDATE_REJECTED", "After update rejected"));
        }
        Ok(())
    }
}
