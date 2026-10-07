use super::TestSchema;
use async_trait::async_trait;
use axum::{Json, Router, routing::post};
use better_auth::plugins::password_management::SendResetPassword;
use better_auth::plugins::user_management::{
    AfterDeleteUser, BeforeDeleteUser, SendDeleteAccountVerification,
};
use better_auth::plugins::{PasswordManagementPlugin, UserManagementPlugin};
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::{AuthRequest, CreateAccount, user_fields::UserFieldConfig, wire::UserView};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, Statement};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct State {
    events: Vec<Value>,
    reset_token: Option<String>,
    delete_token: Option<String>,
}
#[derive(Clone, Default)]
pub(super) struct AuthLifecycleFixture {
    state: Arc<Mutex<State>>,
}
impl AuthLifecycleFixture {
    fn record(&self, name: &str, user: &UserView, request: Option<&AuthRequest>) -> AuthResult<()> {
        self.state.lock().unwrap().events.push(json!({"name":name,"email":user.email,"userName":user.name,"image":user.image,
            "department":user.additional_fields.get("department"),"hasHidden":user.additional_fields.contains_key("secretNote"),
            "hasCreatedAt":true,"path":request.map(AuthRequest::path),"tag":request.and_then(|request|request.headers.get("x-lifecycle-tag"))}));
        if request
            .and_then(|request| request.headers.get("x-lifecycle-fail"))
            .map(String::as_str)
            == Some(name)
        {
            return Err(AuthError::Upstream {
                status: 400,
                code: "LIFECYCLE_REJECTED",
                message: "Lifecycle rejected",
            });
        }
        Ok(())
    }
    pub(super) fn configure(profile: &str, config: &mut AuthConfig) {
        if !profile.starts_with("auth-lifecycle") {
            return;
        }
        if profile == "auth-lifecycle-zero" {
            config.session.fresh_age = Some(Duration::zero());
        }
        for (name, returned, value) in [
            ("department", true, "ops"),
            ("secretNote", false, "internal"),
        ] {
            config.user.fields_mut().insert(
                name.into(),
                UserFieldConfig {
                    required: Some(false),
                    returned: Some(returned),
                    default_value: Some(value.into()),
                    ..Default::default()
                },
            );
        }
    }
    pub(super) fn password(
        &self,
        profile: &str,
        plugin: PasswordManagementPlugin,
    ) -> PasswordManagementPlugin {
        if !profile.starts_with("auth-lifecycle") {
            return plugin;
        }
        let fixture = self.clone();
        let mut plugin = plugin
            .send_reset_password(Arc::new(self.clone()))
            .password_hasher(Arc::new(LifecycleHasher))
            .revoke_sessions_on_password_reset(true)
            .on_password_reset(Arc::new(move |event| {
                let fixture = fixture.clone();
                Box::pin(async move {
                    fixture.record("reset-complete", &event.user, event.request.as_ref())
                })
            }));
        if profile == "auth-lifecycle-confirmation" {
            plugin = plugin.reset_password_token_expires_in(90.0);
        }
        if profile == "auth-lifecycle-zero" {
            plugin = plugin.reset_password_token_expires_in(0.0);
        }
        plugin
    }
    pub(super) fn users(
        &self,
        profile: &str,
        plugin: UserManagementPlugin,
    ) -> UserManagementPlugin {
        if !profile.starts_with("auth-lifecycle") {
            return plugin;
        }
        let plugin = plugin
            .delete_user_enabled(true)
            .before_delete(Arc::new(self.clone()))
            .after_delete(Arc::new(self.clone()));
        if profile == "auth-lifecycle-confirmation" {
            plugin.send_delete_account_verification(Arc::new(self.clone()))
        } else {
            plugin
        }
    }
    pub(super) async fn reset(&self) {
        *self.state.lock().unwrap() = State::default();
    }
    pub(super) fn router(
        &self,
        auth: Arc<BetterAuth<TestSchema>>,
        database: DatabaseConnection,
    ) -> Router {
        let fixture = self.clone();
        Router::new().route("/__test/auth-lifecycle",post(move |Json(body):Json<Value>| {
            let fixture=fixture.clone();let auth=auth.clone();let database=database.clone();
            async move {
                let result:AuthResult<Value>=async {
                    if body["action"]=="clear" {fixture.state.lock().unwrap().events.clear();}
                    let user_id=body["userId"].as_str().unwrap_or_default();
                    if body["action"]=="age" {
                        database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"UPDATE sessions SET created_at = ? WHERE user_id = ?",vec![(Utc::now()-Duration::days(2)).into(),user_id.into()])).await.map_err(|error|AuthError::internal(error.to_string()))?;
                    }
                    if body["action"]=="add-account" {
                        let account=auth.store().create_account(CreateAccount {
user_id: user_id.into(),
provider_id: "lifecycle".into(),
account_id: "lifecycle-account".into(),
access_token: Default::default(),
refresh_token: Default::default(),
id_token: Default::default(),
access_token_expires_at: Default::default(),
refresh_token_expires_at: Default::default(),
scope: Default::default(),
password: Default::default(),
..Default::default()
}).await?;
                        return Ok(json!({"accountId":account.id}));
                    }
                    let user=auth.store().get_user_by_id(user_id).await?;
                    let accounts=auth.store().get_user_accounts(user_id).await?;
                    let token=fixture.state.lock().unwrap().reset_token.clone();
                    let verification=match token {Some(token)=>auth.store().get_verification_by_identifier(&format!("reset-password:{token}")).await?,None=>None};
                    let state=fixture.state.lock().unwrap();
                    Ok(json!({"events":state.events,"resetToken":state.reset_token,"deleteToken":state.delete_token,"userExists":user.is_some(),"accounts":accounts.len(),
                        "resetLifetime":verification.map(|verification| Ok::<_,AuthError>(((*verification.expires_at.typed()? - *verification.created_at.typed()?).num_milliseconds()+500)/1000)).transpose()?}))
                }.await;
                match result {Ok(value)=>Json(value).into_response(),Err(error)=>(axum::http::StatusCode::INTERNAL_SERVER_ERROR,Json(json!({"error":error.to_string()}))).into_response()}
            }
        }))
    }
}
use axum::response::IntoResponse;
#[async_trait]
impl SendResetPassword for AuthLifecycleFixture {
    async fn send(&self, _user: &Value, _url: &str, _token: &str) -> AuthResult<()> {
        Err(AuthError::internal(
            "Lifecycle sender requires the request-aware entry point",
        ))
    }
    async fn send_with_request(
        &self,
        user: &Value,
        _url: &str,
        token: &str,
        request: Option<&AuthRequest>,
    ) -> AuthResult<()> {
        self.state.lock().unwrap().reset_token = Some(token.into());
        let user: UserView = serde_json::from_value(user.clone())?;
        self.record("reset-send", &user, request)
    }
}
#[async_trait]
impl SendDeleteAccountVerification for AuthLifecycleFixture {
    async fn send(
        &self,
        user: &UserView,
        _url: &str,
        token: &str,
        request: Option<&AuthRequest>,
    ) -> AuthResult<()> {
        self.state.lock().unwrap().delete_token = Some(token.into());
        self.record("delete-send", user, request)
    }
}
#[async_trait]
impl BeforeDeleteUser for AuthLifecycleFixture {
    async fn before_delete(
        &self,
        user: &UserView,
        request: Option<&AuthRequest>,
    ) -> AuthResult<()> {
        self.record("before-delete", user, request)
    }
}
#[async_trait]
impl AfterDeleteUser for AuthLifecycleFixture {
    async fn after_delete(&self, user: &UserView, request: Option<&AuthRequest>) -> AuthResult<()> {
        self.record("after-delete", user, request)
    }
}

struct LifecycleHasher;
#[async_trait]
impl better_auth_core::utils::password::PasswordHasher for LifecycleHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        Ok(format!("fixture:{password}"))
    }
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        Ok(hash == format!("fixture:{password}"))
    }
}
