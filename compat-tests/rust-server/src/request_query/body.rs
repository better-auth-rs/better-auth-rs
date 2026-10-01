use better_auth_core::hooks::{RequestHookContext, current_request_hook_context};
use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookControl, DatabaseHooks,
};
use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, BeforeRequestAction,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(super) struct BodyTrace(pub Arc<Mutex<Vec<Value>>>);

impl BodyTrace {
    pub(super) fn record(
        &self,
        phase: &str,
        context: Option<&RequestHookContext>,
        response: Option<&AuthResponse>,
    ) {
        let Some(context) = context.filter(|context| {
            matches!(
                context.path.as_str(),
                "/sign-in/email"
                    | "/sign-up/email"
                    | "/request-password-reset"
                    | "/change-password"
                    | "/verify-password"
                    | "/sign-out"
                    | "/revoke-session"
                    | "/unlink-account"
                    | "/change-email"
                    | "/delete-user"
                    | "/get-access-token"
                    | "/refresh-token"
            )
        }) else {
            return;
        };
        let request = context
            .request
            .original_request()
            .or_else(|| context.is_http.then_some(&context.request));
        let error = response
            .and_then(|response| serde_json::from_slice::<Value>(&response.body).ok())
            .and_then(|value| value.get("code").cloned());
        self.0.lock().unwrap().push(json!({
            "phase":phase, "body":context.body, "request":request.is_some(),
            "requestBody":request.and_then(|request| request.body.as_ref()).map(|bytes| std::str::from_utf8(bytes).unwrap()),
            "errorCode":error,
        }));
    }
    pub(super) fn current(&self, phase: &str, response: Option<&AuthResponse>) {
        self.record(phase, current_request_hook_context().as_ref(), response);
    }
}

pub(super) struct BodyBefore(pub BodyTrace);
#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for BodyBefore {
    fn name(&self) -> &'static str {
        "request-body-before"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_database_hook(Arc::new(self.0.clone()));
        Ok(())
    }
    async fn before_request(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.0.current("before", None);
        Ok((request.path() == "/sign-in/email" && request.headers.get("x-body-mode").map(String::as_str) == Some("replace"))
            .then(|| BeforeRequestAction::MergeContext(better_auth_core::endpoint_input::EndpointInputPatch {
                body: Some(json!({"password":"fixture-password","callbackURL":"/replaced","added":"replacement"})),
                ..Default::default()
            })))
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for BodyTrace {
    async fn before_update_user(
        &self,
        _: &better_auth_core::UpdateUser,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<
        better_auth_core::store::database_hooks::DatabaseHookUpdate<better_auth_core::UpdateUser>,
    > {
        self.record("user.update.before", context.request.as_ref(), None);
        Ok(better_auth_core::store::database_hooks::DatabaseHookUpdate::Continue)
    }
    async fn after_update_user(
        &self,
        _: Option<&S::User>,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("user.update.after", context.request.as_ref(), None);
        Ok(())
    }

    async fn before_delete_session(
        &self,
        _: &S::Session,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("session.delete.before", context.request.as_ref(), None);
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_delete_session(
        &self,
        _: &S::Session,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("session.delete.after", context.request.as_ref(), None);
        Ok(())
    }
    async fn before_create_user(
        &self,
        _: &mut better_auth_core::CreateUser,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("user.before", context.request.as_ref(), None);
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_create_user(
        &self,
        _: &S::User,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("user.after", context.request.as_ref(), None);
        Ok(())
    }

    async fn before_create_session(
        &self,
        _: &mut better_auth_core::CreateSession,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("session.before", context.request.as_ref(), None);
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_create_session(
        &self,
        _: &S::Session,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("session.after", context.request.as_ref(), None);
        Ok(())
    }
}

#[async_trait::async_trait]
impl better_auth::plugins::SendResetPassword for BodyTrace {
    async fn send(&self, _: &Value, _: &str, _: &str) -> AuthResult<()> {
        self.current("sender", None);
        Ok(())
    }
}
