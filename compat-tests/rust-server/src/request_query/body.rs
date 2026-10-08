use better_auth_core::hooks::{RequestHookContext, current_request_hook_context};
use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookControl, DatabaseHookUpdate, DatabaseHooks,
};
use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, BeforeRequestAction,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(super) struct BodyTrace(pub Arc<Mutex<Vec<Value>>>, pub Arc<Mutex<Vec<Value>>>);

impl BodyTrace {
    pub(super) fn record(
        &self,
        phase: &str,
        context: Option<&RequestHookContext>,
        response: Option<&AuthResponse>,
    ) {
        let Some(context) = context.filter(|context| {
            (context.path.as_deref().is_some_and(|path| {
                path.starts_with("/email-otp/")
                    || path.starts_with("/phone-number/")
                    || path.starts_with("/two-factor/")
                    || path.starts_with("/api-key/")
                    || path.starts_with("/admin/")
                    || path.starts_with("/organization/")
            })) || matches!(
                context.path.as_deref().unwrap_or_default(),
                "/sign-in/social"
                    | "/link-social"
                    | "/sign-in/email-otp"
                    | "/forget-password/email-otp"
                    | "/sign-in/phone-number"
                    | "/sign-in/email"
                    | "/sign-up/email"
                    | "/update-user"
                    | "/update-session"
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
                    | "/sign-in/username"
                    | "/is-username-available"
                    | "/one-time-token/verify"
                    | "/multi-session/set-active"
                    | "/multi-session/revoke"
                    | "/sign-in/magic-link"
                    | "/one-tap/callback"
                    | "/passkey/verify-registration"
                    | "/passkey/verify-authentication"
                    | "/passkey/update-passkey"
                    | "/passkey/delete-passkey"
                    | "/device/code"
                    | "/device/token"
                    | "/device/approve"
                    | "/device/deny"
                    | "/siwe/nonce"
                    | "/siwe/get-nonce"
                    | "/siwe/verify"
                    | "/send-verification-email"
            )
        }) else {
            return;
        };
        let request = context
            .request
            .original_request()
            .or_else(|| context.is_http.then_some(&context.request));
        let error = response
            .and_then(|response| {
                serde_json::from_slice::<Value>(
                    &response
                        .body
                        .bytes()
                        .expect("The fixture response must serialize"),
                )
                .ok()
            })
            .and_then(|value| value.get("code").cloned());
        self.0.lock().unwrap().push(json!({
            "phase":phase, "body":super::snapshot(&context.body.json().expect("The fixture body must serialize")), "request":request.is_some(),
            "requestBody":request.map(|request| std::str::from_utf8(request.body.as_deref().unwrap_or_default()).unwrap()),
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
        if request.path() == "/email-otp/send-verification-otp"
            && request.headers.contains_key("x-otp-patch")
        {
            return Ok(Some(BeforeRequestAction::MergeContext(
                better_auth_core::endpoint_input::EndpointInputPatch {
                    body: Some(json!({"email":"patched@test.com","type":"sign-in"})),
                    ..Default::default()
                },
            )));
        }
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
        _: &mut better_auth_core::FieldMap,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<
        better_auth_core::store::database_hooks::DatabaseHookUpdate<better_auth_core::FieldMap>,
    > {
        self.record("user.update.before", context.request.as_ref(), None);
        if context.request.as_ref().is_some_and(|request| {
            request.path.as_deref() == Some("/change-email")
                && request.headers.contains_key("x-user-update-cancel")
        }) {
            return Ok(better_auth_core::store::database_hooks::DatabaseHookUpdate::Cancel);
        }
        Ok(better_auth_core::store::database_hooks::DatabaseHookUpdate::Continue)
    }
    async fn after_update_user(
        &self,
        _: Option<&better_auth_core::wire::UserView>,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("user.update.after", context.request.as_ref(), None);
        Ok(())
    }

    async fn before_delete_session(
        &self,
        _: &better_auth_core::wire::SessionView,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("session.delete.before", context.request.as_ref(), None);
        Ok(DatabaseHookControl::Continue)
    }
    async fn after_delete_session(
        &self,
        _: &better_auth_core::wire::SessionView,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("session.delete.after", context.request.as_ref(), None);
        Ok(())
    }
    async fn before_create_user(
        &self,
        _: &mut better_auth_core::FieldMap,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<
        better_auth_core::store::database_hooks::DatabaseHookUpdate<better_auth_core::FieldMap>,
    > {
        self.record("user.before", context.request.as_ref(), None);
        Ok(better_auth_core::store::database_hooks::DatabaseHookUpdate::Continue)
    }
    async fn after_create_user(
        &self,
        _: Option<&better_auth_core::wire::UserView>,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.record("user.after", context.request.as_ref(), None);
        Ok(())
    }

    async fn before_create_session(
        &self,
        _: &mut better_auth_core::FieldMap,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<better_auth_core::FieldMap>> {
        self.record("session.before", context.request.as_ref(), None);
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_create_session(
        &self,
        _: Option<&better_auth_core::wire::SessionView>,
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

#[async_trait::async_trait]
impl better_auth_core::email::SendVerificationEmail for BodyTrace {
    async fn send(
        &self,
        user: &better_auth_core::wire::UserView,
        url: &str,
        token: &str,
    ) -> AuthResult<()> {
        self.current("email.sender", None);
        self.email("verification", user, None, url, token)
    }
}

impl BodyTrace {
    fn email(
        &self,
        kind: &str,
        user: &better_auth_core::wire::UserView,
        new_email: Option<&str>,
        url: &str,
        token: &str,
    ) -> AuthResult<()> {
        use base64::Engine;
        let context = current_request_hook_context().unwrap();
        if context.path.as_deref() != Some("/change-email") {
            return Ok(());
        }
        let claims: Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        let callback = url::Url::parse(url)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "callbackURL")
            .unwrap()
            .1
            .into_owned();
        self.1.lock().unwrap().push(json!({"kind":kind,"user":user,"newEmail":new_email,"claims":{"email":claims["email"],"updateTo":claims.get("updateTo"),"requestType":claims.get("requestType"),"expiresIn":claims["exp"].as_i64().unwrap()-claims["iat"].as_i64().unwrap()},"callback":callback,"request":context.is_http || context.request.original_request().is_some(),"cookieIssued":context.request.new_session()?.is_some()}));
        if context.headers.contains_key("x-email-fail") {
            return Err(better_auth_core::AuthError::internal(
                "fixture sender failure",
            ));
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl better_auth::plugins::SendChangeEmailConfirmation for BodyTrace {
    async fn send(
        &self,
        user: &better_auth_core::wire::UserView,
        new_email: &str,
        url: &str,
        token: &str,
    ) -> AuthResult<()> {
        self.current("email.confirmation", None);
        self.email("confirmation", user, Some(new_email), url, token)
    }
}

#[async_trait::async_trait]
impl better_auth::plugins::organization::hooks::OrganizationHooks for BodyTrace {
    async fn before_create_organization(
        &self,
        _: &mut better_auth_core::CreateOrganization,
        _: &better_auth_core::wire::UserView,
    ) -> AuthResult<()> {
        self.current("organization.create", None);
        Ok(())
    }
    async fn before_update_organization(
        &self,
        _: &mut better_auth_core::UpdateOrganization,
        _: better_auth::plugins::organization::hooks::OrganizationActor<'_>,
    ) -> AuthResult<()> {
        self.current("organization.update", None);
        Ok(())
    }
    async fn before_create_team(
        &self,
        _: &mut better_auth::plugins::organization::hooks::OrganizationTeamDraft,
        _: &better_auth::plugins::organization::types::OrganizationResponse,
        _: Option<&better_auth_core::wire::UserView>,
    ) -> AuthResult<()> {
        self.current("team.create", None);
        Ok(())
    }
    async fn before_update_team(
        &self,
        _: &mut better_auth_core::UpdateTeam,
        _: better_auth::plugins::organization::hooks::OrganizationTeamEvent<'_>,
    ) -> AuthResult<()> {
        self.current("team.update", None);
        Ok(())
    }
    async fn before_create_invitation(
        &self,
        _: &mut better_auth::plugins::organization::hooks::OrganizationInvitationDraft,
        _: better_auth::plugins::organization::hooks::OrganizationUser<'_>,
    ) -> AuthResult<()> {
        self.current("invitation.create", None);
        Ok(())
    }
}

#[async_trait::async_trait]
impl better_auth::plugins::SendMagicLink for BodyTrace {
    async fn send(&self, message: &better_auth::plugins::MagicLinkMessage) -> AuthResult<()> {
        self.current("magic.sender", None);
        let mut value = serde_json::to_value(message)?;
        value
            .as_object_mut()
            .unwrap()
            .insert("kind".into(), "magic".into());
        self.1.lock().unwrap().push(value);
        Ok(())
    }
}

#[async_trait::async_trait]
impl better_auth::plugins::api_key::ApiKeyDefaultPermissions for BodyTrace {
    async fn permissions(
        &self,
        _: &better_auth::FieldValue,
        _: better_auth::plugins::api_key::ApiKeyEndpoint<'_>,
    ) -> AuthResult<better_auth::plugins::api_key::ApiKeyPermissions> {
        self.current("key.permissions", None);
        Ok(std::collections::HashMap::from([(
            "record".into(),
            vec!["read".into()],
        )]))
    }
}

#[async_trait::async_trait]
impl better_auth::plugins::two_factor::SendTwoFactorOtp for BodyTrace {
    async fn send(&self, _: &better_auth_core::wire::UserView, otp: &str) -> AuthResult<()> {
        self.current("otp.sender", None);
        self.1.lock().unwrap().push(json!({"kind":"otp","otp":otp}));
        Ok(())
    }
}

#[async_trait::async_trait]
impl better_auth::plugins::email_otp::SendEmailOtp for BodyTrace {
    async fn send(
        &self,
        message: &better_auth::plugins::email_otp::EmailOtpMessage,
    ) -> AuthResult<()> {
        self.current("email.otp.sender", None);
        let mut value = serde_json::to_value(message)?;
        value
            .as_object_mut()
            .unwrap()
            .insert("kind".into(), "email-otp".into());
        self.1.lock().unwrap().push(value);
        Ok(())
    }
}
