use better_auth_core::{AuthContext, AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse};

mod callbacks;
mod options;
mod registration;
pub use callbacks::*;
pub use options::*;

pub(super) mod handlers;
pub(super) mod types;
pub(super) mod webauthn;

#[cfg(test)]
mod tests;

use handlers::*;
use types::*;

/// Passkey / WebAuthn authentication plugin.
///
/// Generates WebAuthn-compatible registration and authentication options,
/// stores challenge state via the auth store, and manages passkey CRUD.
pub struct PasskeyPlugin {
    config: PasskeyConfig,
}

#[derive(Debug, Clone, better_auth_core::PluginConfig)]
#[plugin(name = "PasskeyPlugin")]
pub struct PasskeyConfig {
    #[config(default = String::new())]
    pub rp_id: String,
    #[config(default = String::new())]
    pub rp_name: String,
    #[config(default = PasskeyOrigins::default(), skip)]
    pub origin: PasskeyOrigins,
    #[config(default = AuthenticatorSelection::default())]
    pub authenticator_selection: AuthenticatorSelection,
    #[config(default = "better-auth-passkey".to_owned())]
    pub web_authn_challenge_cookie: String,
    #[config(default = PasskeyRegistrationOptions::default())]
    pub registration: PasskeyRegistrationOptions,
    #[config(default = PasskeyAuthenticationOptions::default())]
    pub authentication: PasskeyAuthenticationOptions,
    #[config(default = 300)]
    pub challenge_ttl_secs: i64,
}

// -- Plugin --

impl PasskeyPlugin {
    pub fn origin(mut self, origin: impl Into<PasskeyOrigins>) -> Self {
        self.config.origin = origin.into();
        self
    }
    // -- Handlers (delegate to core functions) --

    /// GET /passkey/generate-register-options
    async fn handle_generate_register_options(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let passkey_name = req.query_string("name")?;
        let authenticator_attachment = req.query_string("authenticatorAttachment")?;
        if authenticator_attachment
            .is_some_and(|value| !matches!(value, "platform" | "cross-platform"))
        {
            return Err(AuthError::FieldInput { code: "VALIDATION_ERROR", message: "[query.authenticatorAttachment] Invalid option: expected one of \"platform\"|\"cross-platform\"".into() });
        }
        let user = registration::resolve_user(ctx, req, &self.config).await?;
        let (result, cookie_header) = generate_register_options_core(
            &user,
            req,
            passkey_name,
            authenticator_attachment,
            &self.config,
            ctx,
        )
        .await?;
        Ok(AuthResponse::json(200, &result)?.with_header("Set-Cookie", cookie_header))
    }

    /// POST /passkey/verify-registration
    async fn handle_verify_registration(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = match VerifyRegistrationRequest::parse(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let user = if self.config.registration.require_session {
            registration::registration_session(ctx, req, &self.config).await?
        } else {
            None
        };
        match registration::verify_registration_core(body, req, user, &self.config, ctx).await? {
            PasskeyHandlerOutcome::Success((result, token)) => {
                let response = AuthResponse::json(200, &result)?;
                if let Some(data) = token {
                    ctx.session_manager()
                        .set_session_cookie(req, data, None)
                        .await?;
                }
                Ok(response)
            }
            PasskeyHandlerOutcome::Response(response) => Ok(response),
        }
    }

    /// GET /passkey/generate-authenticate-options
    async fn handle_generate_authenticate_options(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let maybe_user = registration::optional_session(ctx, req).await?;
        let (result, cookie_header) =
            generate_authenticate_options_core(maybe_user.as_ref(), req, &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &result)?.with_header("Set-Cookie", cookie_header))
    }

    /// POST /passkey/verify-authentication
    async fn handle_verify_authentication(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = match VerifyAuthenticationRequest::parse(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let ip_address = ctx.config.advanced.ip_address.resolve(req);
        let user_agent = req.headers.get("user-agent").cloned();
        match verify_authentication_core(&body, req, &self.config, ip_address, user_agent, ctx)
            .await?
        {
            PasskeyHandlerOutcome::Success((response, data)) => {
                ctx.session_manager()
                    .set_session_cookie(req, data, None)
                    .await?;
                Ok(AuthResponse::json(200, &response)?)
            }
            PasskeyHandlerOutcome::Response(response) => Ok(response),
        }
    }

    /// GET /passkey/list-user-passkeys
    async fn handle_list_user_passkeys(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let result = list_user_passkeys_core(&user, ctx).await?;
        AuthResponse::json(200, &result).map_err(AuthError::from)
    }

    /// POST /passkey/delete-passkey
    async fn handle_delete_passkey(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let body: DeletePasskeyRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let result = delete_passkey_core(&body, &user, ctx).await?;
        AuthResponse::json(200, &result).map_err(AuthError::from)
    }

    /// POST /passkey/update-passkey
    async fn handle_update_passkey(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let body: UpdatePasskeyRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let result = update_passkey_core(&body, &user, ctx).await?;
        AuthResponse::json(200, &result).map_err(AuthError::from)
    }
}

better_auth_core::impl_auth_plugin! {
    PasskeyPlugin, "passkey";
    routes {
        get  "/passkey/generate-register-options"      => handle_generate_register_options,      "generatePasskeyRegistrationOptions", query = crate::plugins::query_input::passkey_registration;
        post "/passkey/verify-registration"            => handle_verify_registration,            "passkeyVerifyRegistration";
        get  "/passkey/generate-authenticate-options"  => handle_generate_authenticate_options,  "passkeyGenerateAuthenticateOptions";
        post "/passkey/verify-authentication"          => handle_verify_authentication,          "passkeyVerifyAuthentication";
        get  "/passkey/list-user-passkeys"             => handle_list_user_passkeys,             "listPasskeys";
        post "/passkey/delete-passkey"                 => handle_delete_passkey,                 "deletePasskey";
        post "/passkey/update-passkey"                 => handle_update_passkey,                 "updatePasskey";
    }
}
