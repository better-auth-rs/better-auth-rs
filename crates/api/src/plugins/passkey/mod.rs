use better_auth_core::{AuthContext, AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse};

use better_auth_core::utils::cookie_utils::create_session_cookie;

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
    #[config(default = "Better Auth".to_string())]
    pub rp_name: String,
    #[config(default = String::new())]
    pub origin: String,
    #[config(default = 300)]
    pub challenge_ttl_secs: i64,
}

// -- Plugin --

impl PasskeyPlugin {
    // -- Handlers (delegate to core functions) --

    /// GET /passkey/generate-register-options
    async fn handle_generate_register_options(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let passkey_name = req.query.get("name").map(|s| s.as_str());
        let authenticator_attachment = req.query.get("authenticatorAttachment").map(|s| s.as_str());
        let (result, cookie_header) = generate_register_options_core(
            &user,
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
        let (user, _session) = ctx.require_session(req).await?;
        let body: VerifyRegistrationRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        match verify_registration_core(&body, req, &user, &self.config, ctx).await? {
            PasskeyHandlerOutcome::Success(result) => {
                AuthResponse::json(200, &result).map_err(AuthError::from)
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
        let maybe_user = ctx.require_session(req).await.ok().map(|(u, _)| u);
        let (result, cookie_header) =
            generate_authenticate_options_core(maybe_user.as_ref(), &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &result)?.with_header("Set-Cookie", cookie_header))
    }

    /// POST /passkey/verify-authentication
    async fn handle_verify_authentication(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyAuthenticationRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let ip_address = req.headers.get("x-forwarded-for").cloned();
        let user_agent = req.headers.get("user-agent").cloned();
        match verify_authentication_core(&body, req, &self.config, ip_address, user_agent, ctx)
            .await?
        {
            PasskeyHandlerOutcome::Success((response, token)) => {
                let cookie_header = create_session_cookie(&token, &ctx.config);
                Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
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
        get  "/passkey/generate-register-options"      => handle_generate_register_options,      "passkey_generate_register_options";
        post "/passkey/verify-registration"            => handle_verify_registration,            "passkey_verify_registration";
        get  "/passkey/generate-authenticate-options"  => handle_generate_authenticate_options,  "passkey_generate_authenticate_options";
        post "/passkey/verify-authentication"          => handle_verify_authentication,          "passkey_verify_authentication";
        get  "/passkey/list-user-passkeys"             => handle_list_user_passkeys,             "passkey_list_user_passkeys";
        post "/passkey/delete-passkey"                 => handle_delete_passkey,                 "passkey_delete_passkey";
        post "/passkey/update-passkey"                 => handle_update_passkey,                 "passkey_update_passkey";
    }
}
