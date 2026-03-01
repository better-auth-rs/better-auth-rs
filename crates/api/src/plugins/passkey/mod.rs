use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::{AuthContext, AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse};

use better_auth_core::utils::cookie_utils::create_session_cookie;

pub(super) mod handlers;
pub(super) mod types;

#[cfg(test)]
mod tests;

use handlers::*;
use types::*;

/// Passkey / WebAuthn authentication plugin.
///
/// Generates WebAuthn-compatible registration and authentication options,
/// stores challenge state via `VerificationOps`, and manages passkey CRUD.
///
/// **WARNING: Simplified WebAuthn mode.**
/// This implementation does NOT perform full FIDO2 signature verification
/// (rpId, origin, authenticatorData, signature). It trusts the client-side
/// WebAuthn response after verifying the challenge round-trip. For production
/// use, integrate `webauthn-rs` or another FIDO2 library for full attestation
/// and assertion verification.
pub struct PasskeyPlugin {
    config: PasskeyConfig,
}

#[derive(Debug, Clone, better_auth_core::PluginConfig)]
#[plugin(name = "PasskeyPlugin")]
pub struct PasskeyConfig {
    #[config(default = "localhost".to_string())]
    pub rp_id: String,
    #[config(default = "Better Auth".to_string())]
    pub rp_name: String,
    #[config(default = "http://localhost:3000".to_string())]
    pub origin: String,
    #[config(default = 300)]
    pub challenge_ttl_secs: i64,
    /// Allows simplified (non-cryptographic) response verification.
    ///
    /// Keep disabled in production. This exists only for local development
    /// until full WebAuthn validation is integrated.
    #[config(default = false)]
    pub allow_insecure_unverified_assertion: bool,
}

// -- Plugin --

impl PasskeyPlugin {
    // -- Handlers (delegate to core functions) --

    /// GET /passkey/generate-register-options
    async fn handle_generate_register_options<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let authenticator_attachment = req.query.get("authenticatorAttachment").map(|s| s.as_str());
        let result =
            generate_register_options_core(&user, authenticator_attachment, &self.config, ctx)
                .await?;
        AuthResponse::json(200, &result).map_err(AuthError::from)
    }

    /// POST /passkey/verify-registration
    async fn handle_verify_registration<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let body: VerifyRegistrationRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let result = verify_registration_core(&body, &user, &self.config, ctx).await?;
        AuthResponse::json(200, &result).map_err(AuthError::from)
    }

    /// POST /passkey/generate-authenticate-options
    async fn handle_generate_authenticate_options<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let maybe_user = ctx.require_session(req).await.ok().map(|(u, _)| u);
        let result =
            generate_authenticate_options_core(maybe_user.as_ref(), &self.config, ctx).await?;
        AuthResponse::json(200, &result).map_err(AuthError::from)
    }

    /// POST /passkey/verify-authentication
    async fn handle_verify_authentication<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyAuthenticationRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let ip_address = req.headers.get("x-forwarded-for").cloned();
        let user_agent = req.headers.get("user-agent").cloned();
        let (response, token) =
            verify_authentication_core(&body, &self.config, ip_address, user_agent, ctx).await?;
        let cookie_header = create_session_cookie(&token, &ctx.config);
        Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
    }

    /// GET /passkey/list-user-passkeys
    async fn handle_list_user_passkeys<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let result = list_user_passkeys_core(&user, ctx).await?;
        AuthResponse::json(200, &result).map_err(AuthError::from)
    }

    /// POST /passkey/delete-passkey
    async fn handle_delete_passkey<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
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
    async fn handle_update_passkey<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
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
        post "/passkey/generate-authenticate-options"  => handle_generate_authenticate_options,  "passkey_generate_authenticate_options";
        post "/passkey/verify-authentication"          => handle_verify_authentication,          "passkey_verify_authentication";
        get  "/passkey/list-user-passkeys"             => handle_list_user_passkeys,             "passkey_list_user_passkeys";
        post "/passkey/delete-passkey"                 => handle_delete_passkey,                 "passkey_delete_passkey";
        post "/passkey/update-passkey"                 => handle_update_passkey,                 "passkey_update_passkey";
    }
}

// ---------------------------------------------------------------------------
// Axum integration
// ---------------------------------------------------------------------------

#[cfg(feature = "axum")]
mod axum_impl {
    use super::*;
    use std::sync::Arc;

    use axum::Json;
    use axum::extract::{Extension, Query, State};
    use axum::http::HeaderMap;
    use axum::http::header;
    use axum::response::IntoResponse;
    use better_auth_core::error::AuthError;
    use better_auth_core::extractors::{CurrentSession, OptionalSession, ValidatedJson};
    use better_auth_core::plugin::AuthState;

    #[derive(Clone)]
    struct PluginState {
        config: PasskeyConfig,
    }

    async fn handle_generate_register_options<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        Query(params): Query<RegisterOptionsQuery>,
    ) -> Result<Json<serde_json::Value>, AuthError> {
        let ctx = state.to_context();
        let result = generate_register_options_core(
            &user,
            params.authenticator_attachment.as_deref(),
            &ps.config,
            &ctx,
        )
        .await?;
        Ok(Json(result))
    }

    async fn handle_verify_registration<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<VerifyRegistrationRequest>,
    ) -> Result<Json<PasskeyView>, AuthError> {
        let ctx = state.to_context();
        let result = verify_registration_core(&body, &user, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_generate_authenticate_options<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        OptionalSession(maybe): OptionalSession<DB>,
    ) -> Result<Json<serde_json::Value>, AuthError> {
        let ctx = state.to_context();
        let maybe_user = maybe.as_ref().map(|s| &s.user);
        let result = generate_authenticate_options_core(maybe_user, &ps.config, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_verify_authentication<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        Extension(ps): Extension<Arc<PluginState>>,
        headers: HeaderMap,
        ValidatedJson(body): ValidatedJson<VerifyAuthenticationRequest>,
    ) -> Result<impl IntoResponse, AuthError> {
        let ip = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let ua = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let ctx = state.to_context();
        let (response, token) = verify_authentication_core(&body, &ps.config, ip, ua, &ctx).await?;
        let cookie = state.session_cookie(&token);
        Ok(([(header::SET_COOKIE, cookie)], Json(response)))
    }

    async fn handle_list_user_passkeys<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
    ) -> Result<Json<Vec<PasskeyView>>, AuthError> {
        let ctx = state.to_context();
        let result = list_user_passkeys_core(&user, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_delete_passkey<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<DeletePasskeyRequest>,
    ) -> Result<Json<crate::plugins::StatusResponse>, AuthError> {
        let ctx = state.to_context();
        let result = delete_passkey_core(&body, &user, &ctx).await?;
        Ok(Json(result))
    }

    async fn handle_update_passkey<DB: DatabaseAdapter>(
        State(state): State<AuthState<DB>>,
        CurrentSession { user, .. }: CurrentSession<DB>,
        ValidatedJson(body): ValidatedJson<UpdatePasskeyRequest>,
    ) -> Result<Json<PasskeyResponse>, AuthError> {
        let ctx = state.to_context();
        let result = update_passkey_core(&body, &user, &ctx).await?;
        Ok(Json(result))
    }

    impl<DB: DatabaseAdapter> better_auth_core::AxumPlugin<DB> for PasskeyPlugin {
        fn name(&self) -> &'static str {
            "passkey"
        }

        fn router(&self) -> axum::Router<AuthState<DB>> {
            use axum::routing::{get, post};

            let plugin_state = Arc::new(PluginState {
                config: self.config.clone(),
            });
            axum::Router::new()
                .route(
                    "/passkey/generate-register-options",
                    get(handle_generate_register_options::<DB>),
                )
                .route(
                    "/passkey/verify-registration",
                    post(handle_verify_registration::<DB>),
                )
                .route(
                    "/passkey/generate-authenticate-options",
                    post(handle_generate_authenticate_options::<DB>),
                )
                .route(
                    "/passkey/verify-authentication",
                    post(handle_verify_authentication::<DB>),
                )
                .route(
                    "/passkey/list-user-passkeys",
                    get(handle_list_user_passkeys::<DB>),
                )
                .route("/passkey/delete-passkey", post(handle_delete_passkey::<DB>))
                .route("/passkey/update-passkey", post(handle_update_passkey::<DB>))
                .layer(Extension(plugin_state))
        }
    }
}
