use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use validator::Validate;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthPasskey, AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, CreatePasskey, CreateVerification, HttpMethod};

use better_auth_core::utils::cookie_utils::create_session_cookie;

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

#[derive(Debug, Clone)]
pub struct PasskeyConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub origin: String,
    pub challenge_ttl_secs: i64,
    /// Allows simplified (non-cryptographic) response verification.
    ///
    /// Keep disabled in production. This exists only for local development
    /// until full WebAuthn validation is integrated.
    pub allow_insecure_unverified_assertion: bool,
}

impl Default for PasskeyConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "Better Auth".to_string(),
            origin: "http://localhost:3000".to_string(),
            challenge_ttl_secs: 300, // 5 minutes
            allow_insecure_unverified_assertion: false,
        }
    }
}

// -- Request types --

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct VerifyRegistrationRequest {
    response: serde_json::Value,
    name: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct VerifyAuthenticationRequest {
    response: serde_json::Value,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct DeletePasskeyRequest {
    #[validate(length(min = 1))]
    id: String,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct UpdatePasskeyRequest {
    #[validate(length(min = 1))]
    id: String,
    #[validate(length(min = 1))]
    name: String,
}

// -- Response helpers --

#[derive(Debug, Serialize)]
struct PasskeyView {
    id: String,
    name: String,
    #[serde(rename = "credentialID")]
    credential_id: String,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    counter: u64,
    #[serde(rename = "deviceType")]
    device_type: String,
    #[serde(rename = "backedUp")]
    backed_up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    transports: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
}

impl PasskeyView {
    fn from_entity(pk: &impl AuthPasskey) -> Self {
        Self {
            id: pk.id().to_string(),
            name: pk.name().to_string(),
            credential_id: pk.credential_id().to_string(),
            user_id: pk.user_id().to_string(),
            public_key: pk.public_key().to_string(),
            counter: pk.counter(),
            device_type: pk.device_type().to_string(),
            backed_up: pk.backed_up(),
            transports: pk.transports().map(|s| s.to_string()),
            created_at: pk.created_at().to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize)]
struct SessionUserResponse<U: Serialize, S: Serialize> {
    session: S,
    user: U,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    status: bool,
}

#[derive(Debug, Serialize)]
struct PasskeyResponse {
    passkey: PasskeyView,
}

// -- Plugin --

impl PasskeyPlugin {
    pub fn new() -> Self {
        Self {
            config: PasskeyConfig::default(),
        }
    }

    pub fn with_config(config: PasskeyConfig) -> Self {
        Self { config }
    }

    pub fn rp_id(mut self, rp_id: impl Into<String>) -> Self {
        self.config.rp_id = rp_id.into();
        self
    }

    pub fn rp_name(mut self, rp_name: impl Into<String>) -> Self {
        self.config.rp_name = rp_name.into();
        self
    }

    pub fn origin(mut self, origin: impl Into<String>) -> Self {
        self.config.origin = origin.into();
        self
    }

    pub fn allow_insecure_unverified_assertion(mut self, allow: bool) -> Self {
        self.config.allow_insecure_unverified_assertion = allow;
        self
    }

    // -- Helpers --

    fn generate_challenge() -> String {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn ensure_insecure_verification_enabled(&self) -> AuthResult<()> {
        if self.config.allow_insecure_unverified_assertion {
            Ok(())
        } else {
            Err(AuthError::not_implemented(
                "Passkey verification requires full WebAuthn signature validation. \
                Set `allow_insecure_unverified_assertion = true` only for local development.",
            ))
        }
    }

    fn decode_client_data_json(response: &serde_json::Value) -> AuthResult<serde_json::Value> {
        let encoded = response
            .get("response")
            .and_then(|r| r.get("clientDataJSON"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::bad_request("Missing clientDataJSON in response"))?;

        let decode_and_parse = |bytes: Vec<u8>| -> Option<serde_json::Value> {
            serde_json::from_slice::<serde_json::Value>(&bytes).ok()
        };

        if let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded)
            && let Some(client_data) = decode_and_parse(bytes)
        {
            return Ok(client_data);
        }

        if let Ok(bytes) = STANDARD.decode(encoded)
            && let Some(client_data) = decode_and_parse(bytes)
        {
            return Ok(client_data);
        }

        Err(AuthError::bad_request("Invalid clientDataJSON encoding"))
    }

    fn validate_client_data(
        &self,
        client_data: &serde_json::Value,
        expected_type: &str,
    ) -> AuthResult<String> {
        let client_type = client_data
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::bad_request("Missing clientDataJSON.type"))?;

        if client_type != expected_type {
            return Err(AuthError::bad_request(format!(
                "Invalid clientDataJSON.type, expected {}",
                expected_type
            )));
        }

        let origin = client_data
            .get("origin")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::bad_request("Missing clientDataJSON.origin"))?;

        if origin != self.config.origin {
            return Err(AuthError::bad_request("Invalid clientDataJSON.origin"));
        }

        let challenge = client_data
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::bad_request("Missing clientDataJSON.challenge"))?;

        Ok(challenge.to_string())
    }

    // -- Handlers --

    /// GET /passkey/generate-register-options
    async fn handle_generate_register_options<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;

        let challenge = Self::generate_challenge();

        // Store challenge as a verification token
        let identifier = format!("passkey_reg:{}", user.id());
        let expires_at =
            chrono::Utc::now() + chrono::Duration::seconds(self.config.challenge_ttl_secs);
        ctx.database
            .create_verification(CreateVerification {
                identifier: identifier.clone(),
                value: challenge.clone(),
                expires_at,
            })
            .await?;

        // Build excludeCredentials from existing passkeys
        let existing_passkeys = ctx.database.list_passkeys_by_user(user.id()).await?;
        let exclude_credentials: Vec<serde_json::Value> = existing_passkeys
            .iter()
            .map(|pk| {
                let mut cred = serde_json::json!({
                    "type": "public-key",
                    "id": pk.credential_id(),
                });
                if let Some(transports) = pk.transports()
                    && let Ok(t) = serde_json::from_str::<Vec<String>>(transports)
                {
                    cred["transports"] = serde_json::json!(t);
                }
                cred
            })
            .collect();

        // Read optional authenticatorAttachment from query params
        let authenticator_attachment = req
            .query
            .get("authenticatorAttachment")
            .cloned()
            .unwrap_or_else(|| "platform".to_string());

        let user_id_b64 = URL_SAFE_NO_PAD.encode(user.id().as_bytes());
        let display_name = user
            .name()
            .unwrap_or_else(|| user.email().unwrap_or("user"));
        let user_name = user
            .email()
            .unwrap_or_else(|| user.name().unwrap_or("user"));

        let options = serde_json::json!({
            "challenge": challenge,
            "rp": {
                "name": self.config.rp_name,
                "id": self.config.rp_id,
            },
            "user": {
                "id": user_id_b64,
                "name": user_name,
                "displayName": display_name,
            },
            "pubKeyCredParams": [
                { "type": "public-key", "alg": -7 },
                { "type": "public-key", "alg": -257 },
            ],
            "timeout": 60000,
            "excludeCredentials": exclude_credentials,
            "authenticatorSelection": {
                "authenticatorAttachment": authenticator_attachment,
                "requireResidentKey": false,
                "userVerification": "preferred",
            },
            "attestation": "none",
        });

        AuthResponse::json(200, &options).map_err(AuthError::from)
    }

    /// POST /passkey/verify-registration
    async fn handle_verify_registration<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        self.ensure_insecure_verification_enabled()?;
        let (user, _session) = ctx.require_session(req).await?;

        let body: VerifyRegistrationRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let client_data = Self::decode_client_data_json(&body.response)?;
        let challenge = self.validate_client_data(&client_data, "webauthn.create")?;

        // Atomically consume the challenge (single-use)
        let identifier = format!("passkey_reg:{}", user.id());
        ctx.database
            .consume_verification(&identifier, &challenge)
            .await?
            .ok_or_else(|| {
                AuthError::bad_request(
                    "Invalid or expired registration challenge. Please generate registration options again.",
                )
            })?;

        // Extract credential data from the client response
        let resp = &body.response;
        let credential_id = resp
            .get("id")
            .or_else(|| resp.get("rawId"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::bad_request("Missing credential id in response"))?;

        // Extract public key from attestation response
        // In a simplified approach, we store the clientDataJSON as the public key representation
        let public_key = resp
            .get("response")
            .and_then(|r| r.get("attestationObject"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                resp.get("response")
                    .and_then(|r| r.get("clientDataJSON"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("")
            .to_string();

        // Extract device type and backup info from authenticator data or client extensions
        let authenticator_attachment = resp
            .get("authenticatorAttachment")
            .and_then(|v| v.as_str())
            .unwrap_or("platform");

        let device_type = if authenticator_attachment == "cross-platform" {
            "multiDevice"
        } else {
            "singleDevice"
        }
        .to_string();

        let backed_up = resp
            .get("clientExtensionResults")
            .and_then(|v| v.get("credProps"))
            .and_then(|v| v.get("rk"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Extract transports if available
        let transports = resp
            .get("response")
            .and_then(|r| r.get("transports"))
            .map(|v| v.to_string());

        let passkey_name = body
            .name
            .unwrap_or_else(|| format!("Passkey {}", chrono::Utc::now().format("%Y-%m-%d")));

        // Create the passkey
        let passkey = ctx
            .database
            .create_passkey(CreatePasskey {
                user_id: user.id().to_string(),
                name: passkey_name,
                credential_id: credential_id.to_string(),
                public_key,
                counter: 0,
                device_type,
                backed_up,
                transports,
            })
            .await?;

        let view = PasskeyView::from_entity(&passkey);
        AuthResponse::json(200, &view).map_err(AuthError::from)
    }

    /// POST /passkey/generate-authenticate-options
    async fn handle_generate_authenticate_options<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let challenge = Self::generate_challenge();

        // If user is authenticated, build allowCredentials from their passkeys
        let allow_credentials: Vec<serde_json::Value> =
            if let Ok((user, _session)) = ctx.require_session(req).await {
                let passkeys = ctx.database.list_passkeys_by_user(user.id()).await?;
                passkeys
                    .iter()
                    .map(|pk| {
                        let mut cred = serde_json::json!({
                            "type": "public-key",
                            "id": pk.credential_id(),
                        });
                        if let Some(transports) = pk.transports()
                            && let Ok(t) = serde_json::from_str::<Vec<String>>(transports)
                        {
                            cred["transports"] = serde_json::json!(t);
                        }
                        cred
                    })
                    .collect()
            } else {
                vec![]
            };

        // Store challenge with the challenge itself as part of the identifier
        let identifier = format!("passkey_auth:{}", challenge);
        let expires_at =
            chrono::Utc::now() + chrono::Duration::seconds(self.config.challenge_ttl_secs);
        ctx.database
            .create_verification(CreateVerification {
                identifier,
                value: challenge.clone(),
                expires_at,
            })
            .await?;

        let options = serde_json::json!({
            "challenge": challenge,
            "timeout": 60000,
            "rpId": self.config.rp_id,
            "allowCredentials": allow_credentials,
            "userVerification": "preferred",
        });

        AuthResponse::json(200, &options).map_err(AuthError::from)
    }

    /// POST /passkey/verify-authentication
    async fn handle_verify_authentication<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        self.ensure_insecure_verification_enabled()?;
        let body: VerifyAuthenticationRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let resp = &body.response;

        // Extract credential_id from the response
        let credential_id = resp
            .get("id")
            .or_else(|| resp.get("rawId"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::bad_request("Missing credential id in response"))?;

        let client_data = Self::decode_client_data_json(resp)?;
        let challenge = self.validate_client_data(&client_data, "webauthn.get")?;

        // Atomically consume challenge so it cannot be replayed.
        let identifier = format!("passkey_auth:{}", challenge);
        ctx.database
            .consume_verification(&identifier, &challenge)
            .await?
            .ok_or_else(|| AuthError::bad_request("Invalid or expired authentication challenge"))?;

        // Look up the passkey by credential_id
        let passkey = ctx
            .database
            .get_passkey_by_credential_id(credential_id)
            .await?
            .ok_or_else(|| AuthError::bad_request("Passkey not found for credential"))?;

        // Look up the user
        let user = ctx
            .database
            .get_user_by_id(passkey.user_id())
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Update the passkey counter
        let new_counter = passkey
            .counter()
            .checked_add(1)
            .ok_or_else(|| AuthError::internal("Passkey counter overflow"))?;
        ctx.database
            .update_passkey_counter(passkey.id(), new_counter)
            .await?;

        // Create a session
        let ip_address = req.headers.get("x-forwarded-for").cloned();
        let user_agent = req.headers.get("user-agent").cloned();
        let session_manager =
            better_auth_core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager
            .create_session(&user, ip_address, user_agent)
            .await?;

        let cookie_header = create_session_cookie(session.token(), ctx);
        let response = SessionUserResponse { session, user };
        Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
    }

    /// GET /passkey/list-user-passkeys
    async fn handle_list_user_passkeys<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;

        let passkeys = ctx.database.list_passkeys_by_user(user.id()).await?;
        let views: Vec<PasskeyView> = passkeys.iter().map(PasskeyView::from_entity).collect();

        AuthResponse::json(200, &views).map_err(AuthError::from)
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

        // Verify ownership
        let passkey = ctx
            .database
            .get_passkey_by_id(&body.id)
            .await?
            .ok_or_else(|| AuthError::not_found("Passkey not found"))?;

        if passkey.user_id() != user.id() {
            return Err(AuthError::not_found("Passkey not found"));
        }

        ctx.database.delete_passkey(&body.id).await?;

        let response = StatusResponse { status: true };
        AuthResponse::json(200, &response).map_err(AuthError::from)
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

        // Verify ownership
        let passkey = ctx
            .database
            .get_passkey_by_id(&body.id)
            .await?
            .ok_or_else(|| AuthError::not_found("Passkey not found"))?;

        if passkey.user_id() != user.id() {
            return Err(AuthError::not_found("Passkey not found"));
        }

        let updated = ctx
            .database
            .update_passkey_name(&body.id, &body.name)
            .await?;

        let response = PasskeyResponse {
            passkey: PasskeyView::from_entity(&updated),
        };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }
}

impl Default for PasskeyPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<DB: DatabaseAdapter> AuthPlugin<DB> for PasskeyPlugin {
    fn name(&self) -> &'static str {
        "passkey"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get(
                "/passkey/generate-register-options",
                "passkey_generate_register_options",
            ),
            AuthRoute::post(
                "/passkey/verify-registration",
                "passkey_verify_registration",
            ),
            AuthRoute::post(
                "/passkey/generate-authenticate-options",
                "passkey_generate_authenticate_options",
            ),
            AuthRoute::post(
                "/passkey/verify-authentication",
                "passkey_verify_authentication",
            ),
            AuthRoute::get("/passkey/list-user-passkeys", "passkey_list_user_passkeys"),
            AuthRoute::post("/passkey/delete-passkey", "passkey_delete_passkey"),
            AuthRoute::post("/passkey/update-passkey", "passkey_update_passkey"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get, "/passkey/generate-register-options") => {
                Ok(Some(self.handle_generate_register_options(req, ctx).await?))
            }
            (HttpMethod::Post, "/passkey/verify-registration") => {
                Ok(Some(self.handle_verify_registration(req, ctx).await?))
            }
            (HttpMethod::Post, "/passkey/generate-authenticate-options") => Ok(Some(
                self.handle_generate_authenticate_options(req, ctx).await?,
            )),
            (HttpMethod::Post, "/passkey/verify-authentication") => {
                Ok(Some(self.handle_verify_authentication(req, ctx).await?))
            }
            (HttpMethod::Get, "/passkey/list-user-passkeys") => {
                Ok(Some(self.handle_list_user_passkeys(req, ctx).await?))
            }
            (HttpMethod::Post, "/passkey/delete-passkey") => {
                Ok(Some(self.handle_delete_passkey(req, ctx).await?))
            }
            (HttpMethod::Post, "/passkey/update-passkey") => {
                Ok(Some(self.handle_update_passkey(req, ctx).await?))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::adapters::{
        MemoryDatabaseAdapter, PasskeyOps, SessionOps, UserOps, VerificationOps,
    };
    use better_auth_core::{CreateSession, CreateUser, CreateVerification, Session, User};
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    async fn create_test_context_with_user() -> (AuthContext<MemoryDatabaseAdapter>, User, Session)
    {
        let config = Arc::new(better_auth_core::AuthConfig::new(
            "test-secret-key-at-least-32-chars-long",
        ));
        let database = Arc::new(MemoryDatabaseAdapter::new());
        let ctx = AuthContext::new(config, database.clone());

        let user = database
            .create_user(
                CreateUser::new()
                    .with_email("passkey-test@example.com")
                    .with_name("Passkey Tester"),
            )
            .await
            .unwrap();

        let session = database
            .create_session(CreateSession {
                user_id: user.id.clone(),
                expires_at: Utc::now() + Duration::hours(1),
                ip_address: Some("127.0.0.1".to_string()),
                user_agent: Some("test-agent".to_string()),
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();

        (ctx, user, session)
    }

    fn create_auth_request(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> AuthRequest {
        let mut headers = HashMap::new();
        if let Some(token) = token {
            headers.insert("authorization".to_string(), format!("Bearer {}", token));
        }
        headers.insert("content-type".to_string(), "application/json".to_string());

        AuthRequest::from_parts(
            method,
            path.to_string(),
            headers,
            body.map(|b| serde_json::to_vec(&b).unwrap()),
            HashMap::new(),
        )
    }

    fn encoded_client_data(challenge: &str, client_type: &str, origin: &str) -> String {
        let client_data = serde_json::json!({
            "type": client_type,
            "challenge": challenge,
            "origin": origin,
        });
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&client_data).unwrap())
    }

    #[tokio::test]
    async fn test_verify_registration_requires_insecure_opt_in() {
        let plugin = PasskeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "response": {
                "id": "cred-1",
                "response": {
                    "clientDataJSON": encoded_client_data("challenge-1", "webauthn.create", "http://localhost:3000"),
                }
            }
        });

        let req = create_auth_request(
            HttpMethod::Post,
            "/passkey/verify-registration",
            Some(&session.token),
            Some(body),
        );

        let err = plugin
            .handle_verify_registration(&req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 501);
    }

    #[tokio::test]
    async fn test_verify_registration_consumes_exact_challenge_once() {
        let plugin = PasskeyPlugin::new().allow_insecure_unverified_assertion(true);
        let (ctx, user, session) = create_test_context_with_user().await;

        let challenge = "register-challenge";
        let identifier = format!("passkey_reg:{}", user.id);

        ctx.database
            .create_verification(CreateVerification {
                identifier: identifier.clone(),
                value: challenge.to_string(),
                expires_at: Utc::now() + Duration::minutes(5),
            })
            .await
            .unwrap();

        let wrong_body = serde_json::json!({
            "response": {
                "id": "cred-reg-1",
                "response": {
                    "clientDataJSON": encoded_client_data("wrong-challenge", "webauthn.create", "http://localhost:3000"),
                    "attestationObject": "fake-attestation",
                }
            }
        });
        let wrong_req = create_auth_request(
            HttpMethod::Post,
            "/passkey/verify-registration",
            Some(&session.token),
            Some(wrong_body),
        );
        let err = plugin
            .handle_verify_registration(&wrong_req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 400);

        assert!(
            ctx.database
                .get_verification(&identifier, challenge)
                .await
                .unwrap()
                .is_some()
        );

        let ok_body = serde_json::json!({
            "response": {
                "id": "cred-reg-1",
                "response": {
                    "clientDataJSON": encoded_client_data(challenge, "webauthn.create", "http://localhost:3000"),
                    "attestationObject": "fake-attestation",
                }
            }
        });
        let ok_req = create_auth_request(
            HttpMethod::Post,
            "/passkey/verify-registration",
            Some(&session.token),
            Some(ok_body),
        );
        let response = plugin
            .handle_verify_registration(&ok_req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);

        assert!(
            ctx.database
                .get_verification(&identifier, challenge)
                .await
                .unwrap()
                .is_none()
        );

        let passkeys = ctx.database.list_passkeys_by_user(&user.id).await.unwrap();
        assert_eq!(passkeys.len(), 1);
    }

    #[tokio::test]
    async fn test_verify_authentication_checks_type_origin_and_prevents_replay() {
        let plugin = PasskeyPlugin::new().allow_insecure_unverified_assertion(true);
        let (ctx, user, _session) = create_test_context_with_user().await;

        let credential_id = "cred-auth-1";
        ctx.database
            .create_passkey(CreatePasskey {
                user_id: user.id.clone(),
                name: "Authenticator".to_string(),
                credential_id: credential_id.to_string(),
                public_key: "fake-public-key".to_string(),
                counter: 0,
                device_type: "singleDevice".to_string(),
                backed_up: false,
                transports: None,
            })
            .await
            .unwrap();

        let challenge = "auth-challenge-1";
        let identifier = format!("passkey_auth:{}", challenge);

        ctx.database
            .create_verification(CreateVerification {
                identifier: identifier.clone(),
                value: challenge.to_string(),
                expires_at: Utc::now() + Duration::minutes(5),
            })
            .await
            .unwrap();

        let wrong_type_body = serde_json::json!({
            "response": {
                "id": credential_id,
                "response": {
                    "clientDataJSON": encoded_client_data(challenge, "webauthn.create", "http://localhost:3000"),
                }
            }
        });
        let wrong_type_req = create_auth_request(
            HttpMethod::Post,
            "/passkey/verify-authentication",
            None,
            Some(wrong_type_body),
        );
        let err = plugin
            .handle_verify_authentication(&wrong_type_req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 400);

        let wrong_origin_body = serde_json::json!({
            "response": {
                "id": credential_id,
                "response": {
                    "clientDataJSON": encoded_client_data(challenge, "webauthn.get", "http://evil.example"),
                }
            }
        });
        let wrong_origin_req = create_auth_request(
            HttpMethod::Post,
            "/passkey/verify-authentication",
            None,
            Some(wrong_origin_body),
        );
        let err = plugin
            .handle_verify_authentication(&wrong_origin_req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 400);

        assert!(
            ctx.database
                .get_verification(&identifier, challenge)
                .await
                .unwrap()
                .is_some()
        );

        let ok_body = serde_json::json!({
            "response": {
                "id": credential_id,
                "response": {
                    "clientDataJSON": encoded_client_data(challenge, "webauthn.get", "http://localhost:3000"),
                }
            }
        });
        let ok_req = create_auth_request(
            HttpMethod::Post,
            "/passkey/verify-authentication",
            None,
            Some(ok_body.clone()),
        );
        let response = plugin
            .handle_verify_authentication(&ok_req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);

        assert!(
            ctx.database
                .get_verification(&identifier, challenge)
                .await
                .unwrap()
                .is_none()
        );

        let replay_req = create_auth_request(
            HttpMethod::Post,
            "/passkey/verify-authentication",
            None,
            Some(ok_body),
        );
        let err = plugin
            .handle_verify_authentication(&replay_req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 400);

        let passkey = ctx
            .database
            .get_passkey_by_credential_id(credential_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(passkey.counter(), 1);
    }

    #[tokio::test]
    async fn test_generate_register_options_returns_challenge_and_stores_verification() {
        let plugin = PasskeyPlugin::new();
        let (ctx, user, session) = create_test_context_with_user().await;

        let req = create_auth_request(
            HttpMethod::Get,
            "/passkey/generate-register-options",
            Some(&session.token),
            None,
        );

        let response = plugin
            .handle_generate_register_options(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);

        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["challenge"].is_string());
        assert_eq!(body["rp"]["id"], "localhost");
        assert_eq!(body["rp"]["name"], "Better Auth");
        assert!(body["user"]["id"].is_string());
        assert!(body["pubKeyCredParams"].is_array());
        assert!(body["excludeCredentials"].is_array());

        // Verify challenge was stored
        let challenge = body["challenge"].as_str().unwrap();
        let identifier = format!("passkey_reg:{}", user.id);
        let verification = ctx
            .database
            .get_verification(&identifier, challenge)
            .await
            .unwrap();
        assert!(verification.is_some());
    }

    #[tokio::test]
    async fn test_generate_register_options_unauthenticated() {
        let plugin = PasskeyPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let req = create_auth_request(
            HttpMethod::Get,
            "/passkey/generate-register-options",
            None,
            None,
        );

        let err = plugin
            .handle_generate_register_options(&req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn test_generate_authenticate_options_returns_challenge() {
        let plugin = PasskeyPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        // No auth required for this endpoint
        let req = create_auth_request(
            HttpMethod::Post,
            "/passkey/generate-authenticate-options",
            None,
            None,
        );

        let response = plugin
            .handle_generate_authenticate_options(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);

        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["challenge"].is_string());
        assert_eq!(body["rpId"], "localhost");
        assert!(body["allowCredentials"].is_array());
        assert_eq!(body["allowCredentials"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_generate_authenticate_options_with_auth_includes_credentials() {
        let plugin = PasskeyPlugin::new();
        let (ctx, user, session) = create_test_context_with_user().await;

        // Create a passkey for the user
        ctx.database
            .create_passkey(CreatePasskey {
                user_id: user.id.clone(),
                name: "Test Key".to_string(),
                credential_id: "cred-gen-auth-1".to_string(),
                public_key: "pk".to_string(),
                counter: 0,
                device_type: "singleDevice".to_string(),
                backed_up: false,
                transports: Some("[\"usb\"]".to_string()),
            })
            .await
            .unwrap();

        let req = create_auth_request(
            HttpMethod::Post,
            "/passkey/generate-authenticate-options",
            Some(&session.token),
            None,
        );

        let response = plugin
            .handle_generate_authenticate_options(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);

        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        let allow = body["allowCredentials"].as_array().unwrap();
        assert_eq!(allow.len(), 1);
        assert_eq!(allow[0]["id"], "cred-gen-auth-1");
    }

    #[tokio::test]
    async fn test_list_user_passkeys() {
        let plugin = PasskeyPlugin::new();
        let (ctx, user, session) = create_test_context_with_user().await;

        // No passkeys yet
        let req = create_auth_request(
            HttpMethod::Get,
            "/passkey/list-user-passkeys",
            Some(&session.token),
            None,
        );
        let response = plugin.handle_list_user_passkeys(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
        let body: Vec<serde_json::Value> = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.len(), 0);

        // Create a passkey
        ctx.database
            .create_passkey(CreatePasskey {
                user_id: user.id.clone(),
                name: "My Key".to_string(),
                credential_id: "cred-list-1".to_string(),
                public_key: "pk".to_string(),
                counter: 0,
                device_type: "singleDevice".to_string(),
                backed_up: false,
                transports: None,
            })
            .await
            .unwrap();

        let response = plugin.handle_list_user_passkeys(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
        let body: Vec<serde_json::Value> = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body.len(), 1);
        assert_eq!(body[0]["name"], "My Key");
        assert_eq!(body[0]["credentialID"], "cred-list-1");
    }

    #[tokio::test]
    async fn test_list_user_passkeys_unauthenticated() {
        let plugin = PasskeyPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let req = create_auth_request(HttpMethod::Get, "/passkey/list-user-passkeys", None, None);
        let err = plugin
            .handle_list_user_passkeys(&req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    #[tokio::test]
    async fn test_delete_passkey_success() {
        let plugin = PasskeyPlugin::new();
        let (ctx, user, session) = create_test_context_with_user().await;

        let passkey = ctx
            .database
            .create_passkey(CreatePasskey {
                user_id: user.id.clone(),
                name: "To Delete".to_string(),
                credential_id: "cred-del-1".to_string(),
                public_key: "pk".to_string(),
                counter: 0,
                device_type: "singleDevice".to_string(),
                backed_up: false,
                transports: None,
            })
            .await
            .unwrap();

        let body = serde_json::json!({ "id": passkey.id });
        let req = create_auth_request(
            HttpMethod::Post,
            "/passkey/delete-passkey",
            Some(&session.token),
            Some(body),
        );

        let response = plugin.handle_delete_passkey(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Verify deleted
        let result = ctx.database.get_passkey_by_id(&passkey.id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_passkey_non_owner_rejected() {
        let plugin = PasskeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        // Create another user's passkey
        let other_user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("other@example.com")
                    .with_name("Other User"),
            )
            .await
            .unwrap();

        let passkey = ctx
            .database
            .create_passkey(CreatePasskey {
                user_id: other_user.id.clone(),
                name: "Other's Key".to_string(),
                credential_id: "cred-other-del".to_string(),
                public_key: "pk".to_string(),
                counter: 0,
                device_type: "singleDevice".to_string(),
                backed_up: false,
                transports: None,
            })
            .await
            .unwrap();

        let body = serde_json::json!({ "id": passkey.id });
        let req = create_auth_request(
            HttpMethod::Post,
            "/passkey/delete-passkey",
            Some(&session.token),
            Some(body),
        );

        let err = plugin.handle_delete_passkey(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 404);

        // Verify NOT deleted
        let result = ctx.database.get_passkey_by_id(&passkey.id).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_update_passkey_success() {
        let plugin = PasskeyPlugin::new();
        let (ctx, user, session) = create_test_context_with_user().await;

        let passkey = ctx
            .database
            .create_passkey(CreatePasskey {
                user_id: user.id.clone(),
                name: "Old Name".to_string(),
                credential_id: "cred-upd-1".to_string(),
                public_key: "pk".to_string(),
                counter: 0,
                device_type: "singleDevice".to_string(),
                backed_up: false,
                transports: None,
            })
            .await
            .unwrap();

        let body = serde_json::json!({ "id": passkey.id, "name": "New Name" });
        let req = create_auth_request(
            HttpMethod::Post,
            "/passkey/update-passkey",
            Some(&session.token),
            Some(body),
        );

        let response = plugin.handle_update_passkey(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let resp_body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(resp_body["passkey"]["name"], "New Name");

        // Verify persisted
        let updated = ctx
            .database
            .get_passkey_by_id(&passkey.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.name(), "New Name");
    }

    #[tokio::test]
    async fn test_update_passkey_non_owner_rejected() {
        let plugin = PasskeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let other_user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("other-upd@example.com")
                    .with_name("Other"),
            )
            .await
            .unwrap();

        let passkey = ctx
            .database
            .create_passkey(CreatePasskey {
                user_id: other_user.id.clone(),
                name: "Other's Key".to_string(),
                credential_id: "cred-other-upd".to_string(),
                public_key: "pk".to_string(),
                counter: 0,
                device_type: "singleDevice".to_string(),
                backed_up: false,
                transports: None,
            })
            .await
            .unwrap();

        let body = serde_json::json!({ "id": passkey.id, "name": "Hijacked" });
        let req = create_auth_request(
            HttpMethod::Post,
            "/passkey/update-passkey",
            Some(&session.token),
            Some(body),
        );

        let err = plugin.handle_update_passkey(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 404);

        // Verify unchanged
        let unchanged = ctx
            .database
            .get_passkey_by_id(&passkey.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.name(), "Other's Key");
    }

    #[tokio::test]
    async fn test_expired_challenge_rejected() {
        let plugin = PasskeyPlugin::new().allow_insecure_unverified_assertion(true);
        let (ctx, user, session) = create_test_context_with_user().await;

        let challenge = "expired-challenge";
        let identifier = format!("passkey_reg:{}", user.id);

        // Create an already-expired verification
        ctx.database
            .create_verification(CreateVerification {
                identifier: identifier.clone(),
                value: challenge.to_string(),
                expires_at: Utc::now() - Duration::seconds(1),
            })
            .await
            .unwrap();

        let body = serde_json::json!({
            "response": {
                "id": "cred-exp-1",
                "response": {
                    "clientDataJSON": encoded_client_data(challenge, "webauthn.create", "http://localhost:3000"),
                    "attestationObject": "fake",
                }
            }
        });
        let req = create_auth_request(
            HttpMethod::Post,
            "/passkey/verify-registration",
            Some(&session.token),
            Some(body),
        );

        let err = plugin
            .handle_verify_registration(&req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    #[tokio::test]
    async fn test_verify_authentication_requires_insecure_opt_in() {
        let plugin = PasskeyPlugin::new(); // default: insecure=false
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "response": {
                "id": "cred-1",
                "response": {
                    "clientDataJSON": encoded_client_data("c", "webauthn.get", "http://localhost:3000"),
                }
            }
        });

        let req = create_auth_request(
            HttpMethod::Post,
            "/passkey/verify-authentication",
            None,
            Some(body),
        );

        let err = plugin
            .handle_verify_authentication(&req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 501);
    }

    #[tokio::test]
    async fn test_memory_passkey_list_is_sorted_by_created_at_desc() {
        let (ctx, user, _session) = create_test_context_with_user().await;

        let first = ctx
            .database
            .create_passkey(CreatePasskey {
                user_id: user.id.clone(),
                name: "first".to_string(),
                credential_id: "cred-sort-1".to_string(),
                public_key: "pk-1".to_string(),
                counter: 0,
                device_type: "singleDevice".to_string(),
                backed_up: false,
                transports: None,
            })
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(2)).await;

        let second = ctx
            .database
            .create_passkey(CreatePasskey {
                user_id: user.id.clone(),
                name: "second".to_string(),
                credential_id: "cred-sort-2".to_string(),
                public_key: "pk-2".to_string(),
                counter: 0,
                device_type: "singleDevice".to_string(),
                backed_up: false,
                transports: None,
            })
            .await
            .unwrap();

        let listed = ctx.database.list_passkeys_by_user(&user.id).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id(), second.id());
        assert_eq!(listed[1].id(), first.id());
    }
}
