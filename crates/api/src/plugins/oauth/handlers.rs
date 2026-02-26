use base64::Engine;
use chrono::{Duration, Utc};
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};
use sha2::{Digest, Sha256};

use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser, AuthVerification};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateAccount, CreateUser,
    CreateVerification, DatabaseAdapter, SessionManager, UpdateAccount, UpdateUser,
};

use super::encryption::{maybe_decrypt, maybe_encrypt};

use super::providers::OAuthConfig;
use super::types::{
    AccessTokenResponse, GetAccessTokenRequest, LinkSocialRequest, OAuthCallbackResponse,
    RefreshTokenRequest, RefreshTokenResponse, SocialSignInRequest, SocialSignInResponse,
};

fn generate_pkce() -> (String, String) {
    let verifier: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(43)
        .map(char::from)
        .collect();
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
    (verifier, challenge)
}

fn build_authorization_url(
    config: &OAuthConfig,
    provider_name: &str,
    callback_url: &str,
    scopes: Option<&[String]>,
    state: &str,
    code_challenge: &str,
    link_user_id: Option<&str>,
) -> AuthResult<String> {
    let provider = config
        .providers
        .get(provider_name)
        .ok_or_else(|| AuthError::bad_request(format!("Unknown provider: {}", provider_name)))?;

    let effective_scopes: Vec<&str> = scopes
        .map(|s| s.iter().map(|s| s.as_str()).collect())
        .unwrap_or_else(|| provider.scopes.iter().map(|s| s.as_str()).collect());
    let scope_str = effective_scopes.join(" ");

    let _ = link_user_id;

    let url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        provider.auth_url,
        urlencoding::encode(&provider.client_id),
        urlencoding::encode(callback_url),
        urlencoding::encode(&scope_str),
        urlencoding::encode(state),
        urlencoding::encode(code_challenge),
    );

    Ok(url)
}

pub async fn handle_social_sign_in<DB: DatabaseAdapter>(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let signin_req: SocialSignInRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };

    let provider_name = &signin_req.provider;

    // Verify provider exists
    if !config.providers.contains_key(provider_name) {
        return Err(AuthError::bad_request(format!(
            "Unknown provider: {}",
            provider_name
        )));
    }

    let callback_url = signin_req
        .callback_url
        .clone()
        .unwrap_or_else(|| format!("{}/callback/{}", ctx.config.base_url, provider_name));

    let (code_verifier, code_challenge) = generate_pkce();
    let state = uuid::Uuid::new_v4().to_string();

    let scopes = signin_req.scopes.as_deref();

    let provider = config.providers.get(provider_name).unwrap();
    let effective_scopes: Vec<String> = scopes
        .map(|s| s.to_vec())
        .unwrap_or_else(|| provider.scopes.clone());

    // Store state via verification
    let payload = serde_json::json!({
        "provider": provider_name,
        "callback_url": callback_url,
        "code_verifier": code_verifier,
        "link_user_id": null,
        "scopes": effective_scopes.join(" "),
    });

    ctx.database
        .create_verification(CreateVerification {
            identifier: format!("oauth:{}", state),
            value: payload.to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await?;

    let url = build_authorization_url(
        config,
        provider_name,
        &callback_url,
        signin_req.scopes.as_deref(),
        &state,
        &code_challenge,
        None,
    )?;

    let response = SocialSignInResponse {
        url,
        redirect: true,
    };

    AuthResponse::json(200, &response).map_err(AuthError::from)
}

pub async fn handle_callback<DB: DatabaseAdapter>(
    config: &OAuthConfig,
    provider_name: &str,
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    // Extract query params: code and state
    // They may be in req.query or embedded in the path as ?code=xxx&state=yyy
    let code = req
        .query
        .get("code")
        .cloned()
        .or_else(|| extract_query_param(req.path(), "code"))
        .ok_or_else(|| AuthError::bad_request("Missing code parameter"))?;

    let state = req
        .query
        .get("state")
        .cloned()
        .or_else(|| extract_query_param(req.path(), "state"))
        .ok_or_else(|| AuthError::bad_request("Missing state parameter"))?;

    // Look up state verification
    let verification = ctx
        .database
        .get_verification_by_identifier(&format!("oauth:{}", state))
        .await?
        .ok_or_else(|| AuthError::bad_request("Invalid or expired OAuth state"))?;

    let payload: serde_json::Value = serde_json::from_str(verification.value())
        .map_err(|e| AuthError::internal(format!("Invalid state payload: {}", e)))?;

    let stored_provider = payload["provider"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing provider in state"))?;

    if stored_provider != provider_name {
        return Err(AuthError::bad_request("Provider mismatch"));
    }

    let callback_url = payload["callback_url"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing callback_url in state"))?;

    let code_verifier = payload["code_verifier"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing code_verifier in state"))?;

    let link_user_id = payload["link_user_id"].as_str().map(String::from);

    let scopes = payload["scopes"].as_str().map(String::from);

    // Delete the verification now that we've used it
    ctx.database.delete_verification(verification.id()).await?;

    let provider = config
        .providers
        .get(provider_name)
        .ok_or_else(|| AuthError::bad_request(format!("Unknown provider: {}", provider_name)))?;

    // Exchange code for tokens
    let client = reqwest::Client::new();
    let token_resp = client
        .post(&provider.token_url)
        .header("Accept", "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", callback_url),
            ("client_id", &provider.client_id),
            ("client_secret", &provider.client_secret),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("Token exchange failed: {}", e)))?;

    if !token_resp.status().is_success() {
        let error_body = token_resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(AuthError::internal(format!(
            "Token exchange returned error: {}",
            error_body
        )));
    }

    let token_data: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to parse token response: {}", e)))?;

    let access_token = token_data["access_token"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing access_token in token response"))?;

    let refresh_token = token_data["refresh_token"].as_str().map(String::from);
    let id_token = token_data["id_token"].as_str().map(String::from);
    let expires_in = token_data["expires_in"].as_i64();

    // Fetch user info
    let user_info_resp = client
        .get(&provider.user_info_url)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to fetch user info: {}", e)))?;

    if !user_info_resp.status().is_success() {
        let error_body = user_info_resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(AuthError::internal(format!(
            "User info request failed: {}",
            error_body
        )));
    }

    let user_info_json: serde_json::Value = user_info_resp
        .json()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to parse user info: {}", e)))?;

    let user_info = (provider.map_user_info)(user_info_json)
        .map_err(|e| AuthError::internal(format!("Failed to map user info: {}", e)))?;

    let access_token_expires_at = expires_in.map(|secs| Utc::now() + Duration::seconds(secs));

    // If linking to an existing user
    if let Some(link_user_id) = link_user_id {
        // Verify user exists
        let user = ctx
            .database
            .get_user_by_id(&link_user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Check if account already exists for this provider
        if ctx
            .database
            .get_account(provider_name, &user_info.id)
            .await?
            .is_some()
        {
            return Err(AuthError::conflict(
                "This social account is already linked to a user",
            ));
        }

        // Create account link (encrypt tokens if configured)
        let encrypt = ctx.config.account.encrypt_oauth_tokens;
        let secret = &ctx.config.secret;
        ctx.database
            .create_account(CreateAccount {
                user_id: link_user_id,
                account_id: user_info.id,
                provider_id: provider_name.to_string(),
                access_token: maybe_encrypt(Some(access_token.to_string()), encrypt, secret)?,
                refresh_token: maybe_encrypt(refresh_token, encrypt, secret)?,
                id_token: maybe_encrypt(id_token, encrypt, secret)?,
                access_token_expires_at,
                refresh_token_expires_at: None,
                scope: scopes,
                password: None,
            })
            .await?;

        // Create session
        let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager.create_session(&user, None, None).await?;

        let response = OAuthCallbackResponse {
            token: session.token().to_string(),
            user,
        };

        let cookie_header = create_session_cookie(session.token(), ctx);
        return Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header));
    }

    // Check if an account already exists for this provider + account_id
    if let Some(existing_account) = ctx
        .database
        .get_account(provider_name, &user_info.id)
        .await?
    {
            let account_cfg = &ctx.config.account;
            let encrypt = account_cfg.encrypt_oauth_tokens;
            let secret = &ctx.config.secret;

            // Update tokens on the existing account (respects update_account_on_sign_in)
            if account_cfg.update_account_on_sign_in {
                ctx.database
                    .update_account(
                        existing_account.id(),
                        UpdateAccount {
                            access_token: maybe_encrypt(Some(access_token.to_string()), encrypt, secret)?,
                            refresh_token: maybe_encrypt(refresh_token.clone(), encrypt, secret)?,
                            id_token: maybe_encrypt(id_token.clone(), encrypt, secret)?,
                            access_token_expires_at,
                            scope: scopes,
                            ..Default::default()
                        },
                    )
                    .await?;
            }

            // Get the associated user
            let user = ctx
                .database
                .get_user_by_id(existing_account.user_id())
                .await?
                .ok_or(AuthError::UserNotFound)?;

        // Create session
        let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager.create_session(&user, None, None).await?;

        let response = OAuthCallbackResponse {
            token: session.token().to_string(),
            user,
        };

        let cookie_header = create_session_cookie(session.token(), ctx);
        return Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header));
    }

    let account_cfg = &ctx.config.account;
    let linking_cfg = &account_cfg.account_linking;
    let encrypt = account_cfg.encrypt_oauth_tokens;
    let secret = &ctx.config.secret;

    // Check if a user with this email already exists
    let user = if let Some(existing_user) = ctx.database.get_user_by_email(&user_info.email).await?
    {
        // Account linking: check if linking is enabled and provider is trusted
        if linking_cfg.enabled {
            let provider_trusted = linking_cfg.trusted_providers.is_empty()
                || linking_cfg
                    .trusted_providers
                    .iter()
                    .any(|p| p == provider_name);

            if !provider_trusted {
                return Err(AuthError::bad_request(
                    "Account linking is not allowed for this provider",
                ));
            }

            // Update user info from the new provider if configured
            if linking_cfg.update_user_info_on_link {
                let mut update = UpdateUser::default();
                if let Some(name) = &user_info.name {
                    update.name = Some(name.clone());
                }
                if let Some(image) = &user_info.image {
                    update.image = Some(image.clone());
                }
                ctx.database.update_user(existing_user.id(), update).await?;
                // Re-fetch the user to get updated fields
                ctx.database
                    .get_user_by_id(existing_user.id())
                    .await?
                    .ok_or(AuthError::UserNotFound)?
            } else {
                existing_user
            }
        } else {
            return Err(AuthError::bad_request(
                "Account linking is disabled. Cannot sign in with a new provider for an existing email.",
            ));
        }
    } else {
        // Create a new user
        let create_user = CreateUser::new()
            .with_email(&user_info.email)
            .with_name(user_info.name.as_deref().unwrap_or(&user_info.email))
            .with_email_verified(user_info.email_verified);

        ctx.database.create_user(create_user).await?
    };

    // Create account (encrypt tokens if configured)
    ctx.database
        .create_account(CreateAccount {
            user_id: user.id().to_string(),
            account_id: user_info.id,
            provider_id: provider_name.to_string(),
            access_token: maybe_encrypt(Some(access_token.to_string()), encrypt, secret)?,
            refresh_token: maybe_encrypt(refresh_token, encrypt, secret)?,
            id_token: maybe_encrypt(id_token, encrypt, secret)?,
            access_token_expires_at,
            refresh_token_expires_at: None,
            scope: scopes,
            password: None,
        })
        .await?;

    // Create session
    let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
    let session = session_manager.create_session(&user, None, None).await?;

    let response = OAuthCallbackResponse {
        token: session.token().to_string(),
        user,
    };

    let cookie_header = create_session_cookie(session.token(), ctx);
    Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
}

pub async fn handle_link_social<DB: DatabaseAdapter>(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    // Require authenticated session
    let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
    let token = session_manager
        .extract_session_token(req)
        .ok_or(AuthError::Unauthenticated)?;
    let session = session_manager
        .get_session(&token)
        .await?
        .ok_or(AuthError::Unauthenticated)?;

    let link_req: LinkSocialRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };

    let provider_name = &link_req.provider;

    if !config.providers.contains_key(provider_name) {
        return Err(AuthError::bad_request(format!(
            "Unknown provider: {}",
            provider_name
        )));
    }

    let callback_url = link_req
        .callback_url
        .clone()
        .unwrap_or_else(|| format!("{}/callback/{}", ctx.config.base_url, provider_name));

    let (code_verifier, code_challenge) = generate_pkce();
    let state = uuid::Uuid::new_v4().to_string();

    let provider = config.providers.get(provider_name).unwrap();
    let effective_scopes: Vec<String> = link_req
        .scopes
        .clone()
        .unwrap_or_else(|| provider.scopes.clone());

    // Store state with the user ID to link
    let payload = serde_json::json!({
        "provider": provider_name,
        "callback_url": callback_url,
        "code_verifier": code_verifier,
        "link_user_id": session.user_id(),
        "scopes": effective_scopes.join(" "),
    });

    ctx.database
        .create_verification(CreateVerification {
            identifier: format!("oauth:{}", state),
            value: payload.to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await?;

    let url = build_authorization_url(
        config,
        provider_name,
        &callback_url,
        link_req.scopes.as_deref(),
        &state,
        &code_challenge,
        Some(session.user_id()),
    )?;

    let response = SocialSignInResponse {
        url,
        redirect: true,
    };

    AuthResponse::json(200, &response).map_err(AuthError::from)
}

pub async fn handle_get_access_token<DB: DatabaseAdapter>(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    let _ = config;

    // Require authenticated session
    let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
    let token = session_manager
        .extract_session_token(req)
        .ok_or(AuthError::Unauthenticated)?;
    let session = session_manager
        .get_session(&token)
        .await?
        .ok_or(AuthError::Unauthenticated)?;

    let get_req: GetAccessTokenRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };

    // Find the account for this provider
    let accounts = ctx.database.get_user_accounts(session.user_id()).await?;

    let account = accounts
        .iter()
        .find(|a| a.provider_id() == get_req.provider_id)
        .ok_or_else(|| {
            AuthError::not_found(format!(
                "No linked account found for provider: {}",
                get_req.provider_id
            ))
        })?;

    // Decrypt tokens transparently if encryption is enabled
    let encrypt = ctx.config.account.encrypt_oauth_tokens;
    let secret = &ctx.config.secret;

    let response = AccessTokenResponse {
        access_token: maybe_decrypt(account.access_token(), encrypt, secret)?,
        access_token_expires_at: account.access_token_expires_at().map(|dt| dt.to_rfc3339()),
        scope: account.scope().map(String::from),
    };

    AuthResponse::json(200, &response).map_err(AuthError::from)
}

pub async fn handle_refresh_token<DB: DatabaseAdapter>(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<DB>,
) -> AuthResult<AuthResponse> {
    // Require authenticated session
    let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
    let token = session_manager
        .extract_session_token(req)
        .ok_or(AuthError::Unauthenticated)?;
    let session = session_manager
        .get_session(&token)
        .await?
        .ok_or(AuthError::Unauthenticated)?;

    let refresh_req: RefreshTokenRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };

    let provider_name = &refresh_req.provider_id;

    let provider = config
        .providers
        .get(provider_name)
        .ok_or_else(|| AuthError::bad_request(format!("Unknown provider: {}", provider_name)))?;

    // Find the account for this provider
    let accounts = ctx.database.get_user_accounts(session.user_id()).await?;

    let account = accounts
        .iter()
        .find(|a| a.provider_id() == provider_name.as_str())
        .ok_or_else(|| {
            AuthError::not_found(format!(
                "No linked account found for provider: {}",
                provider_name
            ))
        })?;

    // Decrypt refresh token if encryption is enabled
    let encrypt = ctx.config.account.encrypt_oauth_tokens;
    let secret = &ctx.config.secret;

    let raw_refresh_token = account
        .refresh_token()
        .ok_or_else(|| AuthError::bad_request("No refresh token available for this provider"))?;

    let current_refresh_token = if encrypt {
        super::encryption::decrypt_token(raw_refresh_token, secret)?
    } else {
        raw_refresh_token.to_string()
    };

    // Exchange refresh token for new access token
    let client = reqwest::Client::new();
    let token_resp = client
        .post(&provider.token_url)
        .header("Accept", "application/json")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &current_refresh_token),
            ("client_id", &provider.client_id),
            ("client_secret", &provider.client_secret),
        ])
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("Token refresh failed: {}", e)))?;

    if !token_resp.status().is_success() {
        let error_body = token_resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(AuthError::internal(format!(
            "Token refresh returned error: {}",
            error_body
        )));
    }

    let token_data: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to parse refresh response: {}", e)))?;

    let new_access_token = token_data["access_token"]
        .as_str()
        .ok_or_else(|| AuthError::internal("Missing access_token in refresh response"))?;

    let new_refresh_token = token_data["refresh_token"].as_str().map(String::from);
    let expires_in = token_data["expires_in"].as_i64();
    let new_scope = token_data["scope"].as_str().map(String::from);

    let access_token_expires_at = expires_in.map(|secs| Utc::now() + Duration::seconds(secs));

    // Update the account with new tokens (encrypt if configured)
    ctx.database
        .update_account(
            account.id(),
            UpdateAccount {
                access_token: maybe_encrypt(Some(new_access_token.to_string()), encrypt, secret)?,
                refresh_token: maybe_encrypt(new_refresh_token.clone(), encrypt, secret)?,
                access_token_expires_at,
                scope: new_scope.clone(),
                ..Default::default()
            },
        )
        .await?;

    let response = RefreshTokenResponse {
        access_token: Some(new_access_token.to_string()),
        access_token_expires_at: access_token_expires_at.map(|dt| dt.to_rfc3339()),
        refresh_token: new_refresh_token,
        scope: new_scope,
    };

    AuthResponse::json(200, &response).map_err(AuthError::from)
}

fn extract_query_param(path: &str, key: &str) -> Option<String> {
    let query_string = path.split('?').nth(1)?;
    for pair in query_string.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let (Some(k), Some(v)) = (parts.next(), parts.next())
            && k == key
        {
            return Some(urlencoding::decode(v).unwrap_or_default().into_owned());
        }
    }
    None
}

fn create_session_cookie<DB: DatabaseAdapter>(token: &str, ctx: &AuthContext<DB>) -> String {
    let session_config = &ctx.config.session;
    let secure = if session_config.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    let http_only = if session_config.cookie_http_only {
        "; HttpOnly"
    } else {
        ""
    };
    let same_site = match session_config.cookie_same_site {
        better_auth_core::config::SameSite::Strict => "; SameSite=Strict",
        better_auth_core::config::SameSite::Lax => "; SameSite=Lax",
        better_auth_core::config::SameSite::None => "; SameSite=None",
    };

    let expires = Utc::now() + session_config.expires_in;
    let expires_str = expires.format("%a, %d %b %Y %H:%M:%S GMT");

    format!(
        "{}={}; Path=/; Expires={}{}{}{}",
        session_config.cookie_name, token, expires_str, secure, http_only, same_site
    )
}
