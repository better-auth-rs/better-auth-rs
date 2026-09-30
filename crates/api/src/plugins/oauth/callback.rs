use std::collections::HashMap;

use better_auth_core::entity::{AuthSession, AuthVerification};
use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult};

use super::handlers::{
    FlowStartRequest, attach_cookie_state_payload, attach_state_cookie, auth_base_url,
    build_redirect_url, complete_link_social, create_account_cookie_header,
    fetch_user_info_from_provider, initiate_oauth_flow_core, parse_callback_user_payload,
    redirect_response,
};
use super::provider_tokens::validate_authorization_code_via_provider;
use super::providers::OAuthUserInfoRequest;
use super::resolved::ResolvedOAuthConfig as OAuthConfig;
use super::signin::{OAuthSignInOptions, process_oauth_sign_in};
use super::state::{
    OAuthStatePayload, decode_cookie_state_value, decode_database_state_cookie_value, get_cookie,
    state_cookie_name,
};

pub(super) async fn handle_callback(
    config: &OAuthConfig,
    provider_name: &str,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let default_error_url = format!("{}/error", auth_base_url(ctx));
    let meta = better_auth_core::RequestMeta::from_request(req);

    let mut merged = HashMap::new();
    if req.method() == &better_auth_core::HttpMethod::Post {
        if let Some(body) = &req.body
            && !body.is_empty()
        {
            let body_text = String::from_utf8(body.clone()).map_err(|error| {
                AuthError::bad_request(format!("Invalid callback body: {error}"))
            })?;
            let parsed_body =
                serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&body_text)
                    .ok()
                    .map(|body| {
                        body.into_iter()
                            .filter_map(|(key, value)| match value {
                                serde_json::Value::String(value) => Some((key, value)),
                                serde_json::Value::Null => None,
                                other => Some((key, other.to_string())),
                            })
                            .collect::<std::collections::HashMap<String, String>>()
                    })
                    .or_else(|| {
                        Some(
                            url::form_urlencoded::parse(body_text.as_bytes())
                                .into_owned()
                                .collect::<std::collections::HashMap<String, String>>(),
                        )
                    })
                    .ok_or_else(|| AuthError::bad_request("Invalid callback request"))?;
            merged.extend(parsed_body);
        }

        // Match the TS callback route: POST body seeds the redirect, but
        // explicit query parameters win over conflicting body fields.
        merged.extend(req.query.clone());

        let mut params = url::form_urlencoded::Serializer::new(String::new());
        let mut pairs: Vec<_> = merged.iter().collect();
        pairs.sort_by_key(|(left, _)| *left);
        for (key, value) in pairs {
            let _ = params.append_pair(key, value);
        }
        return Ok(redirect_response(&format!(
            "{}/callback/{}?{}",
            auth_base_url(ctx),
            provider_name,
            params.finish()
        )));
    }

    let merged = req.query.clone();

    let error = merged.get("error").cloned();
    let state_param = match merged.get("state").cloned() {
        Some(state) if !state.is_empty() => state,
        _ => {
            if !merged.contains_key("state")
                && merged.get("code").is_some_and(|code| !code.is_empty())
                && let Some(provider) = config.providers.get(provider_name)
                && provider
                    .generic
                    .as_ref()
                    .is_some_and(|generic| generic.config.allow_idp_initiated)
            {
                let flow = initiate_oauth_flow_core(
                    ctx,
                    FlowStartRequest {
                        redirect_base: None,
                        anonymous_user_id: None,
                        provider_name,
                        provider,
                        callback_url: &ctx.config.base_url,
                        new_user_callback_url: None,
                        error_callback_url: None,
                        scopes: None,
                        additional_params: None,
                        login_hint: None,
                        request_sign_up: None,
                        additional_data: Default::default(),
                        link: None,
                        disable_redirect: false,
                    },
                )
                .await?;
                let response = redirect_response(
                    flow.response
                        .url
                        .as_deref()
                        .ok_or_else(|| AuthError::internal("Missing OAuth authorization URL"))?,
                );
                return match ctx.config.account.store_state_strategy {
                    better_auth_core::OAuthStateStrategy::Database => {
                        attach_state_cookie(response, &ctx.config, &ctx.config.secret, &flow.state)
                    }
                    better_auth_core::OAuthStateStrategy::Cookie => attach_cookie_state_payload(
                        response,
                        &ctx.config,
                        &ctx.config.secret,
                        &flow.payload,
                    ),
                };
            }
            let separator = if default_error_url.contains('?') {
                '&'
            } else {
                '?'
            };
            return Ok(redirect_response(&format!(
                "{default_error_url}{separator}error=state_not_found"
            )));
        }
    };
    let payload = match ctx.config.account.store_state_strategy {
        better_auth_core::OAuthStateStrategy::Database => {
            let verification = match ctx
                .database
                .get_verification_by_identifier(&format!("oauth:{state_param}"))
                .await?
            {
                Some(verification) => verification,
                None => {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=please_restart_the_process"
                    )));
                }
            };

            if !ctx.config.account.skip_state_cookie_check {
                let Some(cookie_value) = get_cookie(req, &state_cookie_name(&ctx.config)) else {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=state_mismatch"
                    )));
                };
                let persisted_state =
                    match decode_database_state_cookie_value(&ctx.config.secret, &cookie_value) {
                        Ok(state) => state,
                        Err(_) => {
                            return Ok(redirect_response(&format!(
                                "{default_error_url}?error=state_mismatch"
                            )));
                        }
                    };
                if persisted_state != state_param {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=state_mismatch"
                    )));
                }
            }

            let payload: OAuthStatePayload = serde_json::from_str(verification.value())
                .map_err(|error| AuthError::internal(format!("Invalid state payload: {error}")))?;
            ctx.database.delete_verification(&verification.id()).await?;
            payload
        }
        better_auth_core::OAuthStateStrategy::Cookie => {
            let Some(cookie_value) = get_cookie(req, &state_cookie_name(&ctx.config)) else {
                return Ok(redirect_response(&format!(
                    "{default_error_url}?error=please_restart_the_process"
                )));
            };
            match decode_cookie_state_value(&ctx.config.secret, &cookie_value) {
                Ok(payload) => {
                    if !payload
                        .additional_data
                        .get("oauthState")
                        .is_some_and(|value| value.as_str() == Some(state_param.as_str()))
                    {
                        return Ok(redirect_response(&build_redirect_url(
                            &auth_base_url(ctx),
                            payload.error_url.as_deref().or(Some(&default_error_url)),
                            &[("error", "state_mismatch")],
                        )?));
                    }
                    payload
                }
                Err(_) => {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=please_restart_the_process"
                    )));
                }
            }
        }
    };

    let clear_state_cookie = better_auth_core::utils::cookie_utils::create_clear_cookie(
        &state_cookie_name(&ctx.config),
        &ctx.config,
    );
    let error_url = payload
        .error_url
        .clone()
        .unwrap_or_else(|| default_error_url.clone());

    let redirect_on_error = |error_code: &str, description: Option<&str>| {
        let mut response = redirect_response(
            &build_redirect_url(
                &auth_base_url(ctx),
                Some(&error_url),
                &[("error", error_code)],
            )
            .unwrap_or_else(|_| format!("{default_error_url}?error={error_code}")),
        )
        .with_appended_header("Set-Cookie", clear_state_cookie.clone());
        if let Some(description) = description {
            response = redirect_response(
                &build_redirect_url(
                    &auth_base_url(ctx),
                    Some(&error_url),
                    &[("error", error_code), ("error_description", description)],
                )
                .unwrap_or_else(|_| format!("{default_error_url}?error={error_code}")),
            )
            .with_appended_header("Set-Cookie", clear_state_cookie.clone());
        }
        response
    };

    if let Some(error) = error.as_deref().filter(|error| !error.is_empty()) {
        return Ok(redirect_on_error(
            error,
            merged.get("error_description").map(String::as_str),
        ));
    }

    if payload.is_expired() {
        return Ok(redirect_on_error("please_restart_the_process", None));
    }

    if let Some(user_id) = payload.server_context.get("anonymousUserId") {
        req.set_server_context("anonymousUserId", user_id.clone())?;
    }

    let Some(code) = merged.get("code").filter(|code| !code.is_empty()).cloned() else {
        return Ok(redirect_on_error("no_code", None));
    };

    let Some(provider) = config.providers.get(provider_name) else {
        return Ok(redirect_on_error("oauth_provider_not_found", None));
    };

    if let (Some(received), Some(expected)) = (
        merged.get("iss").filter(|value| !value.is_empty()),
        provider.issuer(),
    ) && received != expected
    {
        return Ok(redirect_on_error("issuer_mismatch", None));
    }
    if provider.requires_nonce() && payload.id_token_nonce.as_ref().is_none_or(String::is_empty) {
        return Ok(redirect_on_error("nonce_binding_missing", None));
    }

    let tokens = match validate_authorization_code_via_provider(
        provider,
        &code,
        &format!("{}/callback/{}", auth_base_url(ctx), provider_name),
        Some(&payload.code_verifier),
        merged.get("device_id").map(String::as_str),
    )
    .await
    {
        Ok(tokens) => tokens,
        Err(_) => return Ok(redirect_on_error("invalid_code", None)),
    };

    let user_info = match fetch_user_info_from_provider(
        provider,
        OAuthUserInfoRequest {
            token_type: tokens.token_type.clone(),
            access_token: tokens.access_token.clone(),
            refresh_token: tokens.refresh_token.clone(),
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scopes: tokens.scopes.clone(),
            id_token: tokens.id_token.clone(),
            raw: tokens.raw.clone(),
            user: parse_callback_user_payload(merged.get("user").map(String::as_str)),
        },
        payload.id_token_nonce.as_deref(),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => return Ok(redirect_on_error("unable_to_get_user_info", None)),
    };

    if let Some(link) = payload.link.as_ref() {
        if let Err(error) =
            complete_link_social(provider_name, &user_info.user, &tokens, link, ctx).await
        {
            return Ok(redirect_on_error(&error, None));
        }

        return Ok(redirect_response(&payload.callback_url)
            .with_appended_header("Set-Cookie", clear_state_cookie));
    }

    let disable_sign_up = provider.config.disable_implicit_sign_up
        && !payload.request_sign_up.unwrap_or(false)
        || provider.config.disable_sign_up;
    let outcome = match process_oauth_sign_in(
        provider_name,
        provider,
        &user_info.user,
        &tokens,
        OAuthSignInOptions {
            disable_sign_up,
            callback_url: &payload.callback_url,
            email_verification: config.email_verification.as_deref(),
        },
        &meta,
        ctx,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            let (code, description) = error.redirect_parts();
            return Ok(redirect_on_error(&code, description));
        }
    };

    let redirect_target = if outcome.is_register {
        payload
            .new_user_url
            .as_deref()
            .unwrap_or(&payload.callback_url)
            .to_string()
    } else {
        payload.callback_url.clone()
    };
    let mut response = redirect_response(&redirect_target)
        .with_appended_header("Set-Cookie", clear_state_cookie)
        .with_appended_header(
            "Set-Cookie",
            better_auth_core::utils::cookie_utils::create_session_cookie(
                outcome.session.token(),
                &ctx.config,
            ),
        );
    if let Some(account_cookie) = outcome.account_cookie.as_ref() {
        response = response.with_appended_header(
            "Set-Cookie",
            create_account_cookie_header(&ctx.config, &ctx.config.secret, account_cookie)?,
        );
    }
    Ok(response)
}
