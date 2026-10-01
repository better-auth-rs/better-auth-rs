//! Popup OAuth navigation and signed completion messages.

use async_trait::async_trait;
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, HttpMethod, OAuthStateStrategy,
    utils::cookie_utils::{
        create_clear_cookie, create_cookie, get_cookie, related_cookie_name, sign_cookie_value,
        verify_cookie_value,
    },
};
use serde_json::{Map, Value};
use std::sync::Arc;

use super::{handlers, resolved::ResolvedOAuthConfig, state::filter_additional_state_data};
use crate::plugins::json_body;

mod completion;
pub use completion::{OAUTH_POPUP_COMPLETE_SCRIPT, OAUTH_POPUP_SCRIPT_CSP_HASH};

/// Complete OAuth sign-in in a popup and post the result to its trusted opener.
#[derive(Debug, Default, Clone, Copy)]
pub struct OAuthPopupPlugin;

impl OAuthPopupPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for OAuthPopupPlugin {
    fn name(&self) -> &'static str {
        "oauth-popup"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/oauth-popup/start", "oauth_popup_start")]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.method() == &HttpMethod::Get && req.path() == "/oauth-popup/start" {
            return start(req, ctx).await.map(Some);
        }
        Ok(None)
    }

    async fn after_request(
        &self,
        req: &AuthRequest,
        response: &mut AuthResponse,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        if !req.path().starts_with("/callback/") && !req.path().starts_with("/oauth2/callback/") {
            return Ok(());
        }
        let Some(redirect) = response
            .headers
            .get("location")
            .cloned()
            .filter(|value| !value.is_empty())
        else {
            return Ok(());
        };
        let name = related_cookie_name(&ctx.config, "oauth_popup");
        let Some(marker) = get_cookie(req, &name)
            .and_then(|value| verify_cookie_value(&value, ctx.config.signing_secret()))
            .filter(|value| !value.is_empty())
        else {
            return Ok(());
        };
        response
            .headers
            .append("Set-Cookie", create_clear_cookie(&name, &ctx.config));
        let Ok(marker) = serde_json::from_str::<Value>(&marker) else {
            return Ok(());
        };
        if marker.is_null() {
            return Ok(());
        }
        let origin = marker.get("popupOrigin").cloned();
        let nonce = marker
            .get("popupNonce")
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(|| "".into());
        if let Some(token) = completion::session_token(response, &ctx.config.session.cookie_name)
            .filter(|value| !value.is_empty())
        {
            completion::render(
                response,
                origin,
                nonce,
                Some(token),
                Some(redirect),
                None,
                ctx,
            )?;
        } else {
            let target = url::Url::parse(&handlers::auth_base_url(ctx))
                .and_then(|base| base.join(&redirect))
                .map_err(|error| {
                    AuthError::internal(format!("Invalid OAuth popup redirect: {error}"))
                })?;
            let error = target
                .query_pairs()
                .find(|(name, _)| name == "error")
                .map(|(_, value)| value.into_owned());
            if let Some(code) = error.filter(|value| !value.is_empty()) {
                let description = target
                    .query_pairs()
                    .find(|(name, _)| name == "error_description")
                    .map(|(_, value)| value.into_owned());
                completion::render(
                    response,
                    origin,
                    nonce,
                    None,
                    None,
                    Some(completion::Failure { code, description }),
                    ctx,
                )?;
            }
        }
        Ok(())
    }
}

async fn start(req: &AuthRequest, ctx: &AuthContext<impl AuthSchema>) -> AuthResult<AuthResponse> {
    let missing: Vec<_> = ["provider", "popupOrigin"]
        .into_iter()
        .filter(|field| !req.query.contains_key(*field))
        .map(|field| json_body::invalid_type(&format!("query.{field}"), "string", None))
        .collect();
    if !missing.is_empty() {
        return Ok(json_body::validation_error(&missing.join("; ")));
    }
    let provider_name = req.query.get("provider").cloned().unwrap_or_default();
    let origin = req.query.get("popupOrigin").cloned().unwrap_or_default();
    if !better_auth_core::config::extract_origin(&origin)
        .is_some_and(|origin| ctx.config.is_origin_trusted(&origin))
    {
        return Err(AuthError::Upstream {
            status: 403,
            code: "INVALID_ORIGIN",
            message: "Invalid origin",
        });
    }
    let nonce = req.query.get("popupNonce").cloned().unwrap_or_default();
    let mut response = AuthResponse::new(302);
    for (field, code) in [
        ("callbackURL", "invalid_callback_url"),
        ("errorCallbackURL", "invalid_error_callback_url"),
        ("newUserCallbackURL", "invalid_new_user_callback_url"),
    ] {
        if let Some(value) = req.query.get(field).filter(|value| !value.is_empty())
            && !ctx.config.is_redirect_target_trusted(value)
        {
            completion::render(
                &mut response,
                Some(origin.into()),
                nonce.into(),
                None,
                None,
                Some(completion::Failure {
                    code: code.into(),
                    description: Some(format!("Untrusted URL: {value}")),
                }),
                ctx,
            )?;
            return Ok(response);
        }
    }
    let providers = ctx.extensions.get::<Arc<ResolvedOAuthConfig>>();
    let Some(provider) = providers.and_then(|providers| providers.providers.get(&provider_name))
    else {
        completion::render(
            &mut response,
            Some(origin.into()),
            nonce.into(),
            None,
            None,
            Some(completion::Failure {
                code: "provider_not_found".into(),
                description: Some(format!("Unknown provider: {provider_name}")),
            }),
            ctx,
        )?;
        return Ok(response);
    };
    let callback = req
        .query
        .get("callbackURL")
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| handlers::auth_base_url(ctx));
    let scopes = req
        .query
        .get("scopes")
        .filter(|value| !value.is_empty())
        .map(|scopes| scopes.split(',').map(str::to_owned).collect::<Vec<_>>());
    let additional = req
        .query
        .get("additionalData")
        .filter(|value| !value.is_empty())
        .map(|text| better_auth_core::utils::json::safe_json_parse(text))
        .unwrap_or(Value::Null);
    let request = handlers::FlowStartRequest {
        redirect_base: None,
        anonymous_user_id: None,
        provider_name: &provider_name,
        provider,
        callback_url: &callback,
        new_user_callback_url: req.query.get("newUserCallbackURL").cloned(),
        error_callback_url: req.query.get("errorCallbackURL").cloned(),
        scopes: scopes.as_deref(),
        additional_params: None,
        login_hint: None,
        request_sign_up: (req.query.get("requestSignUp").map(String::as_str) == Some("true"))
            .then_some(true),
        additional_data: filter_additional_state_data(Some(entries(additional))),
        link: None,
        disable_redirect: false,
    };
    let flow = handlers::prepare_oauth_flow(&request);
    let state_response = match ctx.config.account.store_state_strategy() {
        OAuthStateStrategy::Database => {
            handlers::attach_state_cookie(response, &ctx.config, &flow.state)
        }
        OAuthStateStrategy::Cookie => {
            handlers::attach_cookie_state_payload(response, &ctx.config, &flow.payload)
        }
    };
    response = match state_response {
        Ok(response) => response,
        Err(error) => return failed_start(AuthResponse::new(302), &origin, &nonce, error, ctx),
    };
    if let Err(error) = handlers::store_oauth_flow(ctx, &flow).await {
        return failed_start(response, &origin, &nonce, error, ctx);
    }
    let marker =
        serde_json::to_string(&serde_json::json!({ "popupOrigin": origin, "popupNonce": nonce }))?;
    response.headers.append(
        "Set-Cookie",
        create_cookie(
            &related_cookie_name(&ctx.config, "oauth_popup"),
            &sign_cookie_value(&marker, ctx.config.signing_secret()),
            600,
            &ctx.config,
        ),
    );
    match handlers::oauth_authorization_url(ctx, &request, &flow) {
        Ok(url) => {
            let _ = response.headers.insert("Location", url);
            let _ = response.headers.insert("Content-Type", "application/json");
            Ok(response)
        }
        Err(error) => failed_start(response, &origin, &nonce, error, ctx),
    }
}

fn entries(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(fields) => fields,
        Value::Array(values) => values
            .into_iter()
            .enumerate()
            .map(|(index, value)| (index.to_string(), value))
            .collect(),
        Value::String(value)
            if better_auth_core::utils::json::parse_json_date(&value).is_some() =>
        {
            Map::new()
        }
        Value::String(value) => value
            .chars()
            .enumerate()
            .map(|(index, value)| (index.to_string(), value.to_string().into()))
            .collect(),
        _ => Map::new(),
    }
}

fn failed_start(
    mut response: AuthResponse,
    origin: &str,
    nonce: &str,
    error: AuthError,
    ctx: &AuthContext<impl AuthSchema>,
) -> AuthResult<AuthResponse> {
    tracing::error!(%error, "OAuth popup failed to start");
    completion::render(
        &mut response,
        Some(origin.into()),
        nonce.into(),
        None,
        None,
        Some(completion::Failure {
            code: "popup_sign_in_failed".into(),
            description: Some("Failed to start the OAuth flow.".into()),
        }),
        ctx,
    )?;
    Ok(response)
}
