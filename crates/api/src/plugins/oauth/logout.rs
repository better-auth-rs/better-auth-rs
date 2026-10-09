use std::collections::HashSet;

use better_auth_core::{AuthContext, AuthRequest, AuthResponse, AuthResult, FieldValue};
use url::Url;

use crate::plugins::json_body::{self, SignOutBody};

use super::providers::OAuthProvider;
use super::resolved::ResolvedOAuthConfig as OAuthConfig;

pub(crate) async fn handle_sign_out(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let body = match json_body::sign_out(req) {
        Ok(body) => body,
        Err(response) => return Ok(response),
    };
    let Some(config) = ctx.extensions.get::<std::sync::Arc<OAuthConfig>>() else {
        return crate::plugins::session_management::handle_sign_out(req, ctx).await;
    };
    let current_session = if let Some(token) = ctx.session_manager().extract_session_token(req) {
        match crate::plugins::one_time_token::find_session(ctx, &token.into()).await {
            Ok(session) => session,
            Err(error) => {
                better_auth_core::observability::logger::current().error(
                    "Failed to read session from database",
                    &[better_auth_core::observability::LogArgument::Error(&error)],
                );
                None
            }
        }
    } else {
        None
    };

    let mut response = crate::plugins::session_management::handle_sign_out(req, ctx).await?;
    let Some(current_session) = current_session else {
        return Ok(response);
    };
    // Upstream completes local logout even if provider logout cannot be prepared.
    let url = match async {
        provider_logout_url(&current_session.user_field("id")?, &body, config, ctx).await
    }
    .await
    {
        Ok(url) => url,
        Err(error) => {
            better_auth_core::observability::logger::current().error(
                "Failed to create provider logout URL",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            );
            return Ok(response);
        }
    };
    if let Some(url) = url {
        let redirect = !body.disable_redirect.unwrap_or(false);
        if redirect {
            _ = response.headers.insert("Location", url.as_str());
        }
        response.body =
            better_auth_core::ResponseBody::Bytes(serde_json::to_vec(&serde_json::json!({
                "success": true,
                "url": url.as_str(),
                "redirect": redirect,
            }))?);
    }
    Ok(response)
}

async fn provider_logout_url(
    user_id: &FieldValue,
    body: &SignOutBody,
    config: &OAuthConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Option<Url>> {
    let mut accounts = ctx.database.get_user_accounts_value(user_id).await?;
    accounts.retain(|account| {
        config.providers.iter().any(|(name, provider)| {
            account.provider_id == name.as_str() && provider.config.end_session_endpoint.is_some()
        })
    });
    let mut date_error = None;
    accounts.sort_by(|left, right| {
        if date_error.is_some() {
            return std::cmp::Ordering::Equal;
        }
        match right.updated_at.date_milliseconds().and_then(|right| {
            left.updated_at
                .date_milliseconds()
                .map(|left| (right, left))
        }) {
            // JavaScript Array.sort treats a NaN comparator result as zero.
            Ok((right, left)) => right
                .partial_cmp(&left)
                .unwrap_or(std::cmp::Ordering::Equal),
            Err(error) => {
                date_error = Some(error);
                std::cmp::Ordering::Equal
            }
        }
    });
    if let Some(error) = date_error {
        return Err(error);
    }
    let mut seen = HashSet::new();
    for account in accounts {
        let Some((provider_id, provider)) = config
            .providers
            .iter()
            .find(|(name, _)| account.provider_id == name.as_str())
        else {
            continue;
        };
        if !seen.insert(provider_id.to_owned()) {
            continue;
        }
        if provider.config.end_session_endpoint.is_none() {
            continue;
        }
        let url = (|| -> AuthResult<Option<Url>> {
            let id_token = if account.id_token.is_truthy()? {
                Some(account.id_token.display_string()?)
            } else {
                None
            };
            Ok(end_session_url(
                &provider.config,
                id_token.as_deref(),
                body,
                &super::handlers::auth_base_url(ctx),
            ))
        })();
        match url {
            Ok(Some(url)) => return Ok(Some(url)),
            Ok(None) => {}
            Err(error) => {
                better_auth_core::observability::logger::current().error(
                    &format!("Failed to create logout URL for provider \"{provider_id}\""),
                    &[better_auth_core::observability::LogArgument::Error(&error)],
                );
            }
        }
    }
    Ok(None)
}

fn end_session_url(
    provider: &OAuthProvider,
    id_token: Option<&str>,
    body: &SignOutBody,
    base_url: &str,
) -> Option<Url> {
    let mut url = Url::parse(provider.end_session_endpoint.as_deref()?).ok()?;
    let id_token = id_token.filter(|value| !value.is_empty());
    if let Some(token) = id_token {
        set_query(&mut url, "id_token_hint", token);
    }
    let callback = body
        .callback_url
        .as_deref()
        .filter(|value| !value.is_empty())
        .or(provider.post_logout_redirect_uri.as_deref());
    if let Some(callback) = callback.filter(|value| !value.is_empty()) {
        let redirect = Url::parse(base_url).ok()?.join(callback).ok()?;
        set_query(&mut url, "post_logout_redirect_uri", redirect.as_str());
        set_query(&mut url, "client_id", &provider.client_id);
        if let Some(state) = body.state.as_deref().filter(|value| !value.is_empty()) {
            set_query(&mut url, "state", state);
        }
    } else if id_token.is_none() {
        set_query(&mut url, "client_id", &provider.client_id);
    }
    Some(url)
}

fn set_query(url: &mut Url, key: &str, value: &str) {
    let retained: Vec<_> = url
        .query_pairs()
        .filter(|(name, _)| name != key)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    _ = url
        .query_pairs_mut()
        .clear()
        .extend_pairs(retained)
        .append_pair(key, value);
}
