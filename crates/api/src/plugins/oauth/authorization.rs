use better_auth_core::{AuthError, AuthResult};
use indexmap::IndexMap;
use url::Url;

use super::resolved::ResolvedProvider;

pub(super) const RESERVED_PARAMS: &[&str] = &[
    "state",
    "client_id",
    "redirect_uri",
    "response_type",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "scope",
];

pub(super) struct AuthorizationRequest<'a> {
    pub callback_url: &'a str,
    pub scopes: Option<&'a [String]>,
    pub state: &'a str,
    pub code_challenge: &'a str,
    pub login_hint: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub additional_params: Option<&'a IndexMap<String, String>>,
}

pub(super) fn build_authorization_url(
    provider: &ResolvedProvider,
    input: AuthorizationRequest<'_>,
) -> AuthResult<String> {
    let generic = provider.generic.as_ref();
    if generic.is_none() && provider.config.is_tiktok() {
        return super::providers::tiktok::authorization_url(&provider.config, input);
    }
    let input = if generic.is_none() && provider.config.omits_login_hint() {
        AuthorizationRequest {
            login_hint: None,
            additional_params: if provider.config.is_cloudflare() {
                None
            } else {
                input.additional_params
            },
            ..input
        }
    } else {
        input
    };
    let options = generic.map(|generic| &generic.config);
    if generic.is_none()
        && provider.config.microsoft_options().is_some()
        && provider.config.client_id.is_empty()
    {
        better_auth_core::observability::logger::current().error(
            "Client Id is required for Microsoft Entra ID. Make sure to provide it in the options.",
            &[],
        );
        return Err(AuthError::internal("CLIENT_ID_AND_SECRET_REQUIRED"));
    }
    if generic.is_none()
        && let Some(options) = provider.config.cognito_options()
    {
        let missing = if provider.config.client_id.is_empty() {
            Some((
                "ClientId is required for Amazon Cognito. Make sure to provide them in the options.",
                "CLIENT_ID_AND_SECRET_REQUIRED",
            ))
        } else if options.require_client_secret && provider.config.client_secret.is_empty() {
            Some((
                "Client Secret is required when requireClientSecret is true. Make sure to provide it in the options.",
                "CLIENT_SECRET_REQUIRED",
            ))
        } else {
            None
        };
        if let Some((message, code)) = missing {
            better_auth_core::observability::logger::current().error(message, &[]);
            return Err(AuthError::internal(code));
        }
    }
    if generic.is_none()
        && (provider.config.client_id.is_empty() || provider.config.client_secret.is_empty())
        && let Some(message) = provider.config.required_credentials_message()
    {
        better_auth_core::observability::logger::current().error(message, &[]);
        return Err(AuthError::internal("CLIENT_ID_AND_SECRET_REQUIRED"));
    }
    if generic.is_none() && input.code_challenge.is_empty() {
        let message = if provider.config.is_salesforce() {
            Some("codeVerifier is required for Salesforce")
        } else if provider.config.paybin_issuer().is_some() {
            Some("codeVerifier is required for Paybin")
        } else {
            None
        };
        if let Some(message) = message {
            return Err(AuthError::internal(message));
        }
    }
    if provider.config.auth_url.is_empty() {
        return Err(AuthError::Upstream {
            status: 400,
            code: "INVALID_OAUTH_CONFIGURATION",
            message: "Invalid OAuth configuration",
        });
    }
    let mut scopes = if generic.is_some() {
        input
            .scopes
            .unwrap_or_default()
            .iter()
            .chain(provider.config.scopes.as_deref().unwrap_or_default())
            .map(String::as_str)
            .collect()
    } else {
        provider.config.social_scopes(input.scopes)
    };
    if generic.is_some_and(|generic| generic.is_oidc) && !scopes.contains(&"openid") {
        scopes.insert(0, "openid");
    }
    let mut url = Url::parse(&provider.config.auth_url)
        .map_err(|error| AuthError::internal(format!("Invalid authorization URL: {error}")))?;
    if provider.config.client_id.is_empty() {
        return Err(AuthError::internal("OAuth provider requires clientId"));
    }
    let mut params: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    let mut set = |name: &str, value: &str| {
        let mut found = false;
        params.retain_mut(|(key, previous)| {
            if key != name {
                return true;
            }
            if found {
                return false;
            }
            found = true;
            *previous = value.to_owned();
            true
        });
        if !found {
            params.push((name.to_owned(), value.to_owned()));
        }
    };
    let wechat = generic.is_none() && provider.config.wechat_refresh_url().is_some();
    if wechat {
        set("scope", &scopes.join(","));
        set("response_type", "code");
        set("appid", &provider.config.client_id);
        set(
            "redirect_uri",
            provider
                .config
                .redirect_uri
                .as_deref()
                .filter(|uri| !uri.is_empty())
                .unwrap_or(input.callback_url),
        );
        set("state", input.state);
        set("lang", "cn");
    } else {
        set(
            "response_type",
            options
                .and_then(|options| options.response_type.as_deref())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| {
                    if generic.is_none() && provider.config.apple_options().is_some() {
                        "code id_token"
                    } else {
                        "code"
                    }
                }),
        );
        set("client_id", &provider.config.client_id);
        set("state", input.state);
        if !scopes.is_empty() {
            set("scope", &scopes.join(" "));
        }
        set(
            "redirect_uri",
            provider
                .config
                .redirect_uri
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or(input.callback_url),
        );
        for (name, value) in [
            ("login_hint", input.login_hint),
            (
                "nonce",
                if generic.is_none() && provider.config.omits_request_nonce() {
                    None
                } else {
                    input.nonce
                },
            ),
            (
                "prompt",
                options.map_or_else(
                    || provider.config.social_prompt(),
                    |options| options.prompt.as_deref(),
                ),
            ),
            (
                "access_type",
                options.and_then(|options| options.access_type.as_deref()),
            ),
            (
                "response_mode",
                options
                    .and_then(|options| options.response_mode.as_deref())
                    .or_else(|| {
                        (generic.is_none() && provider.config.apple_options().is_some())
                            .then_some("form_post")
                    }),
            ),
        ] {
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                set(name, value);
            }
        }
        if provider.uses_pkce() {
            set("code_challenge_method", "S256");
            set("code_challenge", input.code_challenge);
        }
    }
    if generic.is_none()
        && let Some(options) = provider.config.twitch_options()
    {
        set("claims", &options.authorization_claims()?);
    }
    let omit_configured_permissions =
        generic.is_none() && provider.config.is_discord() && !scopes.contains(&"bot");
    for (key, value) in provider
        .config
        .authorization_params
        .iter()
        .filter(|(key, _)| !omit_configured_permissions || key != "permissions")
        .map(|(key, value)| (key, value))
        .chain(input.additional_params.into_iter().flatten())
    {
        if !RESERVED_PARAMS.contains(&key.as_str()) && !(wechat && key == "appid") {
            set(key, value);
        }
    }
    if generic.is_none() {
        for (key, value) in provider.config.fixed_authorization_params() {
            set(key, value);
        }
    }
    let cognito_scope = if generic.is_none() && provider.config.cognito_options().is_some() {
        let scope = params
            .iter()
            .find(|(key, value)| key == "scope" && !value.is_empty())
            .map(|(_, value)| value.clone());
        if scope.is_some() {
            params.retain(|(key, _)| key != "scope");
        }
        scope
    } else {
        None
    };
    let _ = url.query_pairs_mut().clear().extend_pairs(params);
    if wechat {
        url.set_fragment(Some("wechat_redirect"));
    }
    if let Some(scope) = cognito_scope {
        // Cognito uses encodeURIComponent and places scope after the other query parameters.
        return Ok(format!(
            "{url}&scope={}",
            better_auth_core::utils::cookie_utils::encode_cookie_value(&scope)
        ));
    }
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::oauth::generic::GenericOAuthConfig;
    use crate::plugins::oauth::providers::OAuthConfig;
    use crate::plugins::oauth::resolved::ResolvedOAuthConfig;
    use crate::plugins::oauth::types::{LinkSocialRequest, SocialSignInRequest};
    use better_auth_core::{AuthRequest, HttpMethod};
    use std::collections::HashMap;

    #[tokio::test]
    async fn authorization_preserves_configured_and_request_parameter_order_on_both_routes() {
        let configuration = GenericOAuthConfig {
            client_id: "client".to_string(),
            authorization_url: Some(
                "https://provider.example/authorize?zeta=old&kept=base&zeta=duplicate".to_string(),
            ),
            token_url: Some("https://provider.example/token".to_string()),
            pkce: false,
            authorization_url_params: [
                ("zeta".to_string(), "configured".to_string()),
                ("configured_z".to_string(), "z".to_string()),
                ("configured_a".to_string(), "a".to_string()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let resolved = ResolvedOAuthConfig::new(
            &OAuthConfig::default(),
            &HashMap::from([("provider".to_string(), configuration)]),
            None,
        )
        .await
        .unwrap();
        for path in ["/sign-in/social", "/link-social"] {
            let mut request = AuthRequest::new(HttpMethod::Post, path);
            request.body = Some(br#"{"provider":"provider","additionalParams":{"request_z":"z","request_a":"a","configured_z":"override","zeta":"request"}}"#.to_vec());
            let params = if path == "/sign-in/social" {
                crate::plugins::oauth::request::read::<SocialSignInRequest>(&request)
                    .unwrap()
                    .additional_params
            } else {
                crate::plugins::oauth::request::read::<LinkSocialRequest>(&request)
                    .unwrap()
                    .additional_params
            };
            let url = build_authorization_url(
                &resolved.providers["provider"],
                AuthorizationRequest {
                    callback_url: "https://app.example/callback",
                    scopes: None,
                    state: "state",
                    code_challenge: "challenge",
                    login_hint: None,
                    nonce: None,
                    additional_params: params.as_ref(),
                },
            )
            .unwrap();
            assert_eq!(
                url,
                "https://provider.example/authorize?zeta=request&kept=base&response_type=code&client_id=client&state=state&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&configured_z=override&configured_a=a&request_z=z&request_a=a",
                "{path}"
            );
        }
    }
}
