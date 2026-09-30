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
    let options = generic.map(|generic| &generic.config);
    if provider.config.auth_url.is_empty() {
        return Err(AuthError::Upstream {
            status: 400,
            code: "INVALID_OAUTH_CONFIGURATION",
            message: "Invalid OAuth configuration",
        });
    }
    let mut scopes: Vec<&str> = input
        .scopes
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .collect();
    if generic.is_some() || input.scopes.is_none() {
        scopes.extend(provider.config.scopes.iter().map(String::as_str));
    }
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
    set(
        "response_type",
        options
            .and_then(|options| options.response_type.as_deref())
            .filter(|value| !value.is_empty())
            .unwrap_or("code"),
    );
    set("client_id", &provider.config.client_id);
    set("state", input.state);
    if !scopes.is_empty() {
        set("scope", &scopes.join(" "));
    }
    set(
        "redirect_uri",
        options
            .and_then(|options| options.redirect_uri.as_deref())
            .filter(|value| !value.is_empty())
            .unwrap_or(input.callback_url),
    );
    for (name, value) in [
        ("login_hint", input.login_hint),
        ("nonce", input.nonce),
        (
            "prompt",
            options.and_then(|options| options.prompt.as_deref()),
        ),
        (
            "access_type",
            options.and_then(|options| options.access_type.as_deref()),
        ),
        (
            "response_mode",
            options.and_then(|options| options.response_mode.as_deref()),
        ),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            set(name, value);
        }
    }
    if options.is_none_or(|options| options.pkce) {
        set("code_challenge_method", "S256");
        set("code_challenge", input.code_challenge);
    }
    for (key, value) in provider
        .config
        .authorization_params
        .iter()
        .map(|(key, value)| (key, value))
        .chain(input.additional_params.into_iter().flatten())
    {
        if !RESERVED_PARAMS.contains(&key.as_str()) {
            set(key, value);
        }
    }
    let _ = url.query_pairs_mut().clear().extend_pairs(params);
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
                better_auth_core::validate_request_body::<SocialSignInRequest>(&request)
                    .unwrap()
                    .additional_params
            } else {
                better_auth_core::validate_request_body::<LinkSocialRequest>(&request)
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
