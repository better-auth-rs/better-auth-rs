use std::collections::HashMap;

use better_auth_core::{AuthError, AuthRequest, AuthResult};
use chrono::{DateTime, Duration, Utc};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;

use super::generic::{OAuthCodeExchange, RefreshTokenParameters};
use super::providers::OAuthTokenSet;
use super::resolved::ResolvedProvider;
use super::token::{AuthorizationCodeRequest, TokenAuthentication, TokenGrantType, TokenRequest};

use crate::plugins::helpers::oauth_scope_whitespace;

pub(super) async fn refresh_tokens_via_provider(
    provider: &ResolvedProvider,
    refresh_token: &str,
    request: &AuthRequest,
) -> AuthResult<OAuthTokenSet> {
    let result = refresh_tokens(provider, refresh_token, request).await;
    if provider.generic.is_none()
        && provider.config.is_paypal()
        && provider.config.refresh_access_token.is_none()
    {
        super::providers::paypal::token_result(result, TokenGrantType::RefreshToken)
    } else {
        result
    }
}

async fn refresh_tokens(
    provider: &ResolvedProvider,
    refresh_token: &str,
    request: &AuthRequest,
) -> AuthResult<OAuthTokenSet> {
    if let Some(handler) = &provider.config.refresh_access_token {
        return handler
            .refresh_access_token(refresh_token)
            .await
            .map_err(AuthError::internal);
    }
    if provider.generic.is_none()
        && let Some(endpoint) = provider.config.wechat_refresh_url()
    {
        return super::providers::wechat::refresh_tokens(&provider.config, endpoint, refresh_token)
            .await;
    }
    let token_endpoint = token_endpoint(provider)?;
    let extra = match provider
        .generic
        .as_ref()
        .and_then(|generic| generic.config.refresh_token_params.as_ref())
    {
        Some(RefreshTokenParameters::Static(parameters)) => parameters.clone(),
        Some(RefreshTokenParameters::Dynamic(handler)) => handler.parameters(request).await?,
        None if provider.generic.is_none() && provider.config.microsoft_options().is_some() => {
            HashMap::from([(
                "scope".into(),
                provider.config.social_scopes(None).join(" "),
            )])
        }
        None => HashMap::new(),
    };
    let mut request = TokenRequest::refresh_token(refresh_token, &extra, &[]);
    authenticate_request(&mut request, provider, TokenGrantType::RefreshToken).await?;
    let value = request.send(token_endpoint).await?;
    let mut tokens = parse_token_response(value)?;
    tokens.raw = None;
    apply_default_expiry(tokens, provider)
}

pub(super) async fn validate_authorization_code_via_provider(
    provider: &ResolvedProvider,
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
    device_id: Option<&str>,
) -> AuthResult<OAuthTokenSet> {
    let result = exchange_code(provider, code, redirect_uri, code_verifier, device_id).await;
    if provider.generic.is_none() && provider.config.is_paypal() {
        super::providers::paypal::token_result(result, TokenGrantType::AuthorizationCode)
    } else {
        result
    }
}

async fn exchange_code(
    provider: &ResolvedProvider,
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
    device_id: Option<&str>,
) -> AuthResult<OAuthTokenSet> {
    let generic = provider.generic.as_ref().map(|generic| &generic.config);
    if let Some(handler) = generic.and_then(|generic| generic.get_token.as_ref()) {
        let tokens = handler
            .get_token(OAuthCodeExchange {
                code,
                redirect_uri,
                code_verifier,
                device_id,
            })
            .await?;
        return apply_default_expiry(tokens, provider);
    }
    if generic.is_none() && provider.config.wechat_refresh_url().is_some() {
        return super::providers::wechat::exchange_code(&provider.config, code).await;
    }
    let token_endpoint = token_endpoint(provider)?;
    let mut social_headers = HeaderMap::new();
    if generic.is_none() && provider.config.is_reddit() {
        let _ = social_headers.insert("accept", HeaderValue::from_static("text/plain"));
        let _ = social_headers.insert("user-agent", HeaderValue::from_static("better-auth"));
    }
    let empty_params = HashMap::new();
    let mut request = TokenRequest::authorization_code(AuthorizationCodeRequest {
        code,
        redirect_uri: provider
            .config
            .redirect_uri
            .as_deref()
            .filter(|uri| !uri.is_empty())
            .unwrap_or(redirect_uri),
        code_verifier: if provider.forwards_code_verifier() {
            code_verifier
        } else {
            None
        },
        client_key: if generic.is_none() {
            provider.config.code_client_key()
        } else {
            None
        },
        device_id: if generic.is_some() || provider.config.omits_device_id() {
            None
        } else {
            device_id
        },
        headers: generic
            .map(|generic| &generic.authorization_headers)
            .unwrap_or(&social_headers),
        additional_params: generic
            .map(|generic| &generic.token_url_params)
            .unwrap_or(&empty_params),
        resources: &[],
    });
    authenticate_request(&mut request, provider, TokenGrantType::AuthorizationCode).await?;
    let value = request.send(token_endpoint).await?;
    apply_default_expiry(parse_token_response(value)?, provider)
}

fn token_endpoint(provider: &ResolvedProvider) -> AuthResult<&str> {
    if provider.config.token_url.is_empty() {
        return Err(AuthError::Upstream {
            status: 400,
            code: "TOKEN_URL_NOT_FOUND",
            message: "Invalid OAuth configuration. Token URL not found.",
        });
    }
    Ok(&provider.config.token_url)
}

async fn authenticate_request(
    request: &mut TokenRequest,
    provider: &ResolvedProvider,
    grant_type: TokenGrantType,
) -> AuthResult<()> {
    if provider.generic.is_none() && provider.config.is_tiktok() {
        request.body.extend([
            (
                "client_key".into(),
                provider
                    .config
                    .client_key
                    .as_deref()
                    .unwrap_or("undefined")
                    .into(),
            ),
            (
                "client_secret".into(),
                provider.config.client_secret.clone(),
            ),
        ]);
        Ok(())
    } else {
        request
            .authenticate(authentication(provider, grant_type))
            .await
    }
}

fn authentication(
    provider: &ResolvedProvider,
    grant_type: TokenGrantType,
) -> TokenAuthentication<'_> {
    let generic = provider.generic.as_ref().map(|generic| &generic.config);
    TokenAuthentication {
        client_id: &provider.config.client_id,
        client_secret: generic
            .map(|generic| generic.client_secret.as_deref())
            .unwrap_or(Some(&provider.config.client_secret)),
        token_endpoint: &provider.config.token_url,
        grant_type,
        token_endpoint_auth: generic.map_or_else(
            || provider.config.token_endpoint_auth(),
            |generic| generic.token_endpoint_auth.as_ref(),
        ),
        authentication: generic.map_or_else(
            || provider.config.token_authentication(grant_type),
            |generic| generic.authentication,
        ),
    }
}

fn expiry(seconds: f64) -> AuthResult<Option<DateTime<Utc>>> {
    if seconds == 0.0 {
        return Ok(None);
    }
    expiry_at(seconds).map(Some)
}

pub(super) fn expiry_at(seconds: f64) -> AuthResult<DateTime<Utc>> {
    let millis = seconds * 1000.0;
    if !millis.is_finite() || millis.abs() > i64::MAX as f64 {
        return Err(AuthError::internal("Invalid OAuth token lifetime"));
    }
    Utc::now()
        .checked_add_signed(Duration::milliseconds(millis as i64))
        .ok_or_else(|| AuthError::internal("OAuth token lifetime is out of range"))
}

fn apply_default_expiry(
    mut tokens: OAuthTokenSet,
    provider: &ResolvedProvider,
) -> AuthResult<OAuthTokenSet> {
    if tokens.access_token_expires_at.is_none()
        && let Some(seconds) = provider
            .generic
            .as_ref()
            .and_then(|generic| generic.config.access_token_expires_in)
    {
        tokens.access_token_expires_at = expiry(seconds)?;
    }
    Ok(tokens)
}

pub(super) fn parse_token_response(value: Value) -> AuthResult<OAuthTokenSet> {
    let string = |key| value.get(key).and_then(Value::as_str).map(str::to_owned);
    let date = |key| -> AuthResult<Option<DateTime<Utc>>> {
        value
            .get(key)
            .and_then(|value| value.as_f64().or_else(|| value.as_str()?.parse().ok()))
            .map(expiry)
            .transpose()
            .map(Option::flatten)
    };
    let scopes = match value.get("scope") {
        Some(Value::String(scope)) => scope
            .split(oauth_scope_whitespace)
            .filter(|scope| !scope.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(scopes)) => scopes
            .iter()
            .filter_map(Value::as_str)
            .map(|scope| scope.trim_matches(oauth_scope_whitespace))
            .filter(|scope| !scope.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    Ok(OAuthTokenSet {
        token_type: string("token_type"),
        access_token: string("access_token"),
        refresh_token: string("refresh_token"),
        access_token_expires_at: date("expires_in")?,
        refresh_token_expires_at: date("refresh_token_expires_in")?,
        scopes,
        id_token: string("id_token"),
        raw: Some(value),
    })
}

#[cfg(test)]
mod tests {
    use super::super::generic::{GenericOAuthConfig, OAuthTokenHandler};
    use super::super::providers::OAuthProvider;
    use super::super::resolved::ResolvedGenericOAuth;
    use super::super::token::{TokenEndpointAuth, TokenEndpointRequestContext, TokenRequestHook};
    use super::*;
    use async_trait::async_trait;
    use better_auth_core::HttpMethod;
    use serde_json::json;
    use std::sync::Arc;

    struct StandardExchange;

    #[async_trait]
    impl TokenRequestHook for StandardExchange {
        async fn customize_request(
            &self,
            request: TokenEndpointRequestContext<'_>,
        ) -> AuthResult<()> {
            assert!(
                request
                    .body
                    .iter()
                    .any(|(key, value)| key == "code_verifier" && value == "verifier")
            );
            assert!(request.body.iter().any(
                |(key, value)| key == "redirect_uri" && value == "https://app.example/callback"
            ));
            assert!(!request.body.iter().any(|(key, _)| key == "device_id"));
            Err(AuthError::internal("request inspected"))
        }
    }

    struct CustomExchange;

    #[async_trait]
    impl OAuthTokenHandler for CustomExchange {
        async fn get_token(&self, request: OAuthCodeExchange<'_>) -> AuthResult<OAuthTokenSet> {
            assert_eq!(request.device_id, Some("device"));
            assert_eq!(request.code_verifier, Some("verifier"));
            Ok(OAuthTokenSet {
                access_token: Some("custom-access".to_string()),
                ..Default::default()
            })
        }
    }

    #[tokio::test]
    async fn generic_exchange_keeps_device_id_only_for_custom_token_handlers() {
        let mut provider = ResolvedProvider {
            config: OAuthProvider::google("client", "secret"),
            generic: Some(ResolvedGenericOAuth {
                config: GenericOAuthConfig {
                    redirect_uri: Some(String::new()),
                    token_endpoint_auth: Some(TokenEndpointAuth::Custom(Arc::new(
                        StandardExchange,
                    ))),
                    ..Default::default()
                },
                issuer: None,
                is_oidc: false,
                verifier: None,
            }),
        };
        let error = validate_authorization_code_via_provider(
            &provider,
            "code",
            "https://app.example/callback",
            Some("verifier"),
            Some("device"),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, AuthError::Internal(message) if message == "request inspected"));

        provider.config.token_url.clear();
        let errors = [
            validate_authorization_code_via_provider(
                &provider,
                "code",
                "https://app.example/callback",
                None,
                None,
            )
            .await
            .unwrap_err(),
            refresh_tokens_via_provider(
                &provider,
                "refresh",
                &AuthRequest::new(HttpMethod::Post, "/refresh-token"),
            )
            .await
            .unwrap_err(),
        ];
        for error in errors {
            assert!(matches!(
                error,
                AuthError::Upstream {
                    status: 400,
                    code: "TOKEN_URL_NOT_FOUND",
                    message: "Invalid OAuth configuration. Token URL not found."
                }
            ));
        }

        provider.generic.as_mut().unwrap().config.get_token = Some(Arc::new(CustomExchange));
        let tokens = validate_authorization_code_via_provider(
            &provider,
            "code",
            "https://app.example/callback",
            Some("verifier"),
            Some("device"),
        )
        .await
        .unwrap();
        assert_eq!(tokens.access_token.as_deref(), Some("custom-access"));
    }

    #[test]
    fn token_response_accepts_id_token_only_and_provider_scope_shapes() {
        let tokens = parse_token_response(
            json!({"id_token":"identity", "scope":[" openid ", "", 42, "email"], "expires_in":0}),
        )
        .unwrap();
        assert!(tokens.access_token.is_none());
        assert!(tokens.access_token_expires_at.is_none());
        assert_eq!(tokens.scopes, ["openid", "email"]);
        assert_eq!(tokens.id_token.as_deref(), Some("identity"));
        let before = Utc::now();
        let tokens =
            parse_token_response(json!({"scope":"email\tprofile,audit  openid", "expires_in":0.5}))
                .unwrap();
        assert_eq!(tokens.scopes, ["email", "profile,audit", "openid"]);
        assert!(tokens.access_token_expires_at.unwrap() >= before + Duration::milliseconds(500));
    }
}
