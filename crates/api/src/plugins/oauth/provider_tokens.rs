use std::collections::HashMap;

use better_auth_core::{AuthError, AuthRequest, AuthResult, FieldDate, FieldValue, NativeRequest};
use chrono::{DateTime, Utc};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;

use super::generic::RefreshTokenParameters;
use super::providers::OAuthTokenSet;
use super::resolved::ResolvedProvider;
use super::token::{AuthorizationCodeRequest, TokenAuthentication, TokenGrantType, TokenRequest};

use crate::plugins::helpers::oauth_scope_whitespace;

pub(super) async fn refresh_tokens_via_provider(
    provider: &ResolvedProvider,
    refresh_token: &FieldValue,
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
    refresh_token: &FieldValue,
    request: &AuthRequest,
) -> AuthResult<OAuthTokenSet> {
    if let Some(handler) = &provider.config.refresh_access_token {
        return handler
            .refresh_access_token(
                refresh_token,
                Some(NativeRequest {
                    request: request.original_request(),
                    headers: request.endpoint_headers(),
                }),
            )
            .await
            .map(|tokens| OAuthTokenSet::from_fields(tokens.fields()))
            .map_err(AuthError::internal);
    }
    let refresh_token = super::providers::token_http::form_string(refresh_token)?;
    if provider.generic.is_none()
        && let Some(endpoint) = provider.config.wechat_refresh_url()
    {
        return super::providers::wechat::refresh_tokens(
            &provider.config,
            endpoint,
            &refresh_token,
        )
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
    let mut request = TokenRequest::refresh_token(&refresh_token, &extra, &[]);
    authenticate_request(&mut request, provider, TokenGrantType::RefreshToken).await?;
    let value = request.send(token_endpoint).await?;
    let tokens = parse_token_response(value)?;
    let mut fields = better_auth_core::FieldMap::from([
        ("accessToken".into(), tokens.access_token.field_value()),
        ("refreshToken".into(), tokens.refresh_token.field_value()),
        ("tokenType".into(), tokens.token_type.field_value()),
        ("scopes".into(), tokens.scopes.field_value()),
        ("idToken".into(), tokens.id_token.field_value()),
    ]);
    for (name, value) in [
        (
            "accessTokenExpiresAt",
            tokens.access_token_expires_at.field_value(),
        ),
        (
            "refreshTokenExpiresAt",
            tokens.refresh_token_expires_at.field_value(),
        ),
    ] {
        if !value.is_undefined() {
            let _ = fields.insert(name.into(), value);
        }
    }
    apply_default_expiry(OAuthTokenSet::from_fields(fields), provider)
}

#[cfg(test)]
pub(super) async fn validate_authorization_code_via_provider(
    provider: &ResolvedProvider,
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
    device_id: Option<&str>,
) -> AuthResult<OAuthTokenSet> {
    let request = better_auth_core::FieldMap::from([
        ("code".into(), code.into()),
        (
            "codeVerifier".into(),
            code_verifier.map(FieldValue::from).unwrap_or_default(),
        ),
        (
            "deviceId".into(),
            device_id.map(FieldValue::from).unwrap_or_default(),
        ),
        ("redirectURI".into(), redirect_uri.into()),
    ])
    .into();
    let tokens = validate_authorization_code_native_via_provider(provider, &request).await?;
    Ok(OAuthTokenSet::from_fields(tokens.enumerable_fields()?))
}

pub(super) async fn validate_authorization_code_native_via_provider(
    provider: &ResolvedProvider,
    input: &FieldValue,
) -> AuthResult<FieldValue> {
    if let Some(handler) = provider
        .generic
        .as_ref()
        .and_then(|generic| generic.config.get_token.as_ref())
    {
        let tokens = handler.get_token_native(input).await?;
        return apply_default_expiry_native(tokens, provider);
    }
    let result = exchange_code(provider, input).await;
    let tokens = if provider.generic.is_none() && provider.config.is_paypal() {
        super::providers::paypal::token_result(result, TokenGrantType::AuthorizationCode)?
    } else {
        result?
    };
    apply_default_expiry_native(tokens.fields().into(), provider)
}

async fn exchange_code(
    provider: &ResolvedProvider,
    input: &FieldValue,
) -> AuthResult<OAuthTokenSet> {
    let generic = provider.generic.as_ref().map(|generic| &generic.config);
    let code = super::providers::token_http::form_string(&input.model_property("code")?)?;
    if generic.is_none() && provider.config.wechat_refresh_url().is_some() {
        return super::providers::wechat::exchange_code(&provider.config, &code).await;
    }
    let token_endpoint = token_endpoint(provider)?;
    let redirect_uri =
        super::providers::token_http::form_string(&input.model_property("redirectURI")?)?;
    let code_verifier = input.model_property("codeVerifier")?;
    let code_verifier = if provider.forwards_code_verifier() && code_verifier.is_truthy() {
        Some(super::providers::token_http::form_string(&code_verifier)?)
    } else {
        None
    };
    let device_id = input.model_property("deviceId")?;
    let device_id =
        if generic.is_none() && !provider.config.omits_device_id() && device_id.is_truthy() {
            Some(super::providers::token_http::form_string(&device_id)?)
        } else {
            None
        };
    let mut social_headers = HeaderMap::new();
    if generic.is_none() && provider.config.is_reddit() {
        let _ = social_headers.insert("accept", HeaderValue::from_static("text/plain"));
        let _ = social_headers.insert("user-agent", HeaderValue::from_static("better-auth"));
    }
    let empty_params = HashMap::new();
    let mut request = TokenRequest::authorization_code(AuthorizationCodeRequest {
        code: &code,
        redirect_uri: provider
            .config
            .redirect_uri
            .as_deref()
            .filter(|uri| !uri.is_empty())
            .unwrap_or(&redirect_uri),
        code_verifier: code_verifier.as_deref(),
        client_key: if generic.is_none() {
            provider.config.code_client_key()
        } else {
            None
        },
        device_id: device_id.as_deref(),
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
    parse_token_response(value)
}

fn token_endpoint(provider: &ResolvedProvider) -> AuthResult<&str> {
    if provider.config.token_url.is_empty() {
        return Err(AuthError::from_code(
            "BAD_REQUEST",
            "TOKEN_URL_NOT_FOUND",
            "Invalid OAuth configuration. Token URL not found.",
        ));
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

pub(super) fn expiry_at(seconds: f64) -> AuthResult<FieldDate> {
    expiry_from(Utc::now(), seconds)
}

fn expiry_from(now: DateTime<Utc>, seconds: f64) -> AuthResult<FieldDate> {
    // Date clips the sum; truncating the duration first loses negative submillisecond offsets.
    Ok(FieldDate::from_milliseconds(
        now.timestamp_millis() as f64 + seconds * 1000.0,
    ))
}

fn apply_default_expiry(
    tokens: OAuthTokenSet,
    provider: &ResolvedProvider,
) -> AuthResult<OAuthTokenSet> {
    let tokens = apply_default_expiry_native(tokens.fields().into(), provider)?;
    Ok(OAuthTokenSet::from_fields(tokens.enumerable_fields()?))
}

fn apply_default_expiry_native(
    tokens: FieldValue,
    provider: &ResolvedProvider,
) -> AuthResult<FieldValue> {
    let Some(generic) = &provider.generic else {
        return Ok(tokens);
    };
    if !tokens
        .model_property_at("accessTokenExpiresAt", "tokens.accessTokenExpiresAt")?
        .is_truthy()
        && let Some(seconds) = generic
            .config
            .access_token_expires_in
            .filter(|seconds| FieldValue::Number(*seconds).is_truthy())
    {
        tokens.set_model_property("accessTokenExpiresAt", expiry_at(seconds)?.into())?;
    }
    Ok(tokens)
}

pub(super) fn parse_token_response(value: Value) -> AuthResult<OAuthTokenSet> {
    parse_token_response_with_clock(value, Utc::now)
}

fn parse_token_response_with_clock(
    value: Value,
    clock: impl Fn() -> DateTime<Utc>,
) -> AuthResult<OAuthTokenSet> {
    let raw = FieldValue::from_json(value.clone())?;
    let date = |key| -> AuthResult<FieldValue> {
        let seconds = raw.model_property(key)?;
        if !seconds.is_truthy() {
            return Ok(FieldValue::Undefined);
        }
        Ok(expiry_from(clock(), better_auth_core::query::field_number(&seconds)?)?.into())
    };
    let scopes: Vec<String> = match value.get("scope") {
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
    Ok(OAuthTokenSet::from_fields(
        better_auth_core::FieldMap::from([
            ("tokenType".into(), raw.model_property("token_type")?),
            ("accessToken".into(), raw.model_property("access_token")?),
            ("refreshToken".into(), raw.model_property("refresh_token")?),
            ("accessTokenExpiresAt".into(), date("expires_in")?),
            (
                "refreshTokenExpiresAt".into(),
                date("refresh_token_expires_in")?,
            ),
            (
                "scopes".into(),
                better_auth_core::SchemaValue::Typed(scopes).into_field_value(),
            ),
            ("idToken".into(), raw.model_property("id_token")?),
            ("raw".into(), raw),
        ]),
    ))
}

#[cfg(test)]
#[path = "token_duration_tests.rs"]
mod duration_tests;

#[cfg(test)]
#[path = "native_token_tests.rs"]
mod native_tests;

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Assertions report exact contract mismatches while Result propagates fixture errors."
)]
mod tests {
    use super::super::generic::{GenericOAuthConfig, OAuthCodeExchange, OAuthTokenHandler};
    use super::super::providers::OAuthProvider;
    use super::super::resolved::ResolvedGenericOAuth;
    use super::super::token::{TokenEndpointAuth, TokenEndpointRequestContext, TokenRequestHook};
    use super::*;
    use async_trait::async_trait;
    use better_auth_core::HttpMethod;
    use chrono::Duration;
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
                access_token: Some("custom-access".to_string()).into(),
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
                &"refresh".into(),
                &AuthRequest::new(HttpMethod::Post, "/refresh-token"),
            )
            .await
            .unwrap_err(),
        ];
        for error in errors {
            crate::plugins::test_helpers::assert_coded_api_error(
                &error,
                "BAD_REQUEST",
                400,
                "TOKEN_URL_NOT_FOUND",
                "Invalid OAuth configuration. Token URL not found.",
            );
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
        assert_eq!(
            tokens.access_token.field_value().as_str(),
            Some("custom-access")
        );
    }

    #[test]
    fn token_response_accepts_id_token_only_and_provider_scope_shapes() -> AuthResult<()> {
        let tokens = parse_token_response(
            json!({"id_token":"identity", "scope":[" openid ", "", 42, "email"], "expires_in":0}),
        )?;
        assert!(tokens.access_token.field_value().is_undefined());
        assert!(tokens.access_token_expires_at.field_value().is_undefined());
        assert_eq!(
            tokens.scopes.field_value().json()?,
            Some(json!(["openid", "email"]))
        );
        assert_eq!(tokens.id_token.field_value().as_str(), Some("identity"));
        let before = Utc::now();
        let tokens = parse_token_response(
            json!({"scope":"email\tprofile,audit  openid", "expires_in":0.5}),
        )?;
        assert_eq!(
            tokens.scopes.field_value().json()?,
            Some(json!(["email", "profile,audit", "openid"]))
        );
        assert!(
            tokens
                .access_token_expires_at
                .field_value()
                .as_date()
                .ok_or_else(|| AuthError::internal("Expected token expiry Date"))?
                .milliseconds()
                >= (before + Duration::milliseconds(500)).timestamp_millis() as f64
        );
        Ok(())
    }
}
