use better_auth_core::{AuthError, AuthResult};
use serde::Deserialize;
use serde_json::Value;

use super::{
    OAuthProvider, OAuthTokenSet, OAuthUserInfo, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use crate::plugins::oauth::provider_tokens::expiry_at;
use crate::plugins::oauth::social_profile::fetch_http_profile;
use crate::plugins::oauth::token::{TokenGrantType, TokenRequest};

pub(in crate::plugins::oauth) async fn exchange_code(
    provider: &OAuthProvider,
    code: &str,
) -> AuthResult<OAuthTokenSet> {
    let value = TokenRequest::send_query(
        &provider.token_url,
        &[
            ("appid", &provider.client_id),
            ("secret", &provider.client_secret),
            ("code", code),
            ("grant_type", "authorization_code"),
        ],
    )
    .await?;
    tokens(value, TokenGrantType::AuthorizationCode)
}

pub(in crate::plugins::oauth) async fn refresh_tokens(
    provider: &OAuthProvider,
    endpoint: &str,
    refresh_token: &str,
) -> AuthResult<OAuthTokenSet> {
    let value = TokenRequest::send_query(
        endpoint,
        &[
            ("appid", &provider.client_id),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ],
    )
    .await?;
    tokens(value, TokenGrantType::RefreshToken)
}

fn tokens(value: Value, grant: TokenGrantType) -> AuthResult<OAuthTokenSet> {
    if value.is_null() || provider_error(&value) {
        let operation = match grant {
            TokenGrantType::AuthorizationCode => "validate authorization code",
            TokenGrantType::RefreshToken => "refresh access token",
        };
        let message = value
            .get("errmsg")
            .and_then(Value::as_str)
            .filter(|message| !message.is_empty())
            .unwrap_or("Unknown error");
        return Err(AuthError::internal(format!(
            "Failed to {operation}: {message}"
        )));
    }
    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        refresh_token: String,
        expires_in: f64,
        scope: String,
    }
    let response: TokenResponse = serde_json::from_value(value.clone())
        .map_err(|error| AuthError::internal(format!("Invalid WeChat token response: {error}")))?;
    Ok(OAuthTokenSet {
        token_type: Some("Bearer".into()),
        access_token: Some(response.access_token),
        refresh_token: Some(response.refresh_token),
        access_token_expires_at: Some(expiry_at(response.expires_in)?),
        scopes: response.scope.split(',').map(str::to_owned).collect(),
        raw: (grant == TokenGrantType::AuthorizationCode).then_some(value),
        ..Default::default()
    })
}

fn provider_error(value: &Value) -> bool {
    value
        .get("errcode")
        .is_some_and(crate::plugins::json_body::is_truthy)
}

pub(in crate::plugins::oauth) async fn fetch_user_info(
    provider: &OAuthProvider,
    request: &OAuthUserInfoRequest,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
    let Some(openid) = request
        .raw
        .as_ref()
        .and_then(|raw| raw.get("openid"))
        .and_then(Value::as_str)
        .filter(|openid| !openid.is_empty())
    else {
        return Ok(None);
    };
    let endpoint = provider
        .user_info_url
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing user_info_url for provider"))?;
    let request = reqwest::Client::new().get(endpoint).query(&[
        (
            "access_token",
            request.access_token.as_deref().unwrap_or_default(),
        ),
        ("openid", openid),
        ("lang", "zh_CN"),
    ]);
    let Some(data) = fetch_http_profile(request).await? else {
        return Ok(None);
    };
    if data.is_null() || provider_error(&data) {
        return Ok(None);
    }
    Ok(provider
        .decode_profile(data.clone())?
        .map(|user| OAuthUserInfoResponse { user, data }))
}

pub(super) fn decode_profile(profile: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        id: profile
            .get("unionid")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .or_else(|| profile.get("openid").and_then(Value::as_str))
            .ok_or("Missing WeChat profile identifier")?
            .into(),
        name: serde_json::from_value(profile.get("nickname").cloned().unwrap_or(Value::Null))
            .map_err(|error| format!("Invalid WeChat nickname: {error}"))?,
        email: super::defaults::profile_email(&profile)?,
        image: profile
            .get("headimgurl")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid WeChat image: {error}"))?,
        email_verified: Some(false).into(),
        additional_fields: Default::default(),
    })
}
