use better_auth_core::{AuthError, AuthResult, SchemaValue};
use serde_json::Value;

use super::{OAuthProvider, OAuthUserInfo, OAuthUserInfoRequest, OAuthUserInfoResponse};
use crate::plugins::oauth::google::AcceptedIdToken;
use crate::plugins::oauth::social_profile::{apply_mapped_profile, fetch_http_profile};

impl OAuthProvider {
    /// Configure PayPal sandbox code login with PKCE and HTTP Basic grants.
    /// Optional ID tokens require an explicit application `verify_id_token` callback.
    pub fn paypal(client_id: &str, client_secret: &str) -> Self {
        Self {
            kind: super::ProviderKind::PayPal,
            user_info_url: Some(
                "https://api-m.sandbox.paypal.com/v1/identity/oauth2/userinfo".into(),
            ),
            ..Self::custom(
                client_id,
                client_secret,
                "https://www.sandbox.paypal.com/signin/authorize",
                "https://api-m.sandbox.paypal.com/v1/oauth2/token",
            )
        }
    }

    /// Configure PayPal live code login with the same explicit ID-token verification policy.
    pub fn paypal_live(client_id: &str, client_secret: &str) -> Self {
        Self {
            auth_url: "https://www.paypal.com/signin/authorize".into(),
            token_url: "https://api-m.paypal.com/v1/oauth2/token".into(),
            user_info_url: Some("https://api-m.paypal.com/v1/identity/oauth2/userinfo".into()),
            ..Self::paypal(client_id, client_secret)
        }
    }

    pub(in crate::plugins::oauth) fn is_paypal(&self) -> bool {
        matches!(self.kind, super::ProviderKind::PayPal)
    }
}

pub(super) fn decode_profile(profile: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        id: profile
            .get("user_id")
            .and_then(Value::as_str)
            .ok_or("Missing PayPal user_id")?
            .into(),
        name: profile
            .get("name")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid PayPal name: {error}"))?
            .flatten(),
        email: super::defaults::profile_email(&profile)?,
        image: profile
            .get("picture")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid PayPal picture: {error}"))?,
        email_verified: SchemaValue::from_json(profile.get("email_verified").cloned()),
        additional_fields: Default::default(),
    })
}

pub(in crate::plugins::oauth) async fn fetch_user_info(
    provider: &OAuthProvider,
    request: OAuthUserInfoRequest,
    expected_nonce: Option<&str>,
    claims: Option<Value>,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
    let logger = better_auth_core::observability::logger::current();
    let Some(access_token) = request
        .access_token
        .as_deref()
        .filter(|token| !token.is_empty())
    else {
        logger.error("Access token is required to fetch PayPal user info", &[]);
        return Ok(None);
    };
    let result: AuthResult<Option<OAuthUserInfoResponse>> = async {
        let url = provider
            .user_info_url
            .as_deref()
            .ok_or_else(|| AuthError::internal("Missing PayPal user_info_url"))?;
        let profile = fetch_http_profile(
            provider
                .user_info_request(url, access_token)
                .query(&[("schema", "paypalv1.1")]),
        )
        .await?;
        let Some(profile) = profile.filter(|profile| !profile.is_null()) else {
            logger.error("Failed to fetch user info from PayPal", &[]);
            return Ok(None);
        };
        if let Some(token) = request
            .id_token
            .as_deref()
            .filter(|token| !token.is_empty())
        {
            let claims = match claims {
                Some(claims) => claims,
                None => {
                    let verifier = provider.verify_id_token.as_deref().ok_or_else(|| {
                        AuthError::internal(
                            "PayPal ID token requires an explicit application verifier",
                        )
                    })?;
                    AcceptedIdToken::verify(verifier, token, expected_nonce)
                        .await
                        .ok_or_else(crate::plugins::oauth::id_token::invalid)?
                        .value()?
                }
            };
            let subject = claims
                .get("sub")
                .and_then(Value::as_str)
                .filter(|subject| !subject.is_empty());
            let profile_subject = profile
                .get("sub")
                .filter(|value| !value.is_null())
                .or_else(|| profile.get("user_id"))
                .and_then(Value::as_str);
            if subject.is_none() || subject != profile_subject {
                logger.error(
                    "PayPal user info subject does not match ID token subject",
                    &[],
                );
                return Ok(None);
            }
        }
        let Some(user) = provider.decode_profile(profile.clone())? else {
            return Ok(None);
        };
        let mut response = OAuthUserInfoResponse {
            user,
            data: profile,
        };
        if let Some(mapper) = &provider.map_profile_to_user {
            let mapped = mapper.map_profile(&response.data).await?;
            apply_mapped_profile(&mut response, mapped);
        }
        let _ = response.user.email()?;
        let _ = response.user.email_verified()?;
        Ok(Some(response))
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(error) => {
            logger.error(
                "Failed to fetch user info from PayPal:",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            );
            Ok(None)
        }
    }
}

pub(in crate::plugins::oauth) fn token_result(
    result: AuthResult<super::OAuthTokenSet>,
    grant: crate::plugins::oauth::token::TokenGrantType,
) -> AuthResult<super::OAuthTokenSet> {
    use crate::plugins::oauth::token::TokenGrantType;
    result.map_err(|error| {
        let (message, code) = match grant {
            TokenGrantType::AuthorizationCode => (
                "PayPal token exchange failed:",
                "FAILED_TO_GET_ACCESS_TOKEN",
            ),
            TokenGrantType::RefreshToken => (
                "PayPal token refresh failed:",
                "FAILED_TO_REFRESH_ACCESS_TOKEN",
            ),
        };
        better_auth_core::observability::logger::current().error(
            message,
            &[better_auth_core::observability::LogArgument::Error(&error)],
        );
        AuthError::internal(code)
    })
}
