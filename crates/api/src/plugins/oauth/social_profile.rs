use better_auth_core::{AuthError, AuthResult};

use super::google::{self, VerifiedGoogleClaims};
use super::id_token::VerifiedIdToken;
use super::providers::{OAuthUserInfoRequest, OAuthUserInfoResponse};
use super::resolved::ResolvedProvider;

pub(super) async fn fetch_user_info_from_provider(
    provider: &ResolvedProvider,
    request: OAuthUserInfoRequest,
    expected_nonce: Option<&str>,
) -> AuthResult<OAuthUserInfoResponse> {
    fetch_user_info_with_claims(provider, request, expected_nonce, None).await
}

pub(super) async fn fetch_user_info_with_claims(
    provider: &ResolvedProvider,
    request: OAuthUserInfoRequest,
    expected_nonce: Option<&str>,
    claims: Option<VerifiedIdToken>,
) -> AuthResult<OAuthUserInfoResponse> {
    if let Some(generic) = &provider.generic {
        let claims = match claims {
            Some(VerifiedIdToken::Generic(claims)) => Some(claims),
            None => None,
            Some(VerifiedIdToken::Google(_)) => {
                return Err(AuthError::internal(
                    "Google claims supplied to a Generic provider",
                ));
            }
        };
        return super::generic_profile::fetch_user_info(generic, &request, expected_nonce, claims)
            .await;
    }
    let claims = match claims {
        Some(VerifiedIdToken::Google(claims)) => Some(claims),
        None => None,
        Some(VerifiedIdToken::Generic(_)) => {
            return Err(AuthError::internal(
                "Generic claims supplied to a Social provider",
            ));
        }
    };
    let mut response = fetch_social_user_info(provider, request, claims).await?;
    if let Some(mapper) = &provider.config.map_profile_to_user {
        let mapped = mapper.map_profile(&response.data).await?;
        response
            .user
            .additional_fields
            .extend(mapped.additional_fields);
        if let Some(email) = mapped.email {
            response.user.email = email;
        }
        if let Some(name) = mapped.name {
            response.user.name = name;
        }
        if let Some(image) = mapped.image {
            response.user.image = Some(image);
        }
        if let Some(verified) = mapped.email_verified {
            response.user.email_verified = verified;
        }
    }
    Ok(response)
}

pub(super) async fn fetch_user_info_for_code(
    provider: &ResolvedProvider,
    request: OAuthUserInfoRequest,
    expected_nonce: Option<&str>,
) -> AuthResult<OAuthUserInfoResponse> {
    let claims = if provider.config.get_user_info.is_none()
        && let Some(jwks_url) = provider.config.google_jwks_url()
    {
        let token = request
            .id_token
            .as_deref()
            .ok_or_else(|| AuthError::internal("Missing ID token for Google profile"))?;
        Some(VerifiedIdToken::Google(
            google::verify(
                token,
                std::slice::from_ref(&provider.config.client_id),
                expected_nonce,
                jwks_url,
            )
            .await
            .ok_or_else(|| AuthError::internal("Google ID token verification failed"))?,
        ))
    } else {
        None
    };
    fetch_user_info_with_claims(provider, request, expected_nonce, claims).await
}

async fn fetch_social_user_info(
    provider: &ResolvedProvider,
    request: OAuthUserInfoRequest,
    claims: Option<VerifiedGoogleClaims>,
) -> AuthResult<OAuthUserInfoResponse> {
    if let Some(handler) = &provider.config.get_user_info {
        return handler
            .get_user_info(request)
            .await
            .map_err(AuthError::internal);
    }

    if let Some(claims) = claims {
        let claims = claims.into_value();
        if !google::hosted_domain_allowed(provider.config.google_hosted_domain(), &claims) {
            return Err(AuthError::internal("Google hosted domain does not match"));
        }
        let mapper = provider
            .config
            .map_user_info
            .ok_or_else(|| AuthError::internal("Missing user-info mapper for provider"))?;
        let user = mapper(claims.clone()).map_err(AuthError::internal)?;
        return Ok(OAuthUserInfoResponse { user, data: claims });
    }

    let user_info_url = provider
        .config
        .user_info_url
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing user_info_url for provider"))?;
    let access_token = request
        .access_token
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing access token for user-info lookup"))?;
    let mapper = provider
        .config
        .map_user_info
        .ok_or_else(|| AuthError::internal("Missing user-info mapper for provider"))?;

    let client = reqwest::Client::new();
    let user_info_resp = client
        .get(user_info_url)
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

    let user = mapper(user_info_json.clone())
        .map_err(|e| AuthError::internal(format!("Failed to map user info: {}", e)))?;

    Ok(OAuthUserInfoResponse {
        user,
        data: user_info_json,
    })
}
