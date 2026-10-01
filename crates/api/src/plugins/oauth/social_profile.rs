use better_auth_core::{AuthError, AuthResult};

use super::google::{self, VerifiedGoogleClaims};
use super::id_token::VerifiedIdToken;
use super::providers::{OAuthUserInfoRequest, OAuthUserInfoResponse};
use super::resolved::ResolvedProvider;

pub(super) async fn fetch_user_info_from_provider(
    provider: &ResolvedProvider,
    request: OAuthUserInfoRequest,
    expected_nonce: Option<&str>,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
    fetch_user_info_with_claims(provider, request, expected_nonce, None).await
}

pub(super) async fn fetch_user_info_with_claims(
    provider: &ResolvedProvider,
    request: OAuthUserInfoRequest,
    expected_nonce: Option<&str>,
    claims: Option<VerifiedIdToken>,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
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
            .await
            .map(Some);
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
    if let Some(handler) = &provider.config.get_user_info {
        let response = handler.get_user_info(request).await?;
        if let Some(response) = &response {
            let _ = response.user.email()?;
        }
        return Ok(response);
    }
    if provider.config.is_atlassian() && request.access_token.as_deref().is_none_or(str::is_empty) {
        return Ok(None);
    }
    match fetch_default_user_info(provider, request, claims).await {
        Ok(None) if provider.config.is_figma() || provider.config.is_salesforce() => {
            better_auth_core::observability::logger::current().error(
                if provider.config.is_salesforce() {
                    "Failed to fetch user info from Salesforce"
                } else {
                    "Failed to fetch user from Figma"
                },
                &[],
            );
            Ok(None)
        }
        Err(error)
            if provider.config.is_figma()
                || provider.config.is_atlassian()
                || provider.config.is_salesforce() =>
        {
            // Atlassian retains the Figma diagnostic from its pinned default-profile catch.
            better_auth_core::observability::logger::current().error(
                if provider.config.is_salesforce() {
                    "Failed to fetch user info from Salesforce:"
                } else {
                    "Failed to fetch user info from Figma:"
                },
                &[better_auth_core::observability::LogArgument::Error(&error)],
            );
            Ok(None)
        }
        response => response,
    }
}

pub(super) async fn fetch_user_info_for_code(
    provider: &ResolvedProvider,
    request: OAuthUserInfoRequest,
    expected_nonce: Option<&str>,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
    let claims = if provider.config.get_user_info.is_none()
        && let Some(jwks_url) = provider.config.google_jwks_url()
    {
        let Some(token) = request.id_token.as_deref() else {
            return Ok(None);
        };
        let Some(claims) = google::verify(
            token,
            std::slice::from_ref(&provider.config.client_id),
            expected_nonce,
            jwks_url,
        )
        .await
        else {
            return Ok(None);
        };
        Some(VerifiedIdToken::Google(claims))
    } else {
        None
    };
    fetch_user_info_with_claims(provider, request, expected_nonce, claims).await
}

async fn fetch_default_user_info(
    provider: &ResolvedProvider,
    request: OAuthUserInfoRequest,
    claims: Option<VerifiedGoogleClaims>,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
    let Some(mut response) = fetch_social_user_info(provider, request, claims).await? else {
        return Ok(None);
    };
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
    if provider.config.is_reddit() && response.user.email()?.is_none_or(str::is_empty) {
        response.user.email = Some(placeholder_email(&response.user.id, "reddit")?).into();
    }
    let _ = response.user.email()?;
    Ok(Some(response))
}

async fn fetch_social_user_info(
    provider: &ResolvedProvider,
    request: OAuthUserInfoRequest,
    claims: Option<VerifiedGoogleClaims>,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
    if let Some((user_url, emails_url)) = provider.config.github_endpoints() {
        return super::providers::github_profile(user_url, emails_url, &request).await;
    }
    let data = if let Some(claims) = claims {
        let claims = claims.into_value();
        if !google::hosted_domain_allowed(provider.config.google_hosted_domain(), &claims) {
            return Ok(None);
        }
        claims
    } else {
        let user_info_url = provider
            .config
            .user_info_url
            .as_deref()
            .ok_or_else(|| AuthError::internal("Missing user_info_url for provider"))?;
        let access_token = request
            .access_token
            .as_deref()
            .ok_or_else(|| AuthError::internal("Missing access token for user-info lookup"))?;
        let request = provider
            .config
            .user_info_request(user_info_url, access_token);
        let Some(profile) = fetch_http_profile(request).await? else {
            return Ok(None);
        };
        let Some(profile) = provider
            .config
            .http_profile_data(profile)
            .map_err(AuthError::internal)?
        else {
            return Ok(None);
        };
        profile
    };
    Ok(provider
        .config
        .decode_profile(data.clone())?
        .map(|user| OAuthUserInfoResponse { user, data }))
}

pub(super) async fn fetch_http_profile(
    request: reqwest::RequestBuilder,
) -> AuthResult<Option<serde_json::Value>> {
    let response = request.send().await.map_err(|error| {
        AuthError::internal(format!(
            "Failed to fetch user info: {}",
            error.without_url()
        ))
    })?;
    if !response.status().is_success() {
        let _ = response.text().await.map_err(|error| {
            AuthError::internal(format!("Failed to read user info: {}", error.without_url()))
        })?;
        return Ok(None);
    }
    response.json().await.map(Some).map_err(|error| {
        AuthError::internal(format!(
            "Failed to parse user info: {}",
            error.without_url()
        ))
    })
}

pub(super) fn missing_profile() -> AuthError {
    AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
    }
}

pub(super) fn placeholder_email(identifier: &str, namespace: &str) -> AuthResult<String> {
    let email = format!("{identifier}@{namespace}.placeholder.invalid");
    if !crate::plugins::json_body::valid_email(&email)? {
        return Err(AuthError::internal("Invalid placeholder email"));
    }
    Ok(email)
}

#[cfg(test)]
#[path = "profile_presence_tests.rs"]
mod tests;
