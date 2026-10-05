use better_auth_core::{AuthError, AuthResult, SchemaValue};

use super::google;
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
            Some(
                VerifiedIdToken::Apple(_)
                | VerifiedIdToken::Google(_)
                | VerifiedIdToken::Cognito(_)
                | VerifiedIdToken::Microsoft(_)
                | VerifiedIdToken::Paybin(_)
                | VerifiedIdToken::PayPal(_)
                | VerifiedIdToken::Facebook(_),
            ) => {
                return Err(AuthError::internal(
                    "Social claims supplied to a Generic provider",
                ));
            }
        };
        return super::generic_profile::fetch_user_info(generic, &request, expected_nonce, claims)
            .await
            .map_err(super::generic_profile::GenericProfileError::into_auth_error);
    }
    if let Some(handler) = &provider.config.get_user_info {
        let response = handler.get_user_info(request).await?;
        if let Some(response) = &response {
            let _ = response.user.email()?;
            let _ = response.user.email_verified()?;
        }
        return Ok(response);
    }
    if let Some(options) = provider.config.microsoft_options() {
        let claims = match claims {
            Some(VerifiedIdToken::Microsoft(claims)) => Some(claims),
            None => None,
            Some(_) => {
                return Err(AuthError::internal(
                    "Non-Microsoft claims supplied to Microsoft",
                ));
            }
        };
        return super::providers::microsoft::fetch_user_info(
            &provider.config,
            options,
            request,
            claims,
        )
        .await;
    }
    if provider.config.is_paypal() {
        let claims = match claims {
            Some(VerifiedIdToken::PayPal(claims)) => Some(claims),
            None => None,
            Some(_) => return Err(AuthError::internal("Non-PayPal claims supplied to PayPal")),
        };
        return super::providers::paypal::fetch_user_info(
            &provider.config,
            request,
            expected_nonce,
            claims,
        )
        .await;
    }
    if let Some(options) = provider.config.facebook_options() {
        let claims = match claims {
            Some(VerifiedIdToken::Facebook(claims)) => Some(claims),
            None => match request
                .id_token
                .as_deref()
                .filter(|token| token.split('.').count() == 3)
            {
                Some(token) => Some(
                    options
                        .verify(&provider.config.client_id, token, expected_nonce)
                        .await?,
                ),
                None => None,
            },
            Some(_) => {
                return Err(AuthError::internal(
                    "Non-Facebook claims supplied to Facebook",
                ));
            }
        };
        return super::providers::facebook::fetch_user_info(
            &provider.config,
            options,
            request,
            claims,
        )
        .await;
    }
    if let Some(options) = provider.config.cognito_options() {
        let claims = match claims {
            Some(VerifiedIdToken::Cognito(claims)) => Some(claims),
            None => match request
                .id_token
                .as_deref()
                .filter(|token| !token.is_empty())
            {
                Some(token) => Some(
                    options
                        .verify(&provider.config.client_id, token, expected_nonce)
                        .await?,
                ),
                None => None,
            },
            Some(_) => {
                return Err(AuthError::internal(
                    "Non-Cognito claims supplied to Cognito",
                ));
            }
        };
        return super::cognito::fetch_user_info(&provider.config, request, claims).await;
    }
    let claims = match claims {
        Some(VerifiedIdToken::Apple(claims)) if provider.config.apple_options().is_some() => {
            Some(VerifiedIdToken::Apple(claims))
        }
        Some(VerifiedIdToken::Google(claims)) if provider.config.paybin_issuer().is_none() => {
            Some(VerifiedIdToken::Google(claims))
        }
        Some(VerifiedIdToken::Paybin(claims)) if provider.config.paybin_issuer().is_some() => {
            Some(VerifiedIdToken::Paybin(claims))
        }
        None => {
            if let Some(issuer) = provider.config.paybin_issuer() {
                let Some(token) = request
                    .id_token
                    .as_deref()
                    .filter(|token| !token.is_empty())
                else {
                    return Ok(None);
                };
                Some(VerifiedIdToken::Paybin(
                    super::providers::paybin::verify(
                        issuer,
                        &provider.config.client_id,
                        token,
                        expected_nonce,
                    )
                    .await?,
                ))
            } else {
                None
            }
        }
        Some(_) => {
            return Err(AuthError::internal(
                if provider.config.paybin_issuer().is_some() {
                    "Non-Paybin claims supplied to Paybin"
                } else {
                    "Non-Google claims supplied to a Social provider"
                },
            ));
        }
    };
    if (provider.config.is_atlassian() || provider.config.is_vk())
        && request.access_token.as_deref().is_none_or(str::is_empty)
    {
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
    if let Some(generic) = &provider.generic {
        return match super::generic_profile::fetch_user_info(
            generic,
            &request,
            expected_nonce,
            None,
        )
        .await
        {
            Ok(response) => Ok(response),
            Err(super::generic_profile::GenericProfileError::Identity(_)) => Ok(None),
            Err(super::generic_profile::GenericProfileError::Profile(error)) => Err(error),
        };
    }
    let claims = if provider.config.get_user_info.is_none()
        && let Some(jwks_url) = provider.config.google_jwks_url()
    {
        let Some(token) = request.id_token.as_deref() else {
            return Ok(None);
        };
        let Some(claims) = google::verify(
            token,
            &provider.config.google_client_ids(),
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
    claims: Option<VerifiedIdToken>,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
    let Some(mut response) = fetch_social_user_info(provider, request, claims).await? else {
        return Ok(None);
    };
    let mapped = if !provider.config.is_tiktok()
        && let Some(mapper) = &provider.config.map_profile_to_user
    {
        Some(mapper.map_profile(&response.data).await?)
    } else {
        None
    };
    if provider.config.is_vk() {
        let original_email = response
            .data
            .pointer("/user/email")
            .cloned()
            .map_or(SchemaValue::Undefined, SchemaValue::Dynamic);
        let mapped_email = mapped
            .as_ref()
            .and_then(|value| value.email.as_ref())
            .map(super::providers::profile_email)
            .transpose()?
            .flatten();
        if super::providers::profile_email(&original_email)?.is_none_or(str::is_empty)
            && mapped_email.is_none_or(str::is_empty)
        {
            return Ok(None);
        }
    }
    let placeholder_namespace = if provider.config.is_twitter() {
        Some("twitter")
    } else if provider.config.is_roblox() {
        Some("roblox")
    } else if provider.config.is_tiktok() {
        Some("tiktok")
    } else if provider.config.wechat_refresh_url().is_some() {
        Some("wechat")
    } else {
        None
    };
    if let Some(namespace) = placeholder_namespace
        && response.user.email()?.is_none_or(str::is_empty)
    {
        response.user.email = Some(placeholder_email(&response.user.id, namespace)?).into();
    }
    if let Some(mapped) = mapped {
        apply_mapped_profile(&mut response, mapped);
    }
    if provider.config.is_reddit() && response.user.email()?.is_none_or(str::is_empty) {
        response.user.email = Some(placeholder_email(&response.user.id, "reddit")?).into();
    }
    let verified = response.user.email_verified()?;
    if provider.config.is_reddit() && !verified {
        response.user.email_verified = Some(false).into();
    }
    let _ = response.user.email()?;
    Ok(Some(response))
}

pub(super) fn apply_mapped_profile(
    response: &mut OAuthUserInfoResponse,
    mapped: super::OAuthProfile,
) {
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

async fn fetch_social_user_info(
    provider: &ResolvedProvider,
    request: OAuthUserInfoRequest,
    claims: Option<VerifiedIdToken>,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
    if let Some((user_url, emails_url)) = provider.config.github_endpoints() {
        return super::providers::github_profile(user_url, emails_url, &request).await;
    }
    if provider.config.is_twitter() {
        return super::providers::twitter::fetch_user_info(&provider.config, &request).await;
    }
    if provider.config.wechat_refresh_url().is_some() {
        return super::providers::wechat::fetch_user_info(&provider.config, &request).await;
    }
    let data = match claims {
        Some(VerifiedIdToken::Apple(claims)) => {
            let Some(profile) = super::providers::apple::profile(&request, Some(claims))? else {
                return Ok(None);
            };
            profile
        }
        Some(VerifiedIdToken::Google(claims)) => {
            let claims = claims.into_value();
            if !google::hosted_domain_allowed(provider.config.google_hosted_domain(), &claims) {
                return Ok(None);
            }
            claims
        }
        Some(VerifiedIdToken::Paybin(claims)) => claims,
        Some(_) => return Err(AuthError::internal("Unexpected verified Social profile")),
        None if provider.config.twitch_options().is_some() => {
            let Some(profile) = super::providers::twitch::fetch_profile(&request)? else {
                return Ok(None);
            };
            profile
        }
        None if provider.config.apple_options().is_some() => {
            let Some(profile) = super::providers::apple::profile(&request, None)? else {
                return Ok(None);
            };
            profile
        }
        None if provider.config.line_verify_url().is_some() => {
            let Some(profile) =
                super::providers::line::fetch_profile(&provider.config, &request).await?
            else {
                return Ok(None);
            };
            profile
        }
        None => {
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
        }
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
