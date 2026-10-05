use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{AuthError, AuthResult};
use serde_json::{Map, Value};

use super::generic::GenericOAuthProfileContext;
use super::providers::{OAuthUserInfo, OAuthUserInfoRequest, OAuthUserInfoResponse};
use super::resolved::ResolvedGenericOAuth;
use super::types::AccountInfoUser;

pub(super) struct ProfileResponse {
    pub user: AccountInfoUser,
    pub data: Value,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum GenericProfileError {
    #[error(transparent)]
    Profile(#[from] AuthError),
    #[error(transparent)]
    Identity(AuthError),
}

impl GenericProfileError {
    pub(super) fn into_auth_error(self) -> AuthError {
        match self {
            Self::Profile(error) => error,
            Self::Identity(_) => super::social_profile::missing_profile(),
        }
    }
}

pub(super) async fn fetch_user_info(
    provider: &ResolvedGenericOAuth,
    tokens: &OAuthUserInfoRequest,
    expected_nonce: Option<&str>,
    verified_claims: Option<Value>,
) -> Result<Option<OAuthUserInfoResponse>, GenericProfileError> {
    let Some(response) = fetch_profile(provider, tokens, expected_nonce, verified_claims).await?
    else {
        return Ok(None);
    };
    let subject = if let Some(resolver) = &provider.config.account_subject {
        resolver
            .resolve_subject(tokens, &response.data)
            .await
            .map_err(GenericProfileError::Identity)?
    } else {
        let field = if provider.is_oidc { "sub" } else { "id" };
        response
            .data
            .get(field)
            .map(subject_string)
            .unwrap_or_default()
    };
    if subject.trim().is_empty() || matches!(subject.as_str(), "undefined" | "null") {
        return Err(GenericProfileError::Identity(AuthError::internal(
            "OAUTH_ACCOUNT_SUBJECT_INVALID",
        )));
    }
    Ok(Some(OAuthUserInfoResponse {
        user: OAuthUserInfo {
            additional_fields: response.user.additional_fields,
            id: subject,
            email: response.user.email,
            name: response.user.name,
            image: response.user.image,
            email_verified: response.user.email_verified,
        },
        data: response.data,
    }))
}

pub(super) async fn fetch_profile(
    provider: &ResolvedGenericOAuth,
    tokens: &OAuthUserInfoRequest,
    expected_nonce: Option<&str>,
    verified_claims: Option<Value>,
) -> Result<Option<ProfileResponse>, GenericProfileError> {
    let verified_claims = if verified_claims.is_some() {
        verified_claims
    } else if let (Some(token), Some(verifier)) = (
        tokens.id_token.as_deref().filter(|token| !token.is_empty()),
        &provider.verifier,
    ) {
        Some(
            verifier
                .verify(token, expected_nonce)
                .await
                .map_err(|error| {
                    GenericProfileError::Identity(AuthError::internal(format!(
                        "ID token verification failed: {error}"
                    )))
                })?,
        )
    } else {
        None
    };

    let raw = if let Some(handler) = &provider.config.get_user_info {
        handler
            .get_user_info_with_context(
                tokens,
                GenericOAuthProfileContext::new(
                    &provider.config,
                    expected_nonce,
                    verified_claims.as_ref(),
                ),
            )
            .await?
    } else {
        default_profile(provider, tokens, verified_claims).await?
    };
    let Some(raw) = raw.filter(|profile| !profile.is_null()) else {
        return Ok(None);
    };
    let profile = raw
        .as_object()
        .ok_or_else(|| AuthError::internal("OAuth user info must be an object"))?;
    let mapped = match &provider.config.map_profile_to_user {
        Some(mapper) => mapper.map_profile(&raw).await?,
        None => Default::default(),
    };
    let email = mapped.email.unwrap_or_else(|| match profile.get("email") {
        None => better_auth_core::SchemaValue::Undefined,
        Some(Value::Null) => better_auth_core::SchemaValue::Typed(None),
        Some(value) => Some(value.as_str().unwrap_or_default().to_owned()).into(),
    });
    let _ = super::providers::profile_email(&email)?;
    let email_verified = mapped.email_verified.unwrap_or_else(|| {
        better_auth_core::SchemaValue::from_json(profile.get("emailVerified").cloned())
    });
    let _ = super::providers::profile_email_verified(&email_verified)?;
    Ok(Some(ProfileResponse {
        user: AccountInfoUser {
            id: None,
            additional_fields: mapped.additional_fields,
            email,
            name: mapped
                .name
                .unwrap_or_else(|| super::providers::decode_profile_name(profile.get("name"))),
            image: mapped
                .image
                .unwrap_or_else(|| string(profile, "image"))
                .map(Some),
            email_verified,
        },
        data: raw,
    }))
}

async fn default_profile(
    provider: &ResolvedGenericOAuth,
    tokens: &OAuthUserInfoRequest,
    verified_claims: Option<Value>,
) -> AuthResult<Option<Value>> {
    let claims = verified_claims.or_else(|| tokens.id_token.as_deref().and_then(decode_claims));
    if let Some(Value::Object(claims)) = claims
        && claims.get("sub").is_some_and(truthy)
        && claims.get("email").is_some_and(truthy)
    {
        let mut profile = Map::new();
        if let Some(subject) = claims.get("sub") {
            let _ = profile.insert("id".to_string(), subject.clone());
        }
        for (from, to) in [("email_verified", "emailVerified"), ("picture", "image")] {
            if let Some(value) = claims.get(from) {
                let _ = profile.insert(to.to_string(), value.clone());
            }
        }
        profile.extend(claims);
        return Ok(Some(Value::Object(profile)));
    }

    let Some(endpoint) = provider
        .config
        .user_info_url
        .as_deref()
        .filter(|endpoint| !endpoint.is_empty())
    else {
        return Ok(None);
    };
    // Upstream uses the literal `undefined` when a token set has no access token.
    let access_token = tokens.access_token.as_deref().unwrap_or("undefined");
    let response = reqwest::Client::new()
        .get(endpoint)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|error| AuthError::internal(format!("User info request failed: {error}")))?;
    let success = response.status().is_success();
    let body = response
        .text()
        .await
        .map_err(|error| AuthError::internal(format!("User info response failed: {error}")))?;
    if !success || body.is_empty() {
        return Ok(None);
    }
    let profile: Option<Map<String, Value>> = serde_json::from_str(&body)
        .map_err(|error| AuthError::internal(format!("Invalid user info response: {error}")))?;
    let Some(mut profile) = profile else {
        return Ok(None);
    };
    let verified = profile
        .get("email_verified")
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or(Value::Bool(false));
    let _ = profile.insert("emailVerified".to_string(), verified);
    match profile.get("picture").cloned() {
        Some(picture) => {
            let _ = profile.insert("image".to_string(), picture);
        }
        None => {
            let _ = profile.remove("image");
        }
    }
    Ok(Some(Value::Object(profile)))
}

fn string(profile: &Map<String, Value>, field: &str) -> Option<String> {
    profile
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
}

// Generic OAuth without discovery retains upstream's unverified JWT decoding path.
// Providers that require signed ID tokens are rejected during initialization without JWKS.
pub(super) fn decode_claims(token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let decoded = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let claims: Map<String, Value> = serde_json::from_slice(&decoded).ok()?;
    Some(Value::Object(claims))
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

fn subject_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.as_f64().map(number_subject).unwrap_or_default(),
        Value::Array(values) => values
            .iter()
            .map(|value| {
                if value.is_null() {
                    String::new()
                } else {
                    subject_string(value)
                }
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_string(),
        value => value.to_string(),
    }
}

fn number_subject(value: f64) -> String {
    if value == 0.0 {
        return "0".to_string();
    }
    if value.abs() >= 1e21 || value.abs() < 1e-6 {
        let scientific = format!("{value:e}");
        return if value.abs() >= 1e21 {
            scientific.replace('e', "e+")
        } else {
            scientific
        };
    }
    value.to_string()
}

#[cfg(test)]
#[path = "generic_profile_tests.rs"]
mod tests;

#[cfg(all(test, feature = "axum"))]
#[path = "generic_profile_results_tests.rs"]
mod result_tests;
