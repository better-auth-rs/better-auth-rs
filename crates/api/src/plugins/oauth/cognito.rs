use std::time::Duration;

use better_auth_core::{AuthError, AuthResult, SchemaValue};
use serde_json::Value;

use super::oidc::OidcVerifier;
use super::providers::{OAuthProvider, OAuthUserInfo, OAuthUserInfoRequest, OAuthUserInfoResponse};

/// Cognito hosted domain and user-pool verification policy.
#[derive(Clone)]
pub struct CognitoOptions {
    pub domain: String,
    pub region: String,
    pub user_pool_id: String,
    /// Additional accepted audiences. `OAuthProvider::client_id` remains the primary client.
    pub additional_client_ids: Vec<String>,
    /// Require a client secret before constructing an authorization URL.
    pub require_client_secret: bool,
    #[cfg(test)]
    pub(super) jwks_url: Option<String>,
}

impl CognitoOptions {
    pub fn new(domain: &str, region: &str, user_pool_id: &str) -> Self {
        Self {
            domain: domain.into(),
            region: region.into(),
            user_pool_id: user_pool_id.into(),
            additional_client_ids: Vec::new(),
            require_client_secret: false,
            #[cfg(test)]
            jwks_url: None,
        }
    }

    pub(super) async fn verify(
        &self,
        client_id: &str,
        token: &str,
        nonce: Option<&str>,
    ) -> AuthResult<Value> {
        let issuer = format!(
            "https://cognito-idp.{}.amazonaws.com/{}",
            self.region, self.user_pool_id
        );
        let jwks_url = format!("{issuer}/.well-known/jwks.json");
        #[cfg(test)]
        let jwks_url = self.jwks_url.as_deref().unwrap_or(&jwks_url).to_owned();
        let audiences = std::iter::once(client_id.to_owned())
            .chain(self.additional_client_ids.iter().cloned())
            .collect();
        let verifier = OidcVerifier::with_policy(
            jwks_url
                .parse()
                .map_err(|error: url::ParseError| AuthError::internal(error.to_string()))?,
            issuer,
            audiences,
            None,
            Some(Duration::from_secs(3600)),
        )
        .map_err(|error| AuthError::internal(error.to_string()))?;
        verifier
            .verify(token, nonce)
            .await
            .map_err(|_| super::id_token::invalid())
    }
}

pub(super) fn profile_name(profile: &Value) -> String {
    ["name", "given_name", "username"]
        .into_iter()
        .find_map(|field| {
            profile
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_default()
        .to_owned()
}

pub(super) fn decode_profile(profile: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        id: profile
            .get("sub")
            .and_then(Value::as_str)
            .ok_or("missing sub")?
            .into(),
        email: super::providers::defaults::profile_email(&profile)?,
        name: Some(profile_name(&profile)).into(),
        image: profile
            .get("picture")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Cognito picture: {error}"))?,
        email_verified: SchemaValue::from_json(profile.get("email_verified").cloned())
            .map_err(|error| error.to_string())?,
        additional_fields: Default::default(),
    })
}

async fn map_profile(
    provider: &OAuthProvider,
    data: Value,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
    let Some(user) = provider.decode_profile(data.clone())? else {
        return Ok(None);
    };
    let mut response = OAuthUserInfoResponse { user, data };
    if let Some(mapper) = &provider.map_profile_to_user {
        let mapped = mapper.map_profile(&response.data).await?;
        super::social_profile::apply_mapped_profile(&mut response, mapped);
    }
    let _ = response.user.email()?;
    let _ = response.user.email_verified()?;
    Ok(Some(response))
}

pub(super) async fn fetch_user_info(
    provider: &OAuthProvider,
    request: OAuthUserInfoRequest,
    claims: Option<Value>,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
    if let Some(mut claims) = claims {
        let name = profile_name(&claims);
        let _ = claims
            .as_object_mut()
            .ok_or_else(|| AuthError::internal("Cognito claims must be an object"))?
            .insert("name".into(), name.into());
        match map_profile(provider, claims).await {
            Ok(response) => return Ok(response),
            Err(error) => better_auth_core::observability::logger::current().error(
                "Failed to decode ID token:",
                &[better_auth_core::observability::LogArgument::Error(&error)],
            ),
        }
    }
    if let Some(access_token) = request
        .access_token
        .as_deref()
        .filter(|token| !token.is_empty())
    {
        let result = async {
            let url = provider
                .user_info_url
                .as_deref()
                .ok_or_else(|| AuthError::internal("Missing user_info_url for provider"))?;
            let Some(profile) = super::social_profile::fetch_http_profile(
                provider.user_info_request(url, access_token),
            )
            .await?
            else {
                return Ok(None);
            };
            if profile.is_null() {
                return Ok(None);
            }
            map_profile(provider, profile).await
        }
        .await;
        return match result {
            Ok(response) => Ok(response),
            Err(error) => {
                better_auth_core::observability::logger::current().error(
                    "Failed to fetch user info from Cognito:",
                    &[better_auth_core::observability::LogArgument::Error(&error)],
                );
                Ok(None)
            }
        };
    }
    Ok(None)
}
