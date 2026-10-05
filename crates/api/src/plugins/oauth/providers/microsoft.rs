use std::{sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use better_auth_core::{AuthError, AuthResult, SchemaValue};
use serde_json::Value;

use super::{OAuthProvider, OAuthUserInfo, OAuthUserInfoRequest, OAuthUserInfoResponse};
use crate::plugins::oauth::{
    ClientAssertion, generic_profile::decode_claims, id_token, oidc::OidcVerifier,
};

const CONSUMER_TENANT: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

/// Microsoft Graph profile photo dimensions supported by the upstream provider.
#[derive(Clone, Copy, Debug, Default)]
pub enum MicrosoftProfilePhotoSize {
    #[default]
    Size48,
    Size64,
    Size96,
    Size120,
    Size240,
    Size360,
    Size432,
    Size504,
    Size648,
}

impl MicrosoftProfilePhotoSize {
    fn pixels(self) -> u16 {
        match self {
            Self::Size48 => 48,
            Self::Size64 => 64,
            Self::Size96 => 96,
            Self::Size120 => 120,
            Self::Size240 => 240,
            Self::Size360 => 360,
            Self::Size432 => 432,
            Self::Size504 => 504,
            Self::Size648 => 648,
        }
    }
}

/// Social Microsoft options. Generic Entra uses `GenericOAuthConfig::microsoft_entra_id`.
#[derive(Clone, Default)]
pub struct MicrosoftOptions {
    /// Omission or an empty value selects `common`.
    pub tenant_id: Option<String>,
    /// Omission or an empty value selects `https://login.microsoftonline.com`.
    pub authority: Option<String>,
    pub profile_photo_size: MicrosoftProfilePhotoSize,
    pub disable_profile_photo: bool,
    /// Additional accepted ID-token audiences. The provider client ID remains primary.
    pub additional_client_ids: Vec<String>,
    /// Obtain an assertion for each code or refresh grant instead of using a secret.
    pub client_assertion: Option<Arc<dyn ClientAssertion>>,
    #[cfg(test)]
    pub(in crate::plugins::oauth) jwks_url: Option<String>,
    #[cfg(test)]
    pub(in crate::plugins::oauth) photo_url: Option<String>,
}

impl MicrosoftOptions {
    pub(in crate::plugins::oauth) fn tenant(&self) -> &str {
        self.tenant_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("common")
    }

    pub(in crate::plugins::oauth) fn authority(&self) -> &str {
        self.authority
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("https://login.microsoftonline.com")
            .trim_end_matches('/')
    }

    pub(in crate::plugins::oauth) fn photo_endpoint(&self) -> String {
        let size = self.profile_photo_size.pixels();
        format!("https://graph.microsoft.com/v1.0/me/photos/{size}x{size}/$value")
    }

    pub(in crate::plugins::oauth) async fn verify(
        &self,
        client_id: &str,
        token: &str,
        nonce: Option<&str>,
    ) -> AuthResult<Value> {
        let decoded = decode_claims(token).ok_or_else(id_token::invalid)?;
        let tid = decoded
            .get("tid")
            .and_then(Value::as_str)
            .ok_or_else(id_token::invalid)?;
        let tenant = self.tenant();
        let authority = self.authority();
        // Dynamic tenant claims select only the issuer below the configured authority.
        // The same token must then pass the existing signature and claims verifier.
        let issuer_tenant = match tenant {
            "common" | "organizations" | "consumers" => tid,
            specific => specific,
        };
        let issuer = format!("{authority}/{issuer_tenant}/v2.0");
        let jwks_url = format!("{authority}/{tenant}/discovery/v2.0/keys");
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
        let claims = verifier
            .verify(token, nonce)
            .await
            .map_err(|_| id_token::invalid())?;
        let tid = claims
            .get("tid")
            .and_then(Value::as_str)
            .ok_or_else(id_token::invalid)?;
        if claims.get("iss").and_then(Value::as_str)
            != Some(format!("{authority}/{tid}/v2.0").as_str())
            || tenant == "organizations" && tid == CONSUMER_TENANT
            || tenant == "consumers" && tid != CONSUMER_TENANT
        {
            return Err(id_token::invalid());
        }
        Ok(claims)
    }
}

pub(in crate::plugins::oauth) fn decode_profile(profile: Value) -> Result<OAuthUserInfo, String> {
    let email_verified = profile.get("email_verified").cloned().unwrap_or_else(|| {
        let verified = profile
            .get("email")
            .and_then(Value::as_str)
            .filter(|email| !email.is_empty())
            .is_some_and(|email| {
                ["verified_primary_email", "verified_secondary_email"]
                    .into_iter()
                    .any(|field| {
                        profile
                            .get(field)
                            .and_then(Value::as_array)
                            .is_some_and(|values| {
                                values.iter().any(|value| value.as_str() == Some(email))
                            })
                    })
            });
        Value::Bool(verified)
    });
    Ok(OAuthUserInfo {
        id: profile
            .get("oid")
            .and_then(Value::as_str)
            .ok_or("missing oid")?
            .into(),
        name: super::decode_profile_name(profile.get("name")),
        email: super::defaults::profile_email(&profile)?,
        image: profile
            .get("picture")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Microsoft picture: {error}"))?,
        email_verified: SchemaValue::from_json(Some(email_verified)),
        additional_fields: Default::default(),
    })
}

pub(in crate::plugins::oauth) async fn fetch_user_info(
    provider: &OAuthProvider,
    options: &MicrosoftOptions,
    request: OAuthUserInfoRequest,
    claims: Option<Value>,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
    let mut data = match claims {
        Some(claims) => claims,
        None => {
            let Some(token) = request
                .id_token
                .as_deref()
                .filter(|token| !token.is_empty())
            else {
                return Ok(None);
            };
            decode_claims(token).ok_or_else(|| AuthError::internal("Invalid Microsoft ID token"))?
        }
    };
    if data
        .get("oid")
        .and_then(Value::as_str)
        .is_none_or(|oid| oid.trim().is_empty())
    {
        better_auth_core::observability::logger::current().error(
            "Microsoft Entra ID token did not include a valid oid claim; unable to resolve a stable account identifier.", &[],
        );
        return Ok(None);
    }
    if !options.disable_profile_photo
        && let Some(access_token) = request
            .access_token
            .as_deref()
            .filter(|token| !token.is_empty())
    {
        let photo_url = options.photo_endpoint();
        #[cfg(test)]
        let photo_url = options
            .photo_url
            .as_deref()
            .unwrap_or(&photo_url)
            .to_owned();
        let response = reqwest::Client::new()
            .get(photo_url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|error| {
                AuthError::internal(format!("Microsoft photo request failed: {error}"))
            })?;
        if response.status().is_success() {
            match response.bytes().await {
                Ok(bytes) => {
                    let image = format!("data:image/jpeg;base64, {}", STANDARD.encode(bytes));
                    let _ = data
                        .as_object_mut()
                        .ok_or_else(|| AuthError::internal("Microsoft profile must be an object"))?
                        .insert("picture".into(), Value::String(image));
                }
                Err(error) => better_auth_core::observability::logger::current().error(
                    "Failed to read Microsoft profile photo",
                    &[better_auth_core::observability::LogArgument::Error(&error)],
                ),
            }
        }
    }
    let mapped = match &provider.map_profile_to_user {
        Some(mapper) => Some(mapper.map_profile(&data).await?),
        None => None,
    };
    let mut response = OAuthUserInfoResponse {
        user: decode_profile(data.clone()).map_err(AuthError::internal)?,
        data,
    };
    if let Some(mapped) = mapped {
        crate::plugins::oauth::social_profile::apply_mapped_profile(&mut response, mapped);
    }
    let _ = response.user.email()?;
    let _ = response.user.email_verified()?;
    Ok(Some(response))
}
