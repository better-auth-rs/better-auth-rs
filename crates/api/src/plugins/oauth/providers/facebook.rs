use better_auth_core::{AuthError, AuthResult, SchemaValue};
use serde_json::{Value, json};

use super::{
    OAuthProvider, OAuthUserInfo, OAuthUserInfoRequest, OAuthUserInfoResponse, ProviderKind,
};
use crate::plugins::oauth::{oidc::OidcVerifier, social_profile::fetch_http_profile};

/// Facebook profile fields and additional app audiences.
#[derive(Clone, Default)]
pub struct FacebookOptions {
    /// Extra Graph fields appended after the default profile fields.
    pub fields: Vec<String>,
    /// Additional accepted audiences; requests still use the primary client ID.
    pub additional_client_ids: Vec<String>,
    #[cfg(test)]
    pub(in crate::plugins::oauth) jwks_url: Option<String>,
    #[cfg(test)]
    pub(in crate::plugins::oauth) debug_token_url: Option<String>,
}

impl OAuthProvider {
    /// Configure Facebook Graph login and verified Limited Login profiles.
    /// Set `config_id` through `authorization_params` for Facebook Login for Business.
    pub fn facebook(client_id: &str, client_secret: &str, options: FacebookOptions) -> Self {
        Self {
            kind: ProviderKind::Facebook(options),
            user_info_url: Some("https://graph.facebook.com/me".into()),
            ..Self::custom(
                client_id,
                client_secret,
                "https://www.facebook.com/v24.0/dialog/oauth",
                "https://graph.facebook.com/v24.0/oauth/access_token",
            )
        }
    }

    pub(in crate::plugins::oauth) fn facebook_options(&self) -> Option<&FacebookOptions> {
        match &self.kind {
            ProviderKind::Facebook(options) => Some(options),
            _ => None,
        }
    }
}

impl FacebookOptions {
    pub(in crate::plugins::oauth) async fn verify(
        &self,
        client_id: &str,
        token: &str,
        nonce: Option<&str>,
    ) -> AuthResult<Value> {
        let jwks_url = "https://limited.facebook.com/.well-known/oauth/openid/jwks/";
        #[cfg(test)]
        let jwks_url = self.jwks_url.as_deref().unwrap_or(jwks_url);
        let audiences = std::iter::once(client_id.to_owned())
            .chain(self.additional_client_ids.iter().cloned())
            .collect();
        let verifier = OidcVerifier::with_policy(
            jwks_url
                .parse()
                .map_err(|error: url::ParseError| AuthError::internal(error.to_string()))?,
            "https://www.facebook.com".into(),
            audiences,
            Some(vec![json!("RS256")]),
            None,
        )
        .map_err(|error| AuthError::internal(error.to_string()))?;
        verifier
            .verify(token, nonce)
            .await
            .map_err(|_| crate::plugins::oauth::id_token::invalid())
    }
}

pub(in crate::plugins::oauth) async fn fetch_user_info(
    provider: &OAuthProvider,
    options: &FacebookOptions,
    request: OAuthUserInfoRequest,
    claims: Option<Value>,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
    let (data, limited) = if let Some(claims) = claims {
        (claims, true)
    } else {
        let Some(access_token) = request
            .access_token
            .as_deref()
            .filter(|token| !token.is_empty())
        else {
            return Ok(None);
        };
        if provider.client_id.is_empty() || provider.client_secret.is_empty() {
            return Ok(None);
        }
        let debug_url = "https://graph.facebook.com/debug_token";
        #[cfg(test)]
        let debug_url = options.debug_token_url.as_deref().unwrap_or(debug_url);
        let inspection = reqwest::Client::new().get(debug_url).query(&[
            ("input_token", access_token),
            (
                "access_token",
                &format!("{}|{}", provider.client_id, provider.client_secret),
            ),
        ]);
        let Some(inspection) = fetch_http_profile(inspection).await? else {
            return Ok(None);
        };
        let Some(data) = inspection.get("data") else {
            return Ok(None);
        };
        let Some(app_id) = data
            .get("app_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            return Ok(None);
        };
        let Some(user_id) = data
            .get("user_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            return Ok(None);
        };
        if data.get("is_valid") != Some(&Value::Bool(true))
            || (app_id != provider.client_id
                && !options.additional_client_ids.iter().any(|id| id == app_id))
        {
            return Ok(None);
        }
        let endpoint = provider
            .user_info_url
            .as_deref()
            .ok_or_else(|| AuthError::internal("Missing user_info_url for provider"))?;
        let fields = ["id", "name", "email", "picture"]
            .into_iter()
            .chain(options.fields.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(",");
        let profile = reqwest::Client::new()
            .get(endpoint)
            .query(&[("fields", fields)])
            .bearer_auth(access_token);
        let Some(profile) = fetch_http_profile(profile).await? else {
            return Ok(None);
        };
        if profile.get("id").and_then(Value::as_str) != Some(user_id) {
            return Ok(None);
        }
        (profile, false)
    };
    let user = if let Some(decode) = provider.map_user_info {
        decode(data.clone())
    } else {
        decode_profile(&data, limited)
    }
    .map_err(AuthError::internal)?;
    let mut response = OAuthUserInfoResponse { user, data };
    if let Some(mapper) = &provider.map_profile_to_user {
        let mapped = mapper.map_profile(&response.data).await?;
        crate::plugins::oauth::social_profile::apply_mapped_profile(&mut response, mapped);
    }
    let _ = response.user.email()?;
    let _ = response.user.email_verified()?;
    Ok(Some(response))
}

pub(super) fn graph_profile(profile: Value) -> Result<OAuthUserInfo, String> {
    decode_profile(&profile, false)
}

fn decode_profile(profile: &Value, limited: bool) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        id: profile
            .get(if limited { "sub" } else { "id" })
            .and_then(Value::as_str)
            .ok_or("missing Facebook subject")?
            .into(),
        name: serde_json::from_value(profile.get("name").cloned().unwrap_or(Value::Null))
            .map_err(|error| format!("Invalid Facebook name: {error}"))?,
        email: super::defaults::profile_email(profile)?,
        image: (if limited {
            profile.get("picture")
        } else {
            profile.pointer("/picture/data/url")
        })
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| format!("Invalid Facebook picture: {error}"))?,
        email_verified: if limited {
            Some(false).into()
        } else {
            SchemaValue::from_json(Some(
                profile
                    .get("email_verified")
                    .filter(|value| !value.is_null())
                    .cloned()
                    .unwrap_or(Value::Bool(false)),
            ))
        },
        additional_fields: Default::default(),
    })
}
