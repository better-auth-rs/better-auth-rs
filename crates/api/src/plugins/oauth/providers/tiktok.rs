use better_auth_core::{AuthError, AuthResult};
use serde_json::Value;

use super::super::authorization::{AuthorizationRequest, RESERVED_PARAMS};
use super::{OAuthProvider, OAuthUserInfo};

pub(in crate::plugins::oauth) fn authorization_url(
    provider: &OAuthProvider,
    input: AuthorizationRequest<'_>,
) -> AuthResult<String> {
    let mut url = url::Url::parse("https://www.tiktok.com/v2/auth/authorize")
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let scopes = provider.social_scopes(input.scopes).join(",");
    let callback = provider
        .redirect_uri
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(input.callback_url);
    let _ = url.query_pairs_mut().extend_pairs([
        ("scope", scopes.as_str()),
        ("response_type", "code"),
        (
            "client_key",
            provider.client_key.as_deref().unwrap_or("undefined"),
        ),
        ("redirect_uri", callback),
        ("state", input.state),
    ]);
    for (key, value) in input.additional_params.into_iter().flatten() {
        if !RESERVED_PARAMS.contains(&key.as_str()) && key != "client_key" {
            let _ = url.query_pairs_mut().append_pair(key, value);
        }
    }
    Ok(url.to_string())
}

pub(in crate::plugins::oauth) fn decode_profile(profile: Value) -> Result<OAuthUserInfo, String> {
    let user = profile
        .pointer("/data/user")
        .ok_or("Missing TikTok user profile")?;
    let name = ["display_name", "username"]
        .into_iter()
        .find_map(|field| {
            user.get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_default();
    Ok(OAuthUserInfo {
        id: user
            .get("open_id")
            .and_then(Value::as_str)
            .ok_or("missing open_id")?
            .into(),
        email: super::defaults::profile_email(user)?,
        name: Some(name.to_owned()).into(),
        image: user
            .get("avatar_large_url")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid TikTok image: {error}"))?,
        email_verified: Some(false).into(),
        additional_fields: Default::default(),
    })
}
