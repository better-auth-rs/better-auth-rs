use better_auth_core::{AuthError, AuthResult, SchemaValue};
use serde_json::{Map, Value, json};

use super::{OAuthProvider, OAuthUserInfo, OAuthUserInfoRequest, defaults::ProviderKind};
use crate::plugins::oauth::generic_profile::decode_claims;

/// Claims requested in Twitch ID tokens.
#[derive(Clone, Default)]
pub struct TwitchOptions {
    /// Use Twitch's default claims with `None`, or replace the requested claim list.
    /// An empty list still requests email and email verification through the shared helper.
    pub claims: Option<Vec<String>>,
}

impl TwitchOptions {
    pub(in crate::plugins::oauth) fn authorization_claims(&self) -> AuthResult<String> {
        let mut claims = Map::from_iter([
            ("email".into(), Value::Null),
            ("email_verified".into(), Value::Null),
        ]);
        if let Some(requested) = &self.claims {
            claims.extend(requested.iter().map(|name| (name.clone(), Value::Null)));
        } else {
            claims.extend([
                ("preferred_username".into(), Value::Null),
                ("picture".into(), Value::Null),
            ]);
        }
        better_auth_core::utils::json::stringify(&json!({"id_token": claims})).map_err(|error| {
            AuthError::internal(format!("Failed to encode Twitch claims: {error}"))
        })
    }
}

impl OAuthProvider {
    pub(in crate::plugins::oauth) fn twitch_options(&self) -> Option<&TwitchOptions> {
        match &self.kind {
            ProviderKind::Twitch(options) => Some(options),
            _ => None,
        }
    }
}

pub(in crate::plugins::oauth) fn fetch_profile(
    request: &OAuthUserInfoRequest,
) -> AuthResult<Option<Value>> {
    let Some(token) = request
        .id_token
        .as_deref()
        .filter(|token| !token.is_empty())
    else {
        better_auth_core::observability::logger::current().error("No idToken found in token", &[]);
        return Ok(None);
    };
    decode_claims(token)
        .map(Some)
        .ok_or_else(|| AuthError::internal("Invalid Twitch ID-token claims"))
}

pub(super) fn decode_profile(profile: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: profile
            .get("sub")
            .and_then(Value::as_str)
            .ok_or("missing Twitch subject")?
            .into(),
        name: super::decode_profile_name(profile.get("preferred_username")),
        email: super::defaults::profile_email(&profile)?,
        image: profile
            .get("picture")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Twitch picture: {error}"))?,
        email_verified: SchemaValue::from_json(profile.get("email_verified").cloned()),
    })
}

#[cfg(test)]
#[path = "twitch_tests.rs"]
mod tests;
