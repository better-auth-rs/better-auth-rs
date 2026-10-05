use better_auth_core::{AuthError, AuthResult};
use serde_json::Value;

use super::{OAuthProvider, OAuthUserInfo, OAuthUserInfoRequest, OAuthUserInfoResponse};
use crate::plugins::oauth::social_profile::fetch_http_profile;

pub(in crate::plugins::oauth) async fn fetch_user_info(
    provider: &OAuthProvider,
    request: &OAuthUserInfoRequest,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
    let endpoint = provider
        .user_info_url
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing user_info_url for provider"))?;
    let access_token = request
        .access_token
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing access token for user-info lookup"))?;
    let mut url = url::Url::parse(endpoint)
        .map_err(|error| AuthError::internal(format!("Invalid Twitter user-info URL: {error}")))?;
    let _ = url
        .query_pairs_mut()
        .clear()
        .append_pair("user.fields", "profile_image_url");
    let Some(mut profile) =
        fetch_http_profile(provider.user_info_request(url.as_str(), access_token)).await?
    else {
        return Ok(None);
    };
    let _ = url
        .query_pairs_mut()
        .clear()
        .append_pair("user.fields", "confirmed_email");
    let email_profile =
        fetch_http_profile(provider.user_info_request(url.as_str(), access_token)).await?;
    let confirmed_email = email_profile
        .as_ref()
        .and_then(|profile| profile.pointer("/data/confirmed_email"))
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| AuthError::internal("Invalid Twitter confirmed email"))
        })
        .transpose()?
        .filter(|email| !email.is_empty());
    if let Some(email) = confirmed_email {
        let data = profile
            .get_mut("data")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| AuthError::internal("Missing Twitter profile data"))?;
        let _ = data.insert("email".into(), email.into());
    }
    let Some(mut user) = provider.decode_profile(profile.clone())? else {
        return Ok(None);
    };
    if provider.map_user_info.is_none() {
        user.email_verified = Some(confirmed_email.is_some()).into();
    }
    Ok(Some(OAuthUserInfoResponse {
        user,
        data: profile,
    }))
}

pub(super) fn decode_profile(profile: Value) -> Result<OAuthUserInfo, String> {
    let data = profile.get("data").ok_or("Missing Twitter profile data")?;
    Ok(OAuthUserInfo {
        id: data
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing id")?
            .into(),
        name: data
            .get("name")
            .cloned()
            .map(serde_json::from_value::<Option<String>>)
            .transpose()
            .map(|value| value.map(Into::into).unwrap_or_default())
            .map_err(|error| format!("Invalid Twitter name: {error}"))?,
        email: super::defaults::profile_email(data)?,
        image: data
            .get("profile_image_url")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Twitter picture: {error}"))?,
        email_verified: Some(false).into(),
        additional_fields: Default::default(),
    })
}
