use std::sync::Arc;

use async_trait::async_trait;
use better_auth_core::{AuthError, AuthResult, SchemaValue};
use serde_json::{Map, Value};

use super::{
    GenericOAuthConfig, GenericOAuthUserInfoHandler, OAuthAccountSubject, OAuthUserInfoRequest,
    TokenEndpointSecretAuthentication,
};
use crate::plugins::json_body::is_truthy;

impl GenericOAuthConfig {
    /// Configure Gumroad with its `view_profile` scope and user profile endpoint.
    pub fn gumroad(client_id: &str, client_secret: &str) -> Self {
        Preset::Gumroad.config(client_id, client_secret)
    }

    /// Configure HubSpot with its `oauth` scope and access-token profile lookup.
    pub fn hubspot(client_id: &str, client_secret: &str) -> Self {
        Preset::HubSpot.config(client_id, client_secret)
    }

    /// Configure Patreon with its `identity[email]` scope and identity fields.
    pub fn patreon(client_id: &str, client_secret: &str) -> Self {
        Preset::Patreon.config(client_id, client_secret)
    }

    /// Configure Slack with its OpenID scopes and userinfo profile mapping.
    pub fn slack(client_id: &str, client_secret: &str) -> Self {
        Preset::Slack.config(client_id, client_secret)
    }

    /// Configure Yandex with its info, email, and avatar scopes.
    pub fn yandex(client_id: &str, client_secret: &str) -> Self {
        Preset::Yandex.config(client_id, client_secret)
    }
}

#[derive(Clone, Copy)]
enum Preset {
    Gumroad,
    HubSpot,
    Patreon,
    Slack,
    Yandex,
}

impl Preset {
    fn config(self, client_id: &str, client_secret: &str) -> GenericOAuthConfig {
        let (authorization, token, scopes): (_, _, &[&str]) = match self {
            Self::Gumroad => (
                "https://gumroad.com/oauth/authorize",
                "https://api.gumroad.com/oauth/token",
                &["view_profile"],
            ),
            Self::HubSpot => (
                "https://app.hubspot.com/oauth/authorize",
                "https://api.hubapi.com/oauth/v1/token",
                &["oauth"],
            ),
            Self::Patreon => (
                "https://www.patreon.com/oauth2/authorize",
                "https://www.patreon.com/api/oauth2/token",
                &["identity[email]"],
            ),
            Self::Slack => (
                "https://slack.com/openid/connect/authorize",
                "https://slack.com/api/openid.connect.token",
                &["openid", "profile", "email"],
            ),
            Self::Yandex => (
                "https://oauth.yandex.com/authorize",
                "https://oauth.yandex.com/token",
                &["login:info", "login:email", "login:avatar"],
            ),
        };
        GenericOAuthConfig {
            client_id: client_id.into(),
            client_secret: Some(client_secret.into()),
            authorization_url: Some(authorization.into()),
            token_url: Some(token.into()),
            user_info_url: matches!(self, Self::Slack).then(|| self.profile_endpoint().into()),
            scopes: scopes.iter().map(|scope| (*scope).into()).collect(),
            authentication: matches!(self, Self::HubSpot)
                .then_some(TokenEndpointSecretAuthentication::Post),
            get_user_info: Some(Arc::new(PresetProfile {
                preset: self,
                endpoint: self.profile_endpoint().into(),
            })),
            account_subject: Some(Arc::new(self)),
            ..Default::default()
        }
    }

    fn profile_endpoint(self) -> &'static str {
        match self {
            Self::Gumroad => "https://api.gumroad.com/v2/user",
            Self::HubSpot => "https://api.hubapi.com/oauth/v1/access-tokens/",
            Self::Patreon => "https://www.patreon.com/api/oauth2/v2/identity",
            Self::Slack => "https://slack.com/api/openid.connect.userInfo",
            Self::Yandex => "https://login.yandex.ru/info?format=json",
        }
    }

    fn profile(self, response: Value) -> AuthResult<Value> {
        if !is_truthy(&response) {
            return Ok(Value::Null);
        }
        let mut profile = Map::new();
        match self {
            Self::Gumroad => {
                let Some(user) = response.get("user").filter(|value| is_truthy(value)) else {
                    return Ok(Value::Null);
                };
                if !response.get("success").is_some_and(is_truthy) {
                    return Ok(Value::Null);
                }
                copy_fields(
                    &mut profile,
                    user,
                    &[
                        ("user_id", "id"),
                        ("name", "name"),
                        ("email", "email"),
                        ("profile_url", "image"),
                    ],
                );
                let _ = profile.insert("emailVerified".into(), Value::Bool(false));
            }
            Self::HubSpot => {
                let id = response
                    .get("user_id")
                    .filter(|value| !value.is_null())
                    .or_else(|| response.pointer("/signed_access_token/userId"));
                let Some(id) = id.filter(|value| is_truthy(value)) else {
                    return Ok(Value::Null);
                };
                let _ = profile.insert("id".into(), id.clone());
                copy_fields(
                    &mut profile,
                    &response,
                    &[("user", "name"), ("user", "email")],
                );
                let _ = profile.insert("emailVerified".into(), Value::Bool(false));
            }
            Self::Patreon => {
                let data = response
                    .get("data")
                    .filter(|value| !value.is_null())
                    .ok_or_else(|| AuthError::internal("Missing Patreon profile data"))?;
                let attributes = data
                    .get("attributes")
                    .filter(|value| !value.is_null())
                    .ok_or_else(|| AuthError::internal("Missing Patreon profile attributes"))?;
                copy_fields(&mut profile, data, &[("id", "id")]);
                copy_fields(
                    &mut profile,
                    attributes,
                    &[
                        ("full_name", "name"),
                        ("email", "email"),
                        ("image_url", "image"),
                        ("is_email_verified", "emailVerified"),
                    ],
                );
            }
            Self::Slack => {
                copy_fields(
                    &mut profile,
                    &response,
                    &[("sub", "sub"), ("name", "name"), ("email", "email")],
                );
                if let Some(image) = response
                    .get("picture")
                    .filter(|value| !value.is_null())
                    .or_else(|| response.get("https://slack.com/user_image_512"))
                {
                    let _ = profile.insert("image".into(), image.clone());
                }
                let verified = response
                    .get("email_verified")
                    .filter(|value| !value.is_null())
                    .cloned()
                    .unwrap_or(Value::Bool(false));
                let _ = profile.insert("emailVerified".into(), verified);
            }
            Self::Yandex => {
                let email = response
                    .get("default_email")
                    .filter(|value| !value.is_null())
                    .or_else(|| response.pointer("/emails/0"));
                let Some(email) = email.filter(|value| is_truthy(value)) else {
                    return Ok(Value::Null);
                };
                copy_fields(&mut profile, &response, &[("id", "id")]);
                if let Some(name) = ["display_name", "real_name", "first_name"]
                    .into_iter()
                    .find_map(|key| response.get(key).filter(|value| !value.is_null()))
                    .or_else(|| response.get("login"))
                {
                    let _ = profile.insert("name".into(), name.clone());
                }
                let _ = profile.insert("email".into(), email.clone());
                let _ = profile.insert("emailVerified".into(), Value::Bool(false));
                if !response.get("is_avatar_empty").is_some_and(is_truthy)
                    && let Some(avatar) = response
                        .get("default_avatar_id")
                        .filter(|value| is_truthy(value))
                {
                    let avatar = SchemaValue::<Value>::Dynamic(avatar.clone()).display_string()?;
                    let _ = profile.insert(
                        "image".into(),
                        Value::String(format!(
                            "https://avatars.yandex.net/get-yapic/{avatar}/islands-200"
                        )),
                    );
                }
            }
        }
        Ok(Value::Object(profile))
    }
}

fn copy_fields(target: &mut Map<String, Value>, source: &Value, fields: &[(&str, &str)]) {
    target.extend(
        fields
            .iter()
            .filter_map(|(from, to)| source.get(*from).map(|value| ((*to).into(), value.clone()))),
    );
}

struct PresetProfile {
    preset: Preset,
    endpoint: String,
}

impl PresetProfile {
    fn request(&self, tokens: &OAuthUserInfoRequest) -> reqwest::RequestBuilder {
        let access_token = tokens.access_token.as_deref().unwrap_or("undefined");
        let client = reqwest::Client::new();
        match self.preset {
            Preset::HubSpot => client
                .get(format!("{}{access_token}", self.endpoint))
                .header("content-type", "application/json"),
            Preset::Yandex => client
                .get(&self.endpoint)
                .header("authorization", format!("OAuth {access_token}")),
            Preset::Patreon => client
                .get(&self.endpoint)
                .query(&[(
                    "fields[user]",
                    "email,full_name,image_url,is_email_verified",
                )])
                .bearer_auth(access_token),
            _ => client.get(&self.endpoint).bearer_auth(access_token),
        }
    }
}

#[async_trait]
impl GenericOAuthUserInfoHandler for PresetProfile {
    async fn get_user_info(&self, tokens: &OAuthUserInfoRequest) -> AuthResult<Option<Value>> {
        match super::social_profile::fetch_http_profile(self.request(tokens)).await? {
            Some(profile) => self
                .preset
                .profile(profile)
                .map(|profile| (!profile.is_null()).then_some(profile)),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl OAuthAccountSubject for Preset {
    async fn resolve_subject(
        &self,
        _: &OAuthUserInfoRequest,
        profile: &Value,
    ) -> AuthResult<String> {
        let field = if matches!(self, Self::Slack) {
            "sub"
        } else {
            "id"
        };
        SchemaValue::<Value>::Dynamic(
            profile
                .get(field)
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or_else(|| Value::String(String::new())),
        )
        .display_string()
    }
}

#[cfg(test)]
#[path = "generic_presets_tests.rs"]
mod tests;
