use super::{
    OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use async_trait::async_trait;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use std::sync::Arc;

#[derive(Clone)]
pub(super) enum ProviderKind {
    Custom,
    Google {
        jwks_url: String,
    },
    GitHub {
        user_url: String,
        emails_url: String,
    },
    Discord,
    GitLab,
    Spotify,
    HuggingFace,
    Polar,
}

impl ProviderKind {
    pub(super) fn scopes(&self) -> &'static [&'static str] {
        match self {
            Self::Custom => &[],
            Self::Google { .. } => &["email", "profile", "openid"],
            Self::GitHub { .. } => &["read:user", "user:email"],
            Self::Discord => &["identify", "email"],
            Self::GitLab => &["read_user"],
            Self::Spotify => &["user-read-email"],
            Self::HuggingFace | Self::Polar => &["openid", "profile", "email"],
        }
    }
    pub(super) fn apply(&self, provider: &mut OAuthProvider) {
        match self {
            Self::Google { .. } => {
                let _ = provider.map_user_info.get_or_insert(google_profile);
            }
            Self::Discord => {
                let _ = provider.map_user_info.get_or_insert(discord_profile);
            }
            Self::GitLab => {
                let _ = provider.map_user_info.get_or_insert(gitlab_profile);
            }
            Self::Spotify => {
                let _ = provider.map_user_info.get_or_insert(spotify_profile);
            }
            Self::HuggingFace => {
                let _ = provider.map_user_info.get_or_insert(huggingface_profile);
            }
            Self::Polar => {
                let _ = provider.map_user_info.get_or_insert(polar_profile);
            }
            Self::GitHub {
                user_url,
                emails_url,
            } => {
                provider.get_user_info = Some(Arc::new(GitHubUserInfoHandler::new(
                    user_url.clone(),
                    emails_url.clone(),
                )));
            }
            Self::Custom => {}
        }
    }
}

fn google_profile(v: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: v
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or("missing sub")?
            .to_string(),
        email: v
            .get("email")
            .and_then(|v| v.as_str())
            .ok_or("missing email")?
            .to_string(),
        name: v.get("name").and_then(|v| v.as_str()).map(String::from),
        image: v
            .get("picture")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Google picture: {error}"))?,
        email_verified: v
            .get("email_verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

fn discord_profile(v: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: v
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("missing id")?
            .to_string(),
        email: v
            .get("email")
            .and_then(|v| v.as_str())
            .ok_or("missing email")?
            .to_string(),
        name: v.get("username").and_then(|v| v.as_str()).map(String::from),
        image: v.get("avatar").and_then(|v| v.as_str()).map(|a| {
            Some(format!(
                "https://cdn.discordapp.com/avatars/{}/{}.png",
                v.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                a
            ))
        }),
        email_verified: v.get("verified").and_then(|v| v.as_bool()).unwrap_or(false),
    })
}

fn gitlab_profile(v: Value) -> Result<OAuthUserInfo, String> {
    if v.get("state").and_then(Value::as_str) != Some("active")
        || v.get("locked").and_then(Value::as_bool) == Some(true)
    {
        return Err("GitLab user is not active or is locked".into());
    }
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: v
            .get("id")
            .and_then(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| value.as_i64().map(|value| value.to_string()))
            })
            .ok_or("missing id")?,
        email: v
            .get("email")
            .and_then(Value::as_str)
            .ok_or("missing email")?
            .into(),
        name: Some(
            v.get("name")
                .and_then(Value::as_str)
                .or_else(|| v.get("username").and_then(Value::as_str))
                .unwrap_or_default()
                .into(),
        ),
        image: v
            .get("avatar_url")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid GitLab avatar: {error}"))?,
        email_verified: v
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn spotify_profile(v: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: v
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing id")?
            .into(),
        email: v
            .get("email")
            .and_then(Value::as_str)
            .ok_or("missing email")?
            .into(),
        name: v
            .get("display_name")
            .and_then(Value::as_str)
            .map(str::to_owned),
        image: v
            .get("images")
            .and_then(Value::as_array)
            .and_then(|images| images.first())
            .and_then(|image| image.get("url"))
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Spotify image: {error}"))?,
        email_verified: false,
    })
}

fn huggingface_profile(v: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: v
            .get("sub")
            .and_then(Value::as_str)
            .ok_or("missing sub")?
            .into(),
        email: v
            .get("email")
            .and_then(Value::as_str)
            .ok_or("missing email")?
            .into(),
        name: Some(nonempty_profile_name(&v, "name", "preferred_username")),
        image: v
            .get("picture")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Hugging Face picture: {error}"))?,
        email_verified: v
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn polar_profile(v: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: v
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing id")?
            .into(),
        email: v
            .get("email")
            .and_then(Value::as_str)
            .ok_or("missing email")?
            .into(),
        name: Some(nonempty_profile_name(&v, "public_name", "username")),
        image: v
            .get("avatar_url")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Polar avatar: {error}"))?,
        email_verified: v
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn nonempty_profile_name(profile: &Value, name: &str, fallback: &str) -> String {
    [name, fallback]
        .into_iter()
        .find_map(|field| {
            profile
                .get(field)
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
        })
        .unwrap_or_default()
        .into()
}

#[derive(Debug, Deserialize)]
struct GitHubEmailAddress {
    email: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    verified: bool,
}

#[derive(Clone)]
struct GitHubUserInfoHandler {
    user_url: String,
    emails_url: String,
}

impl GitHubUserInfoHandler {
    fn new(user_url: String, emails_url: String) -> Self {
        Self {
            user_url,
            emails_url,
        }
    }

    async fn fetch_json<T: DeserializeOwned>(
        &self,
        client: &reqwest::Client,
        url: &str,
        access_token: &str,
    ) -> Result<T, String> {
        let response = client
            .get(url)
            .bearer_auth(access_token)
            .header("Accept", "application/json")
            .header("User-Agent", "better-auth")
            .send()
            .await
            .map_err(|error| format!("Failed to fetch GitHub user info: {error}"))?;

        if !response.status().is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("GitHub user info request failed: {body}"));
        }

        response
            .json()
            .await
            .map_err(|error| format!("Failed to parse GitHub user info: {error}"))
    }
}

#[async_trait]
impl OAuthUserInfoHandler for GitHubUserInfoHandler {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let access_token = request
            .access_token
            .as_deref()
            .ok_or("Missing access token for user-info lookup")?;

        let client = reqwest::Client::new();
        let mut profile: Value = self
            .fetch_json(&client, &self.user_url, access_token)
            .await?;
        let emails = self
            .fetch_json::<Vec<GitHubEmailAddress>>(&client, &self.emails_url, access_token)
            .await
            .unwrap_or_default();

        let resolved_email = profile
            .get("email")
            .and_then(Value::as_str)
            .map(String::from)
            .or_else(|| {
                emails
                    .iter()
                    .find(|record| record.primary)
                    .or_else(|| emails.first())
                    .map(|record| record.email.clone())
            })
            .unwrap_or_default();

        if let Some(profile_object) = profile.as_object_mut()
            && profile_object
                .get("email")
                .and_then(Value::as_str)
                .is_none()
            && !resolved_email.is_empty()
        {
            let _ =
                profile_object.insert("email".to_string(), Value::String(resolved_email.clone()));
        }

        let email_verified = emails
            .iter()
            .find(|record| record.email == resolved_email)
            .map(|record| record.verified)
            .unwrap_or(false);

        let id = profile
            .get("id")
            .and_then(|value| value.as_i64().map(|value| value.to_string()))
            .or_else(|| profile.get("id").and_then(Value::as_str).map(String::from))
            .ok_or("missing id")?;

        let login = profile
            .get("login")
            .and_then(Value::as_str)
            .map(String::from);

        Ok(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                additional_fields: Default::default(),
                id,
                email: resolved_email,
                name: profile
                    .get("name")
                    .and_then(Value::as_str)
                    .map(String::from)
                    .or(login),
                image: profile
                    .get("avatar_url")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|error| format!("Invalid GitHub avatar: {error}"))?,
                email_verified,
            },
            data: profile,
        })
    }
}
