use super::{OAuthUserInfo, OAuthUserInfoRequest, OAuthUserInfoResponse};
use better_auth_core::{AuthError, AuthResult, SchemaValue};
use serde::Deserialize;
use serde_json::Value;

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
    Vercel,

    Figma,
    Dropbox,
    Kick,
    LinkedIn,
    Slack,
    Naver,
    Linear,
    Cloudflare,
}

impl ProviderKind {
    pub(super) fn scopes(&self) -> &'static [&'static str] {
        match self {
            Self::Custom | Self::Vercel => &[],
            Self::Google { .. } => &["email", "profile", "openid"],
            Self::GitHub { .. } => &["read:user", "user:email"],
            Self::Discord => &["identify", "email"],
            Self::GitLab => &["read_user"],
            Self::Spotify => &["user-read-email"],
            Self::HuggingFace | Self::Polar | Self::Slack => &["openid", "profile", "email"],
            Self::Figma => &["current_user:read"],
            Self::Dropbox => &["account_info.read"],
            Self::Kick => &["user:read"],
            Self::LinkedIn => &["profile", "email", "openid"],
            Self::Naver => &["profile", "email"],
            Self::Linear => &["read"],
            Self::Cloudflare => &["user-details.read"],
        }
    }
    pub(super) fn decode_profile(&self, profile: Value) -> AuthResult<Option<OAuthUserInfo>> {
        let mapper = match self {
            Self::Google { .. } => google_profile,
            Self::Discord => discord_profile,
            Self::GitLab => {
                if profile.get("state").and_then(Value::as_str) != Some("active")
                    || profile.get("locked").and_then(Value::as_bool) == Some(true)
                {
                    return Ok(None);
                }
                gitlab_profile
            }
            Self::Spotify => spotify_profile,
            Self::HuggingFace => huggingface_profile,
            Self::Polar => polar_profile,
            Self::Vercel if profile.is_null() => return Ok(None),
            Self::Figma if profile.is_null() => return Ok(None),
            Self::Vercel => vercel_profile,
            Self::Figma => figma_profile,
            Self::Dropbox => dropbox_profile,
            Self::Kick => kick_profile,
            Self::LinkedIn => linkedin_profile,
            Self::Slack => slack_profile,
            Self::Naver if profile.get("resultcode").and_then(Value::as_str) != Some("00") => {
                return Ok(None);
            }
            Self::Naver => naver_profile,
            Self::Linear => linear_profile,
            Self::Cloudflare => cloudflare_profile,
            Self::GitHub { .. } | Self::Custom => {
                return Err(AuthError::internal("Missing user-info mapper for provider"));
            }
        };
        mapper(profile).map(Some).map_err(AuthError::internal)
    }
}

fn profile_email(profile: &Value) -> Result<SchemaValue<Option<String>>, String> {
    profile
        .get("email")
        .cloned()
        .map(serde_json::from_value::<Option<String>>)
        .transpose()
        .map(|value| value.map(SchemaValue::Typed).unwrap_or_default())
        .map_err(|error| format!("Invalid provider email: {error}"))
}

fn google_profile(v: Value) -> Result<OAuthUserInfo, String> {
    openid_profile(v, "Google")
}

fn linkedin_profile(v: Value) -> Result<OAuthUserInfo, String> {
    openid_profile(v, "LinkedIn")
}

fn slack_profile(v: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: v
            .get("https://slack.com/user_id")
            .and_then(Value::as_str)
            .ok_or("missing Slack user_id")?
            .into(),
        email: profile_email(&v)?,
        name: Some(
            v.get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into(),
        ),
        image: v
            .get("picture")
            .filter(|value| !value.is_null() && value.as_str() != Some(""))
            .or_else(|| v.get("https://slack.com/user_image_512"))
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Slack picture: {error}"))?,
        email_verified: v
            .get("email_verified")
            .and_then(Value::as_bool)
            .ok_or("missing email_verified")?,
    })
}

fn naver_profile(v: Value) -> Result<OAuthUserInfo, String> {
    let response = v.get("response").ok_or("missing response")?;
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: response
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing id")?
            .into(),
        email: profile_email(response)?,
        name: Some(nonempty_profile_name(response, "name", "nickname")),
        image: response
            .get("profile_image")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Naver profile image: {error}"))?,
        email_verified: false,
    })
}

fn linear_profile(v: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: v
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing id")?
            .into(),
        email: profile_email(&v)?,
        name: v.get("name").and_then(Value::as_str).map(str::to_owned),
        image: v
            .get("avatarUrl")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Linear avatar: {error}"))?,
        email_verified: false,
    })
}

fn openid_profile(v: Value, provider: &str) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: v
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or("missing sub")?
            .to_string(),
        email: profile_email(&v)?,
        name: v.get("name").and_then(|v| v.as_str()).map(String::from),
        image: v
            .get("picture")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid {provider} picture: {error}"))?,
        email_verified: v
            .get("email_verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

pub(super) fn prepare_discord_profile(profile: &mut Value) -> Result<(), String> {
    let id = profile
        .get("id")
        .and_then(Value::as_str)
        .ok_or("missing id")?;
    let image = if profile.get("avatar") == Some(&Value::Null) {
        let discriminator = profile
            .get("discriminator")
            .and_then(Value::as_str)
            .ok_or("missing discriminator")?;
        let index = if discriminator == "0" {
            (id.parse::<u64>()
                .map_err(|error| format!("Invalid Discord snowflake: {error}"))?
                >> 22)
                % 6
        } else {
            discriminator
                .parse::<u64>()
                .map_err(|error| format!("Invalid Discord discriminator: {error}"))?
                % 5
        };
        format!("https://cdn.discordapp.com/embed/avatars/{index}.png")
    } else {
        let avatar = profile
            .get("avatar")
            .and_then(Value::as_str)
            .ok_or("missing avatar")?;
        let extension = if avatar.starts_with("a_") {
            "gif"
        } else {
            "png"
        };
        format!("https://cdn.discordapp.com/avatars/{id}/{avatar}.{extension}")
    };
    let _ = profile
        .as_object_mut()
        .ok_or("Discord profile must be an object")?
        .insert("image_url".into(), Value::String(image));
    Ok(())
}

fn discord_profile(v: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: v
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("missing id")?
            .to_string(),
        email: profile_email(&v)?,
        name: Some(nonempty_profile_name(&v, "global_name", "username")),
        image: v
            .get("image_url")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Discord image: {error}"))?,
        email_verified: v.get("verified").and_then(|v| v.as_bool()).unwrap_or(false),
    })
}

fn gitlab_profile(v: Value) -> Result<OAuthUserInfo, String> {
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
        email: profile_email(&v)?,
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
        email: profile_email(&v)?,
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
        email: profile_email(&v)?,
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
        email: profile_email(&v)?,
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

fn vercel_profile(v: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: v
            .get("sub")
            .and_then(Value::as_str)
            .ok_or("missing sub")?
            .into(),
        email: profile_email(&v)?,
        name: Some(
            v.get("name")
                .and_then(Value::as_str)
                .or_else(|| v.get("preferred_username").and_then(Value::as_str))
                .unwrap_or_default()
                .into(),
        ),
        image: v
            .get("picture")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Vercel picture: {error}"))?,
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

fn dropbox_profile(v: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: v
            .get("account_id")
            .and_then(Value::as_str)
            .ok_or("missing account_id")?
            .into(),
        email: profile_email(&v)?,
        name: v
            .get("name")
            .and_then(|name| name.get("display_name"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        image: v
            .get("profile_photo_url")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Dropbox image: {error}"))?,
        email_verified: v
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn figma_profile(v: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: v
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing id")?
            .into(),
        email: profile_email(&v)?,
        name: v.get("handle").and_then(Value::as_str).map(str::to_owned),
        image: v
            .get("img_url")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Figma image: {error}"))?,
        email_verified: false,
    })
}

fn cloudflare_profile(v: Value) -> Result<OAuthUserInfo, String> {
    let email = profile_email(&v)?;
    let name = ["first_name", "last_name"]
        .into_iter()
        .filter_map(|field| v.get(field).and_then(Value::as_str))
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    Ok(OAuthUserInfo {
        id: v
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing id")?
            .into(),
        email,
        name: if name.is_empty() {
            v.get("email").and_then(Value::as_str).map(str::to_owned)
        } else {
            Some(name)
        },
        image: None,
        email_verified: false,
        additional_fields: Default::default(),
    })
}

fn kick_profile(v: Value) -> Result<OAuthUserInfo, String> {
    Ok(OAuthUserInfo {
        additional_fields: Default::default(),
        id: v
            .get("user_id")
            .and_then(Value::as_u64)
            .ok_or("missing user_id")?
            .to_string(),
        email: profile_email(&v)?,
        name: v.get("name").and_then(Value::as_str).map(str::to_owned),
        image: v
            .get("profile_picture")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("Invalid Kick image: {error}"))?,
        email_verified: false,
    })
}

#[derive(Debug, Deserialize)]
struct GitHubEmailAddress {
    email: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    verified: bool,
}

pub(in crate::plugins::oauth) async fn github_profile(
    user_url: &str,
    emails_url: &str,
    request: &OAuthUserInfoRequest,
) -> AuthResult<Option<OAuthUserInfoResponse>> {
    let access_token = request
        .access_token
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing access token for user-info lookup"))?;
    let client = reqwest::Client::new();
    let get = |url: &str| {
        client
            .get(url)
            .bearer_auth(access_token)
            .header("Accept", "application/json")
            .header("User-Agent", "better-auth")
    };
    let Some(mut profile) = super::super::social_profile::fetch_http_profile(get(user_url)).await?
    else {
        return Ok(None);
    };
    let emails = super::super::social_profile::fetch_http_profile(get(emails_url))
        .await?
        .filter(|value| !value.is_null())
        .map(serde_json::from_value::<Vec<GitHubEmailAddress>>)
        .transpose()?;

    let mut email = profile_email(&profile).map_err(AuthError::internal)?;
    if super::profile_email(&email)?.is_none_or(str::is_empty)
        && let Some(emails) = &emails
        && let Some(profile_object) = profile.as_object_mut()
    {
        if let Some(record) = emails
            .iter()
            .find(|record| record.primary)
            .or_else(|| emails.first())
        {
            let _ = profile_object.insert("email".to_string(), Value::String(record.email.clone()));
            email = SchemaValue::Typed(Some(record.email.clone()));
        } else {
            let _ = profile_object.remove("email");
            email = SchemaValue::Undefined;
        }
    }

    let resolved_email = super::profile_email(&email)?;
    let email_verified = emails
        .as_ref()
        .and_then(|emails| {
            emails
                .iter()
                .find(|record| Some(record.email.as_str()) == resolved_email)
        })
        .is_some_and(|record| record.verified);

    let id = profile
        .get("id")
        .and_then(|value| value.as_i64().map(|value| value.to_string()))
        .or_else(|| profile.get("id").and_then(Value::as_str).map(String::from))
        .ok_or_else(|| AuthError::internal("missing id"))?;

    let login = profile
        .get("login")
        .and_then(Value::as_str)
        .map(String::from);

    Ok(Some(OAuthUserInfoResponse {
        user: OAuthUserInfo {
            additional_fields: Default::default(),
            id,
            email,
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
                .map_err(|error| AuthError::internal(format!("Invalid GitHub avatar: {error}")))?,
            email_verified,
        },
        data: profile,
    }))
}
