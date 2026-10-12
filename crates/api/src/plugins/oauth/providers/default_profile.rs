//! Default Social profiles retain native values through mapper and object-literal evaluation.

use better_auth_core::{AuthError, AuthResult, FieldMap, FieldValue, Utf16String};

use super::ProviderKind;

#[path = "default_profile_fields.rs"]
mod fields;
#[path = "http_profile.rs"]
mod http;
use crate::plugins::oauth::{OAuthProfileMapper, social_profile::ProviderProfile};

impl ProviderKind {
    pub(in crate::plugins::oauth) async fn native_default_profile(
        &self,
        profile: &FieldValue,
        source: &FieldValue,
        mapper: Option<&dyn OAuthProfileMapper>,
    ) -> AuthResult<Option<ProviderProfile>> {
        let construct: fn(&FieldValue) -> AuthResult<FieldMap> = match self {
            Self::Google { .. } => fields::google,
            Self::Discord => fields::discord,
            Self::GitLab => fields::gitlab,
            Self::Spotify => fields::spotify,
            Self::HuggingFace => fields::huggingface,
            Self::Polar => fields::polar,
            Self::Railway | Self::Atlassian => fields::unverified_openid,
            Self::Roblox => fields::roblox,
            Self::Notion => fields::notion,
            Self::Vercel => fields::vercel,
            Self::Figma => fields::figma,
            Self::Dropbox => fields::dropbox,
            Self::Kick => fields::kick,
            Self::LinkedIn => fields::linkedin,
            Self::Slack => fields::slack,
            Self::Naver => fields::naver,
            Self::Linear => fields::linear,
            Self::Kakao => fields::kakao,
            Self::Zoom { .. } => fields::zoom,
            Self::Salesforce => fields::salesforce,
            Self::Vk => fields::vk,
            Self::TikTok => fields::tiktok,
            Self::Reddit => return reddit(profile, mapper).await.map(Some),
            Self::Cloudflare => return cloudflare(profile, mapper).await.map(Some),
            _ => return Ok(None),
        };
        if matches!(self, Self::GitLab)
            && (!profile
                .model_property("state")?
                .strict_equals(&"active".into())
                || profile.model_property("locked")?.is_truthy())
        {
            return Ok(Some(ProviderProfile::default()));
        }
        if matches!(
            self,
            Self::Railway
                | Self::Atlassian
                | Self::Vercel
                | Self::Figma
                | Self::Salesforce
                | Self::Kakao
                | Self::Naver
        ) && !profile.is_truthy()
        {
            return Ok(Some(ProviderProfile::default()));
        }
        if matches!(self, Self::Naver)
            && !profile
                .model_property("resultcode")?
                .strict_equals(&"00".into())
        {
            return Ok(Some(ProviderProfile::default()));
        }
        let mapped = if matches!(self, Self::TikTok) {
            FieldValue::Undefined
        } else {
            map_profile(profile, mapper).await?
        };
        if matches!(self, Self::Vk)
            && !profile
                .model_property("user")?
                .model_property("email")?
                .is_truthy()
            && !optional_property(&mapped, "email")?.is_truthy()
        {
            return Ok(Some(ProviderProfile::default()));
        }
        let literal_source = if matches!(self, Self::Linear) {
            source
        } else {
            profile
        };
        let user = spread(construct(literal_source)?, &mapped)?;
        let data = if matches!(self, Self::Roblox | Self::Zoom { .. }) {
            profile.enumerable_fields()?.into()
        } else {
            profile.clone()
        };
        Ok(Some(response(user, data)))
    }
}

async fn map_profile(
    profile: &FieldValue,
    mapper: Option<&dyn OAuthProfileMapper>,
) -> AuthResult<FieldValue> {
    match mapper {
        Some(mapper) => mapper.map_profile_native(profile).await,
        None => Ok(FieldValue::Undefined),
    }
}

fn literal<const N: usize>(fields: [(&str, FieldValue); N]) -> FieldMap {
    fields
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect()
}

fn spread(mut user: FieldMap, mapped: &FieldValue) -> AuthResult<FieldMap> {
    user.extend(mapped.enumerable_fields()?);
    Ok(user)
}

fn response(user: FieldMap, data: FieldValue) -> ProviderProfile {
    ProviderProfile::from(FieldValue::from(literal([
        ("user", user.into()),
        ("data", data),
    ])))
}

fn optional_property(value: &FieldValue, name: &str) -> AuthResult<FieldValue> {
    if value.is_null() || value.is_undefined() {
        Ok(FieldValue::Undefined)
    } else {
        value.model_property(name)
    }
}

fn or(
    value: FieldValue,
    fallback: impl FnOnce() -> AuthResult<FieldValue>,
) -> AuthResult<FieldValue> {
    if value.is_truthy() {
        Ok(value)
    } else {
        fallback()
    }
}

fn coalesce(
    value: FieldValue,
    fallback: impl FnOnce() -> AuthResult<FieldValue>,
) -> AuthResult<FieldValue> {
    if value.is_null() || value.is_undefined() {
        fallback()
    } else {
        Ok(value)
    }
}

fn name_or(profile: &FieldValue, first: &str, second: &str) -> AuthResult<FieldValue> {
    or(profile.model_property(first)?, || {
        or(profile.model_property(second)?, || Ok("".into()))
    })
}

fn name_coalesce(profile: &FieldValue, first: &str, second: &str) -> AuthResult<FieldValue> {
    coalesce(profile.model_property(first)?, || {
        coalesce(profile.model_property(second)?, || Ok("".into()))
    })
}

fn placeholder(identifier: FieldValue, namespace: &str) -> AuthResult<FieldValue> {
    let identifier = identifier
        .display_utf16()?
        .to_utf8()
        .map_err(|_| AuthError::type_error("Invalid placeholder email"))?;
    crate::plugins::oauth::social_profile::placeholder_email(&identifier, namespace)
        .map(FieldValue::from)
}

fn index_zero(value: &FieldValue) -> AuthResult<FieldValue> {
    match value {
        FieldValue::Array(array) => Ok(array.get(0)?.unwrap_or_default()),
        FieldValue::String(value) => Ok(value
            .encode_utf16()
            .next()
            .map_or(FieldValue::Undefined, |unit| {
                Utf16String::from_units(vec![unit]).into()
            })),
        FieldValue::Utf16String(value) => Ok(value
            .as_utf16()
            .first()
            .map_or(FieldValue::Undefined, |unit| {
                Utf16String::from_units(vec![*unit]).into()
            })),
        value => value.model_property("0"),
    }
}

pub(super) async fn github(
    profile: &FieldValue,
    emails: &FieldValue,
    mapper: Option<&dyn OAuthProfileMapper>,
) -> AuthResult<ProviderProfile> {
    if !profile.model_property("email")?.is_truthy() && emails.is_truthy() {
        let selected = coalesce(
            github_find(emails, |email| {
                Ok(email.model_property("primary")?.is_truthy())
            })?,
            || index_zero(emails),
        )?;
        let email = optional_property(&selected, "email")?;
        if matches!(
            profile,
            FieldValue::Undefined
                | FieldValue::Null
                | FieldValue::Bool(_)
                | FieldValue::Number(_)
                | FieldValue::String(_)
                | FieldValue::Utf16String(_)
        ) {
            return Err(AuthError::type_error(
                "Cannot assign property 'email' to a primitive value",
            ));
        }
        profile.set_model_property("email", email)?;
    }
    let verified = if emails.is_null() || emails.is_undefined() {
        FieldValue::Undefined
    } else {
        let matched = github_find(emails, |email| {
            Ok(email
                .model_property("email")?
                .strict_equals(&profile.model_property("email")?))
        })?;
        optional_property(&matched, "verified")?
    };
    let verified = coalesce(verified, || Ok(false.into()))?;
    let mapped = map_profile(profile, mapper).await?;
    let user = literal([
        ("name", name_or(profile, "name", "login")?),
        ("email", profile.model_property("email")?),
        ("image", profile.model_property("avatar_url")?),
        ("emailVerified", verified),
    ]);
    Ok(response(spread(user, &mapped)?, profile.clone()))
}

fn github_find(
    emails: &FieldValue,
    mut predicate: impl FnMut(&FieldValue) -> AuthResult<bool>,
) -> AuthResult<FieldValue> {
    let FieldValue::Array(emails) = emails else {
        return Err(AuthError::type_error("emails.find is not a function"));
    };
    for email in emails.iter()? {
        let email = email?;
        if predicate(&email)? {
            return Ok(email);
        }
    }
    Ok(FieldValue::Undefined)
}

async fn cloudflare(
    profile: &FieldValue,
    mapper: Option<&dyn OAuthProfileMapper>,
) -> AuthResult<ProviderProfile> {
    let names = [
        profile.model_property("first_name")?,
        profile.model_property("last_name")?,
    ];
    let mut units = Vec::new();
    let mut first = true;
    for name in names.into_iter().filter(FieldValue::is_truthy) {
        if !first {
            units.push(u16::from(b' '));
        }
        first = false;
        units.extend_from_slice(name.display_utf16()?.as_utf16());
    }
    let name = or(Utf16String::from_units(units).into(), || {
        profile.model_property("email")
    })?;
    let mapped = map_profile(profile, mapper).await?;
    let user = literal([
        ("name", name),
        ("email", profile.model_property("email")?),
        ("emailVerified", false.into()),
    ]);
    Ok(response(spread(user, &mapped)?, profile.clone()))
}

async fn reddit(
    profile: &FieldValue,
    mapper: Option<&dyn OAuthProfileMapper>,
) -> AuthResult<ProviderProfile> {
    let mapped = map_profile(profile, mapper).await?;
    let email = or(optional_property(&mapped, "email")?, || {
        placeholder(profile.model_property("id")?, "reddit")
    })?;
    let user = literal([
        ("name", profile.model_property("name")?),
        ("image", reddit_image(profile.model_property("icon_img")?)?),
    ]);
    let mut user = spread(user, &mapped)?;
    let _ = user.insert("email".into(), email);
    let _ = user.insert(
        "emailVerified".into(),
        coalesce(optional_property(&mapped, "emailVerified")?, || {
            Ok(false.into())
        })?,
    );
    Ok(response(user, profile.clone()))
}

fn reddit_image(image: FieldValue) -> AuthResult<FieldValue> {
    let units = match &image {
        FieldValue::Null | FieldValue::Undefined => return Ok(FieldValue::Undefined),
        FieldValue::String(value) => value.encode_utf16().collect::<Vec<_>>(),
        FieldValue::Utf16String(value) => value.as_utf16().to_vec(),
        _ => {
            let FieldValue::Function(split) = image.model_property("split")? else {
                return Err(AuthError::type_error(
                    "profile.icon_img?.split is not a function",
                ));
            };
            return index_zero(&split.call_with(&image, &["?".into()])?);
        }
    };
    Ok(Utf16String::from_units(
        units
            .into_iter()
            .take_while(|unit| *unit != u16::from(b'?'))
            .collect(),
    )
    .into())
}

#[cfg(test)]
#[path = "github_assignment_tests.rs"]
mod github_assignment_tests;
