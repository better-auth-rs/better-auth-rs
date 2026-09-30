use crate::{AuthResult, entity::AuthUser, plugin::MetadataMap, wire::UserView};
use serde_json::{Map, Value, json};

const PLUGIN_FIELDS: &[(&str, &[&str])] = &[
    ("anonymous.enabled", &["isAnonymous"]),
    (
        "phone-number.enabled",
        &["phoneNumber", "phoneNumberVerified"],
    ),
    ("username.enabled", &["username", "displayUsername"]),
    ("two_factor.enabled", &["twoFactorEnabled"]),
    (
        "admin.enabled",
        &["role", "banned", "banReason", "banExpires"],
    ),
];

impl UserView {
    /// Apply current `returned` restrictions to cached fields without repeating adapter transforms.
    /// Upstream keeps fields from disabled plugins until the cache expires or its version changes.
    pub(crate) fn filter_cached_fields(&mut self, config: &super::UserConfig) {
        self.additional_fields.retain(|name, _| {
            config
                .additional_fields
                .get(name)
                .is_none_or(|field| field.returned)
        });
    }

    /// Construct the public user shape from the active application and plugin schemas.
    /// Application model serialization is inspected only at this user boundary.
    pub fn with_fields<T: AuthUser>(
        user: &T,
        config: &super::UserConfig,
        metadata: &MetadataMap,
    ) -> AuthResult<Self> {
        Self::project(user, config, metadata, true, true)
    }

    pub fn with_fields_for_adapter<T: AuthUser>(
        user: &T,
        config: &super::UserConfig,
        metadata: &MetadataMap,
        supports_native_json: bool,
    ) -> AuthResult<Self> {
        Self::project(user, config, metadata, true, supports_native_json)
    }

    /// Apply adapter transforms and active schemas without removing application-only fields.
    /// Use this view only for trusted callbacks, never for public responses.
    pub fn with_internal_fields<T: AuthUser>(
        user: &T,
        config: &super::UserConfig,
        metadata: &MetadataMap,
    ) -> AuthResult<Self> {
        Self::project(user, config, metadata, false, true)
    }

    pub fn with_internal_fields_for_adapter<T: AuthUser>(
        user: &T,
        config: &super::UserConfig,
        metadata: &MetadataMap,
        supports_native_json: bool,
    ) -> AuthResult<Self> {
        Self::project(user, config, metadata, false, supports_native_json)
    }

    fn project<T: AuthUser>(
        user: &T,
        config: &super::UserConfig,
        metadata: &MetadataMap,
        public: bool,
        supports_native_json: bool,
    ) -> AuthResult<Self> {
        let mut view = Self::from(user);
        view.visible_fields = Some(
            PLUGIN_FIELDS
                .iter()
                .filter(|(plugin, _)| metadata.get(*plugin).and_then(Value::as_bool) == Some(true))
                .flat_map(|(_, fields)| fields.iter().map(|name| (*name).to_owned()))
                .collect(),
        );
        view.additional_fields.clear();
        if !config.additional_fields.is_empty() {
            let model = if user.projected_fields().is_none() {
                Some(serde_json::to_value(user)?)
            } else {
                None
            };
            for (name, field) in &config.additional_fields {
                let value = if let Some(projected) = user.projected_fields() {
                    projected.get(name).cloned()
                } else {
                    let value = model
                        .as_ref()
                        .and_then(|model| model.get(field.field_name.as_ref().unwrap_or(name)))
                        .cloned();
                    field.adapter_output(value, supports_native_json)?
                };
                if let Some(mut value) = value {
                    field.normalize_date(&mut value)?;
                    if !public || field.returned {
                        let _ = view.additional_fields.insert(name.clone(), value);
                    }
                }
            }
        }
        Ok(view)
    }
}

impl From<UserView> for Map<String, Value> {
    fn from(user: UserView) -> Self {
        let mut result = Map::from_iter([
            ("id".into(), json!(user.id)),
            ("name".into(), json!(user.name)),
            ("email".into(), json!(user.email)),
            ("emailVerified".into(), json!(user.email_verified)),
            ("image".into(), json!(user.image)),
            (
                "createdAt".into(),
                json!(
                    user.created_at
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                ),
            ),
            (
                "updatedAt".into(),
                json!(
                    user.updated_at
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                ),
            ),
        ]);
        for (name, value) in [
            ("isAnonymous", json!(user.is_anonymous)),
            ("phoneNumber", json!(user.phone_number)),
            ("phoneNumberVerified", json!(user.phone_number_verified)),
            ("username", json!(user.username)),
            ("displayUsername", json!(user.display_username)),
            ("twoFactorEnabled", json!(user.two_factor_enabled)),
            ("role", json!(user.role)),
            ("banned", json!(user.banned)),
            ("banReason", json!(user.ban_reason)),
            (
                "banExpires",
                json!(
                    user.ban_expires
                        .map(|date| date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
                ),
            ),
        ] {
            if user
                .visible_fields
                .as_ref()
                .is_none_or(|fields| fields.contains(name))
            {
                let value =
                    if name == "isAnonymous" && value.is_null() && user.visible_fields.is_some() {
                        json!(false)
                    } else {
                        value
                    };
                if user.visible_fields.is_none()
                    && value.is_null()
                    && ["isAnonymous", "phoneNumber", "phoneNumberVerified"].contains(&name)
                {
                    continue;
                }
                let _ = result.insert(name.into(), value);
            }
        }
        result.extend(user.additional_fields);
        result
    }
}

impl TryFrom<Map<String, Value>> for UserView {
    type Error = serde_json::Error;

    fn try_from(mut fields: Map<String, Value>) -> Result<Self, Self::Error> {
        fn take<T: serde::de::DeserializeOwned>(
            fields: &mut Map<String, Value>,
            name: &str,
        ) -> Result<T, serde_json::Error> {
            serde_json::from_value(fields.remove(name).unwrap_or(Value::Null))
        }
        let visible_fields = Some(
            PLUGIN_FIELDS
                .iter()
                .flat_map(|(_, names)| names.iter())
                .filter(|name| fields.contains_key(**name))
                .map(|name| (*name).to_owned())
                .collect(),
        );
        Ok(Self {
            id: take(&mut fields, "id")?,
            name: take(&mut fields, "name")?,
            email: take(&mut fields, "email")?,
            email_verified: take(&mut fields, "emailVerified")?,
            image: take(&mut fields, "image")?,
            created_at: take(&mut fields, "createdAt")?,
            updated_at: take(&mut fields, "updatedAt")?,
            is_anonymous: take(&mut fields, "isAnonymous")?,
            phone_number: take(&mut fields, "phoneNumber")?,
            phone_number_verified: take(&mut fields, "phoneNumberVerified")?,
            username: take(&mut fields, "username")?,
            display_username: take(&mut fields, "displayUsername")?,
            two_factor_enabled: take::<Option<bool>>(&mut fields, "twoFactorEnabled")?
                .unwrap_or(false),
            role: take(&mut fields, "role")?,
            banned: take::<Option<bool>>(&mut fields, "banned")?.unwrap_or(false),
            ban_reason: take(&mut fields, "banReason")?,
            ban_expires: take(&mut fields, "banExpires")?,
            metadata: Value::Null,
            visible_fields,
            additional_fields: fields,
        })
    }
}
