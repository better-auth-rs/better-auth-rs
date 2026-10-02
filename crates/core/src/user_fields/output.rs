use crate::store::schema::resolve_field_name;
use crate::{AuthResult, entity::AuthUser, plugin::MetadataMap, wire::UserView};
use serde_json::{Map, Value, json};

const PLUGIN_FIELDS: &[(&str, &[&str])] = &[
    ("anonymous.enabled", &["isAnonymous"]),
    (
        "phone-number.enabled",
        &["phoneNumber", "phoneNumberVerified"],
    ),
    ("username.enabled", &["username"]),
    ("username.display.enabled", &["displayUsername"]),
    ("two_factor.enabled", &["twoFactorEnabled"]),
    (
        "admin.enabled",
        &["role", "banned", "banReason", "banExpires"],
    ),
];

impl UserView {
    /// Build an enumeration-safe signup response without adapter transforms or persistence.
    pub fn synthetic_output(
        data: Map<String, Value>,
        config: &super::UserConfig,
        metadata: &MetadataMap,
    ) -> Map<String, Value> {
        let mut output = Map::new();
        for name in [
            "id",
            "name",
            "email",
            "emailVerified",
            "image",
            "createdAt",
            "updatedAt",
        ] {
            if let Some(value) = data.get(name) {
                let _ = output.insert(name.into(), value.clone());
            }
        }
        for (plugin, names) in PLUGIN_FIELDS {
            if metadata.get(*plugin).and_then(Value::as_bool) != Some(true) {
                continue;
            }
            for name in *names {
                let value = data.get(*name).cloned().unwrap_or_else(|| {
                    if ["isAnonymous", "twoFactorEnabled", "banned"].contains(name) {
                        Value::Bool(false)
                    } else {
                        Value::Null
                    }
                });
                let _ = output.insert((*name).into(), value);
            }
        }
        for (name, field) in config.fields() {
            if !field.returned() {
                let _ = output.remove(name);
                continue;
            }
            let value = data
                .get(name)
                .cloned()
                .or_else(|| field.default_value())
                .or_else(|| (field.required != Some(true)).then_some(Value::Null));
            if let Some(value) = value {
                let _ = output.insert(name.clone(), value);
            }
        }
        output
    }

    /// Apply current `returned` restrictions to cached fields without repeating adapter transforms.
    /// Upstream keeps fields from disabled plugins until the cache expires or its version changes.
    pub(crate) fn filter_cached_fields(&mut self, config: &super::UserConfig) {
        for (name, field) in config.fields() {
            if field.returned() {
                continue;
            }
            if let Some(fields) = &mut self.visible_fields {
                let _ = fields.remove(name);
            }
            match name.as_str() {
                "username" => self.username = None,
                "displayUsername" => self.display_username = None,
                _ => {}
            }
        }
        self.additional_fields.retain(|name, _| {
            config
                .fields()
                .get(name)
                .is_none_or(|field| field.returned())
        });
    }

    /// Construct the public user shape from the active application and plugin schemas.
    /// Application model serialization is inspected only at this user boundary.
    pub async fn with_fields<T: AuthUser>(
        user: &T,
        config: &super::UserConfig,
        metadata: &MetadataMap,
    ) -> AuthResult<Self> {
        Self::project(user, config, metadata, true, true).await
    }

    pub async fn with_fields_for_adapter<T: AuthUser>(
        user: &T,
        config: &super::UserConfig,
        metadata: &MetadataMap,
        supports_native_json: bool,
    ) -> AuthResult<Self> {
        Self::project(user, config, metadata, true, supports_native_json).await
    }

    /// Apply adapter transforms once, then use the endpoint's field visibility.
    pub async fn with_field_policies<T: AuthUser>(
        user: &T,
        adapter: &super::UserConfig,
        endpoint: &super::UserConfig,
        metadata: &MetadataMap,
        supports_native_json: bool,
    ) -> AuthResult<Self> {
        let mut view = Self::project(user, adapter, metadata, false, supports_native_json).await?;
        view.filter_cached_fields(endpoint);
        Ok(view)
    }

    /// Apply adapter transforms and active schemas without removing application-only fields.
    /// Use this view only for trusted callbacks, never for public responses.
    pub async fn with_internal_fields<T: AuthUser>(
        user: &T,
        config: &super::UserConfig,
        metadata: &MetadataMap,
    ) -> AuthResult<Self> {
        Self::project(user, config, metadata, false, true).await
    }

    pub async fn with_internal_fields_for_adapter<T: AuthUser>(
        user: &T,
        config: &super::UserConfig,
        metadata: &MetadataMap,
        supports_native_json: bool,
    ) -> AuthResult<Self> {
        Self::project(user, config, metadata, false, supports_native_json).await
    }

    /// Project a database result in row order, interleaving synchronous callbacks by field.
    pub async fn with_internal_fields_many_for_adapter<T: AuthUser>(
        users: &[T],
        config: &super::UserConfig,
        metadata: &MetadataMap,
        supports_native_json: bool,
    ) -> AuthResult<Vec<Self>> {
        Self::project_many(users, config, metadata, false, supports_native_json).await
    }

    async fn project<T: AuthUser>(
        user: &T,
        config: &super::UserConfig,
        metadata: &MetadataMap,
        public: bool,
        supports_native_json: bool,
    ) -> AuthResult<Self> {
        // Projection preserves the one input row.
        Ok(Self::project_many(
            std::slice::from_ref(user),
            config,
            metadata,
            public,
            supports_native_json,
        )
        .await?
        .remove(0))
    }

    async fn project_many<T: AuthUser>(
        users: &[T],
        config: &super::UserConfig,
        metadata: &MetadataMap,
        public: bool,
        supports_native_json: bool,
    ) -> AuthResult<Vec<Self>> {
        let mut rows = users
            .iter()
            .map(|user| {
                let mut view = Self::from_model(user)?;
                view.visible_fields = Some(
                    PLUGIN_FIELDS
                        .iter()
                        .filter(|(plugin, _)| {
                            metadata.get(*plugin).and_then(Value::as_bool) == Some(true)
                        })
                        .flat_map(|(_, fields)| fields.iter().map(|name| (*name).to_owned()))
                        .filter(|name| {
                            user.field_presence()
                                .is_none_or(|fields| fields.contains(name))
                        })
                        .chain(
                            ["name", "email", "image"]
                                .into_iter()
                                .filter(|name| {
                                    user.field_presence()
                                        .is_none_or(|fields| fields.contains(*name))
                                })
                                .map(str::to_owned),
                        )
                        .collect(),
                );
                view.additional_fields.clear();
                let model = if !config.fields().is_empty() && user.projected_fields().is_none() {
                    Some(serde_json::to_value(user)?)
                } else {
                    None
                };
                Ok((user, view, model))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        super::batch::project_fields(
            &mut rows,
            config.fields(),
            |(user, view, model), name, field| {
                Box::pin(async move {
                    let value = if let Some(projected) = user.projected_fields() {
                        match name {
                            "name" => view.name.json()?,
                            "image" => view.image.json()?,
                            _ => projected.get(name).cloned(),
                        }
                    } else {
                        let storage_name = resolve_field_name(field.field_name.as_deref(), name);
                        let value = model
                            .as_ref()
                            .and_then(|model| model.get(storage_name))
                            .cloned()
                            .or_else(|| match (name, storage_name == name) {
                                ("username", true) => Some(json!(user.username())),
                                ("displayUsername", true) => Some(json!(user.display_username())),
                                _ => None,
                            });
                        field.adapter_output(value, supports_native_json).await?
                    };
                    if name == "username" || name == "displayUsername" {
                        if let Some(fields) = &mut view.visible_fields {
                            if value.is_some() && (!public || field.returned()) {
                                let _ = fields.insert(name.to_owned());
                            } else {
                                let _ = fields.remove(name);
                            }
                        }
                        let typed = if !public || field.returned() {
                            value
                                .as_ref()
                                .map(|value| serde_json::from_value(value.clone()))
                                .transpose()?
                                .flatten()
                        } else {
                            None
                        };
                        if name == "username" {
                            view.username = typed;
                        } else {
                            view.display_username = typed;
                        }
                    }
                    if name == "name" || name == "image" {
                        let target = if name == "name" {
                            &mut view.name
                        } else {
                            &mut view.image
                        };
                        *target = crate::SchemaValue::from_json(value);
                        if public
                            && !field.returned()
                            && let Some(fields) = &mut view.visible_fields
                        {
                            let _ = fields.remove(name);
                        }
                        return Ok(());
                    }
                    if let Some(mut value) = value {
                        if !field.references_id() {
                            field.normalize_date(&mut value)?;
                        }
                        if !public || field.returned() {
                            let _ = view.additional_fields.insert(name.to_owned(), value);
                        }
                    }
                    Ok(())
                })
            },
        )
        .await?;
        Ok(rows.into_iter().map(|(_, view, _)| view).collect())
    }
}

impl UserView {
    pub(crate) const NATIVE_FIELDS: &[&str] = &[
        "id",
        "name",
        "email",
        "emailVerified",
        "image",
        "createdAt",
        "updatedAt",
        "isAnonymous",
        "phoneNumber",
        "phoneNumberVerified",
        "username",
        "displayUsername",
        "twoFactorEnabled",
        "role",
        "banned",
        "banReason",
        "banExpires",
    ];

    pub(crate) fn native_field_value(&self, name: &str) -> Option<Value> {
        if matches!(name, "name" | "email" | "image")
            && self
                .visible_fields
                .as_ref()
                .is_some_and(|fields| !fields.contains(name))
        {
            return None;
        }
        let value = match name {
            "id" if !self.id.is_undefined() => json!(self.id),
            "name" if !self.name.is_undefined() => json!(self.name),
            "email" => json!(self.email),
            "emailVerified" => json!(self.email_verified),
            "image" if !self.image.is_undefined() => json!(self.image),
            "createdAt" => json!(
                self.created_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            ),
            "updatedAt" => json!(
                self.updated_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            ),
            "id" | "name" | "image" => return None,
            _ => {
                if self
                    .visible_fields
                    .as_ref()
                    .is_some_and(|fields| !fields.contains(name))
                {
                    return None;
                }
                let value = match name {
                    "isAnonymous" => json!(self.is_anonymous),
                    "phoneNumber" => json!(self.phone_number),
                    "phoneNumberVerified" => json!(self.phone_number_verified),
                    "username" => json!(self.username),
                    "displayUsername" => json!(self.display_username),
                    "twoFactorEnabled" => json!(self.two_factor_enabled),
                    "role" => json!(self.role),
                    "banned" => json!(self.banned),
                    "banReason" => json!(self.ban_reason),
                    "banExpires" => json!(
                        self.ban_expires
                            .map(|date| date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
                    ),
                    _ => return None,
                };
                if name == "isAnonymous" && value.is_null() && self.visible_fields.is_some() {
                    return Some(json!(false));
                }
                if self.visible_fields.is_none()
                    && value.is_null()
                    && ["isAnonymous", "phoneNumber", "phoneNumberVerified"].contains(&name)
                {
                    return None;
                }
                value
            }
        };
        Some(value)
    }
}

impl From<UserView> for Map<String, Value> {
    fn from(user: UserView) -> Self {
        let mut result: Map<_, _> = UserView::NATIVE_FIELDS
            .iter()
            .filter_map(|name| {
                user.native_field_value(name)
                    .map(|value| ((*name).into(), value))
            })
            .collect();
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
                .chain(
                    ["name", "email", "image"]
                        .into_iter()
                        .filter(|name| fields.contains_key(*name))
                        .map(str::to_owned),
                )
                .collect(),
        );
        Ok(Self {
            id: crate::SchemaValue::from_json(fields.remove("id")),
            name: crate::SchemaValue::from_json(fields.remove("name")),
            email: take(&mut fields, "email")?,
            email_verified: take(&mut fields, "emailVerified")?,
            image: crate::SchemaValue::from_json(fields.remove("image")),
            created_at: take(&mut fields, "createdAt")?,
            updated_at: take(&mut fields, "updatedAt")?,
            is_anonymous: take(&mut fields, "isAnonymous")?,
            phone_number: take(&mut fields, "phoneNumber")?,
            phone_number_verified: take(&mut fields, "phoneNumberVerified")?,
            // Keep schema-backed fields in the projected map for later cookie updates.
            username: serde_json::from_value(
                fields.get("username").cloned().unwrap_or(Value::Null),
            )?,
            display_username: serde_json::from_value(
                fields
                    .get("displayUsername")
                    .cloned()
                    .unwrap_or(Value::Null),
            )?,
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
