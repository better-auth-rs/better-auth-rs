use crate::store::schema::resolve_field_name;
use crate::{AuthRecordFields, FromFieldMap, SchemaField};
use crate::{AuthResult, entity::AuthUser, plugin::MetadataMap, wire::UserView};
use crate::{FieldMap, FieldValue as Value};
use futures_util::future::BoxFuture;

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
    pub(crate) fn active_plugin_fields(
        metadata: &MetadataMap,
    ) -> impl Iterator<Item = &'static str> + '_ {
        PLUGIN_FIELDS
            .iter()
            .filter(move |(plugin, _)| {
                metadata.get(*plugin).and_then(serde_json::Value::as_bool) == Some(true)
            })
            .flat_map(|(_, fields)| fields.iter().copied())
    }

    /// Build an enumeration-safe signup response without adapter transforms or persistence.
    pub fn synthetic_output(
        data: FieldMap,
        config: &super::UserConfig,
        metadata: &MetadataMap,
    ) -> AuthResult<FieldMap> {
        let mut output = FieldMap::new();
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
            if metadata.get(*plugin).and_then(serde_json::Value::as_bool) != Some(true) {
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
            let value = match data.get(name) {
                Some(value) => Some(value.clone()),
                None => field.default_value()?,
            }
            .or_else(|| (field.required != Some(true)).then_some(Value::Null));
            if let Some(value) = value {
                let _ = output.insert(name.clone(), value);
            }
        }
        Ok(output)
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
        Self::project_many(
            users,
            config,
            metadata,
            false,
            super::FieldOutputCapabilities::json_only(supports_native_json),
            &|_, _, _| Ok(None),
        )
        .await
    }

    /// Project database rows with raw callback values for unprojected additional fields.
    /// `Some(Value::Null)` preserves a present null; `None` retains the serialized source.
    /// Supplied non-reference extras use the adapter capabilities after their output callback.
    /// Native fields and completed adapter output do not use this accessor.
    pub async fn with_internal_fields_many_for_adapter_using<T: AuthUser>(
        users: &[T],
        config: &super::UserConfig,
        metadata: &MetadataMap,
        capabilities: super::FieldOutputCapabilities,
        read_extra: impl Fn(&T, &str, &super::UserFieldConfig) -> AuthResult<Option<Value>> + Sync,
    ) -> AuthResult<Vec<Self>> {
        Self::project_many(users, config, metadata, false, capabilities, &read_extra).await
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
            super::FieldOutputCapabilities::json_only(supports_native_json),
            &|_, _, _| Ok(None),
        )
        .await?
        .remove(0))
    }

    fn project_many<'a, T: AuthUser>(
        users: &'a [T],
        config: &'a super::UserConfig,
        metadata: &'a MetadataMap,
        public: bool,
        capabilities: super::FieldOutputCapabilities,
        read_extra: &'a (impl Fn(&T, &str, &super::UserFieldConfig) -> AuthResult<Option<Value>> + Sync),
    ) -> BoxFuture<'a, AuthResult<Vec<Self>>> {
        // Erase the projection future so request callers do not expand its nested Send obligations.
        Box::pin(async move {
            let mut rows = users
                .iter()
                .map(|user| {
                    let mut view = Self::from_model(user)?;
                    if user.projected_fields().is_none() {
                        view.field_order = config
                            .user_field_schema()
                            .adapter_fields(&[])
                            .fields()
                            .keys()
                            .cloned()
                            .collect();
                    }
                    view.visible_fields = Some(
                        Self::active_plugin_fields(metadata)
                            .filter(|name| {
                                user.field_presence()
                                    .is_none_or(|fields| fields.contains(*name))
                            })
                            .map(str::to_owned)
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
                    let model = if !config.fields().is_empty() && user.projected_fields().is_none()
                    {
                        Some(user.field_values()?)
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
                        if !view.field_order.iter().any(|field| field == name) {
                            view.field_order.push(name.into());
                        }
                        let value = if let Some(projected) = user.projected_fields() {
                            match name {
                                "id" => Some(view.id.field_value()),
                                "name" => Some(view.name.field_value()),
                                "image" => Some(view.image.field_value()),
                                _ => projected.get(name).cloned(),
                            }
                            .unwrap_or_default()
                        } else {
                            let storage_name =
                                resolve_field_name(field.field_name.as_deref(), name);
                            let value = if Self::NATIVE_FIELDS.contains(&name) {
                                None
                            } else {
                                read_extra(user, name, field)?
                            };
                            let raw_extra = value.is_some() && field.references.is_none();
                            let value = value
                                .or_else(|| {
                                    model
                                        .as_ref()
                                        .and_then(|model| model.get(storage_name))
                                        .cloned()
                                })
                                .or_else(|| match (name, storage_name == name) {
                                    ("username", true) => {
                                        Some(user.username().map(str::to_owned).into_field())
                                    }
                                    ("displayUsername", true) => Some(
                                        user.display_username().map(str::to_owned).into_field(),
                                    ),
                                    _ => None,
                                });
                            if raw_extra {
                                field
                                    .adapter_output_from_raw(
                                        value.unwrap_or_default(),
                                        capabilities,
                                    )
                                    .await?
                            } else {
                                field
                                    .adapter_output(
                                        value.unwrap_or_default(),
                                        capabilities.supports_native_json,
                                    )
                                    .await?
                            }
                        };
                        if name == "username" || name == "displayUsername" {
                            if let Some(fields) = &mut view.visible_fields {
                                if !public || field.returned() {
                                    let _ = fields.insert(name.to_owned());
                                } else {
                                    let _ = fields.remove(name);
                                }
                            }
                            let typed = if !public || field.returned() {
                                value.decode()?
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
                            *target = crate::SchemaValue::from_field(value);
                            if public
                                && !field.returned()
                                && let Some(fields) = &mut view.visible_fields
                            {
                                let _ = fields.remove(name);
                            }
                            return Ok(());
                        }
                        {
                            let mut value = value;
                            if !field.uses_id_output() {
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
        })
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
            "id" if !self.id.is_undefined() => self.id.clone().into_field(),
            "name" if !self.name.is_undefined() => self.name.clone().into_field(),
            "email" => self.email.clone().into_field(),
            "emailVerified" => self.email_verified.into_field(),
            "image" if !self.image.is_undefined() => self.image.clone().into_field(),
            "createdAt" => self.created_at.clone().into_field(),
            "updatedAt" => self.updated_at.clone().into_field(),
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
                    "isAnonymous" => self.is_anonymous.into_field(),
                    "phoneNumber" => self.phone_number.clone().into_field(),
                    "phoneNumberVerified" => self.phone_number_verified.into_field(),
                    "username" => self.username.clone().into_field(),
                    "displayUsername" => self.display_username.clone().into_field(),
                    "twoFactorEnabled" => self.two_factor_enabled.into_field(),
                    "role" => self.role.clone().into_field(),
                    "banned" => self.banned.into_field(),
                    "banReason" => self.ban_reason.clone().into_field(),
                    "banExpires" => self.ban_expires.clone().into_field(),
                    _ => return None,
                };
                if name == "isAnonymous" && value.is_null() && self.visible_fields.is_some() {
                    return Some(Value::Bool(false));
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

impl From<UserView> for FieldMap {
    fn from(user: UserView) -> Self {
        let mut result: FieldMap = UserView::NATIVE_FIELDS
            .iter()
            .filter_map(|name| {
                user.native_field_value(name)
                    .map(|value| ((*name).into(), value))
            })
            .collect();
        result.extend(user.additional_fields);
        result.in_field_order(&user.field_order)
    }
}

impl TryFrom<FieldMap> for UserView {
    type Error = crate::AuthError;

    fn try_from(mut fields: FieldMap) -> Result<Self, Self::Error> {
        fn take<T: crate::SchemaField>(fields: &mut FieldMap, name: &str) -> AuthResult<T> {
            fields.remove(name).unwrap_or_default().decode()
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
            field_order: fields.keys().cloned().collect(),
            id: crate::SchemaValue::from_field(fields.remove("id").unwrap_or_default()),
            name: crate::SchemaValue::from_field(fields.remove("name").unwrap_or_default()),
            email: take(&mut fields, "email")?,
            email_verified: take(&mut fields, "emailVerified")?,
            image: crate::SchemaValue::from_field(fields.remove("image").unwrap_or_default()),
            created_at: take(&mut fields, "createdAt")?,
            updated_at: take(&mut fields, "updatedAt")?,
            is_anonymous: take(&mut fields, "isAnonymous")?,
            phone_number: take(&mut fields, "phoneNumber")?,
            phone_number_verified: take(&mut fields, "phoneNumberVerified")?,
            // Keep schema-backed fields in the projected map for later cookie updates.
            username: fields
                .get("username")
                .cloned()
                .unwrap_or_default()
                .decode()?,
            display_username: fields
                .get("displayUsername")
                .cloned()
                .unwrap_or_default()
                .decode()?,
            two_factor_enabled: take(&mut fields, "twoFactorEnabled")?,
            role: take(&mut fields, "role")?,
            banned: take::<Option<bool>>(&mut fields, "banned")?.unwrap_or(false),
            ban_reason: take(&mut fields, "banReason")?,
            ban_expires: take(&mut fields, "banExpires")?,
            metadata: fields.remove("metadata").unwrap_or(Value::Null),
            visible_fields,
            additional_fields: fields,
        })
    }
}

impl AuthRecordFields for UserView {
    fn field_values(&self) -> AuthResult<FieldMap> {
        let mut fields = FieldMap::from(self.clone());
        let _ = fields.insert("metadata".into(), self.metadata.clone());
        Ok(fields.in_field_order(&self.field_order))
    }

    fn structured_clone(&self, context: &mut crate::StructuredCloneContext) -> AuthResult<Self> {
        let mut user = self.clone();
        user.id = context.clone_field(&self.id)?;
        user.name = context.clone_field(&self.name)?;
        user.image = context.clone_field(&self.image)?;
        user.created_at = context.clone_field(&self.created_at)?;
        user.updated_at = context.clone_field(&self.updated_at)?;
        user.ban_expires = context.clone_field(&self.ban_expires)?;
        user.metadata = context.clone_value(&self.metadata);
        user.additional_fields = context.clone_map(&self.additional_fields);
        Ok(user)
    }
}

impl FromFieldMap for UserView {
    fn from_field_values(fields: FieldMap) -> AuthResult<Self> {
        Self::try_from(fields)
    }
}

impl serde::Serialize for UserView {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::field_value::serde::map::serialize(&FieldMap::from(self.clone()), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for UserView {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let mut fields = crate::field_value::serde::map::deserialize(deserializer)?;
        for name in ["createdAt", "updatedAt", "banExpires"] {
            if let Some(Value::String(text)) = fields.get(name) {
                let date = crate::utils::date::parse_date_constructor(text)
                    .ok_or_else(|| D::Error::custom(format!("Invalid user date field `{name}`")))?;
                let _ = fields.insert(name.into(), date.into());
            }
        }
        Self::from_field_values(fields).map_err(D::Error::custom)
    }
}
