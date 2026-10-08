use crate::store::schema::resolve_field_name;
use crate::{AuthRecordFields, FromFieldMap, SchemaValue};
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
        adapter: &super::UserConfig,
        endpoint: &super::UserConfig,
    ) -> AuthResult<FieldMap> {
        let mut schema = adapter.user_field_schema();
        schema.fields_mut().extend(endpoint.fields().clone());
        let mut output = FieldMap::new();
        for (name, field) in schema.fields() {
            if !field.returned() {
                continue;
            }
            let value = match data.get(name).filter(|value| !value.is_undefined()) {
                Some(value) => Some(value.clone()),
                None if field.default_value_fn.is_some() => field.default_value()?,
                None => field
                    .default_value
                    .clone()
                    .filter(|value| !value.is_undefined()),
            }
            .or_else(|| (field.required != Some(true)).then_some(Value::Null));
            if let Some(value) = value {
                let _ = output.insert(name.clone(), value);
            }
        }
        if let Some(id) = data.get("id") {
            let _ = output.insert("id".into(), id.clone());
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
                                [
                                    "id",
                                    "name",
                                    "email",
                                    "emailVerified",
                                    "image",
                                    "createdAt",
                                    "updatedAt",
                                ]
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
                            view.native_field_value(name)
                                .or_else(|| projected.get(name).cloned())
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
                                .or_else(|| {
                                    (storage_name == name)
                                        .then(|| view.native_field_value(name))
                                        .flatten()
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
                                    .adapter_output_with_capabilities(
                                        value.unwrap_or_default(),
                                        capabilities,
                                    )
                                    .await?
                            }
                        };
                        if Self::NATIVE_FIELDS.contains(&name) {
                            view.set_field(name, value);
                            if public
                                && !field.returned()
                                && let Some(fields) = &mut view.visible_fields
                            {
                                let _ = fields.remove(name);
                            }
                        } else if !public || field.returned() {
                            view.set_field(name, value);
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

macro_rules! user_fields {
    ($($field:ident => $name:literal),* $(,)?) => {
        impl UserView {
            pub(crate) const NATIVE_FIELDS: &[&str] = &[$($name),*];

            pub(crate) fn native_field_value(&self, name: &str) -> Option<Value> {
                if self.visible_fields.as_ref().is_some_and(|fields| !fields.contains(name)) {
                    return None;
                }
                let value = match name {
                    $($name => self.$field.field_value(),)*
                    "metadata" => self.metadata.clone(),
                    _ => return None,
                };
                if value.is_undefined() && self.visible_fields.is_none()
                    && !self.field_order.iter().any(|field| field == name)
                {
                    return None;
                }
                Some(value)
            }

            /// Assign a native or additional field without decoding schema replacements.
            /// Preserve existing property order and record newly present fields, including undefined.
            pub fn set_field(&mut self, name: &str, value: Value) {
                match name {
                    $($name => self.$field = SchemaValue::from_field(value),)*
                    "metadata" => self.metadata = value,
                    _ => { let _ = self.additional_fields.insert(name.into(), value); }
                }
                if let Some(fields) = &mut self.visible_fields {
                    let _ = fields.insert(name.into());
                }
                if !self.field_order.iter().any(|field| field == name) {
                    self.field_order.push(name.into());
                }
            }
        }

        impl TryFrom<FieldMap> for UserView {
            type Error = crate::AuthError;

            fn try_from(mut fields: FieldMap) -> Result<Self, Self::Error> {
                let visible_fields = Some(fields.keys().cloned().collect());
                Ok(Self {
                    field_order: fields.keys().cloned().collect(),
                    $($field: SchemaValue::from_field(fields.remove($name).unwrap_or_default()),)*
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
                $(user.$field = context.clone_field(&self.$field)?;)*
                user.metadata = context.clone_value(&self.metadata);
                user.additional_fields = context.clone_map(&self.additional_fields);
                Ok(user)
            }
        }
    };
}

user_fields! {
    id => "id",
    name => "name",
    email => "email",
    email_verified => "emailVerified",
    image => "image",
    created_at => "createdAt",
    updated_at => "updatedAt",
    is_anonymous => "isAnonymous",
    phone_number => "phoneNumber",
    phone_number_verified => "phoneNumberVerified",
    username => "username",
    display_username => "displayUsername",
    two_factor_enabled => "twoFactorEnabled",
    role => "role",
    banned => "banned",
    ban_reason => "banReason",
    ban_expires => "banExpires",
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
        if user
            .visible_fields
            .as_ref()
            .is_some_and(|fields| fields.contains("metadata"))
        {
            let _ = result.insert("metadata".into(), user.metadata.clone());
        }
        result.extend(user.additional_fields.into_iter().filter(|(name, _)| {
            name != "metadata" && !UserView::NATIVE_FIELDS.contains(&name.as_str())
        }));
        result.in_field_order(&user.field_order)
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
        let fields = crate::field_value::serde::map::deserialize(deserializer)?;
        Self::from_field_values(fields).map_err(D::Error::custom)
    }
}
