use super::ModelFields;
use crate::{
    AuthError, AuthResult,
    store::schema::{EntityRole, resolve_field_name},
    user_fields::UserConfig,
};

/// Logical model identity shared by declarations and adapter operation history.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ModelKey {
    Native(EntityRole),
    Custom(String),
}

impl ModelKey {
    /// Read the logical name without applying adapter table aliases.
    pub fn logical_name(&self) -> AuthResult<&str> {
        match self {
            Self::Native(role) => ModelFields::native_model_name(*role),
            Self::Custom(name) => Ok(name),
        }
    }
}

impl From<EntityRole> for ModelKey {
    fn from(role: EntityRole) -> Self {
        Self::Native(role)
    }
}

impl From<&ModelKey> for ModelKey {
    fn from(model: &ModelKey) -> Self {
        model.clone()
    }
}

const NATIVE_MODELS: &[(EntityRole, &str)] = &[
    (EntityRole::User, "user"),
    (EntityRole::Session, "session"),
    (EntityRole::Account, "account"),
    (EntityRole::Verification, "verification"),
    (EntityRole::Organization, "organization"),
    (EntityRole::Member, "member"),
    (EntityRole::Invitation, "invitation"),
    (EntityRole::Team, "team"),
    (EntityRole::TeamMember, "teamMember"),
    (EntityRole::OrganizationRole, "organizationRole"),
    (EntityRole::ApiKey, "apikey"),
    (EntityRole::DeviceCode, "deviceCode"),
    (EntityRole::Passkey, "passkey"),
    (EntityRole::TwoFactor, "twoFactor"),
    (EntityRole::Jwk, "jwks"),
    (EntityRole::WalletAddress, "walletAddress"),
    (EntityRole::RateLimit, "rateLimit"),
];

fn is_core(role: EntityRole) -> bool {
    matches!(
        role,
        EntityRole::User | EntityRole::Session | EntityRole::Account | EntityRole::Verification
    )
}

impl ModelFields {
    pub(crate) fn native_model_name(role: EntityRole) -> AuthResult<&'static str> {
        NATIVE_MODELS
            .iter()
            .find_map(|(candidate, name)| (*candidate == role).then_some(*name))
            .ok_or_else(|| AuthError::config(format!("Model name is not registered for {role:?}")))
    }

    /// Read effective native models in schema order, including explicitly declared plugin roles.
    #[doc(hidden)]
    pub fn active_models(&self) -> Vec<(EntityRole, &'static str)> {
        let mut models = indexmap::IndexMap::new();
        for &(role, name) in NATIVE_MODELS.iter().filter(|(role, _)| is_core(*role)) {
            if self
                .schema_models
                .as_ref()
                .is_none_or(|configured| configured.iter().any(|(active, _)| *active == role))
            {
                let _ = models.insert(role, name);
            }
        }
        for declaration in self.declarations.keys() {
            if let ModelKey::Native(role) = declaration
                && !is_core(*role)
                && let Some((_, name)) = NATIVE_MODELS.iter().find(|(native, _)| native == role)
            {
                let _ = models.insert(*role, *name);
            }
        }
        models.into_iter().collect()
    }

    /// Resolve the physical model name used by raw relation properties.
    /// Legacy field-only declarations retain the adapter's default model name.
    #[doc(hidden)]
    pub fn storage_model_name<'a>(&'a self, role: EntityRole, default: &'a str) -> &'a str {
        self.storage_name(&ModelKey::Native(role), default)
    }

    /// Read the declared physical alias or the adapter's default table name.
    #[doc(hidden)]
    pub fn storage_name<'a>(&'a self, model: &ModelKey, default: &'a str) -> &'a str {
        self.declarations
            .get(model)
            .and_then(Option::as_deref)
            .unwrap_or(default)
    }

    /// Read registered declarations without adapter defaults or runtime ID replacement.
    #[doc(hidden)]
    pub fn declared_fields(&self, model: &ModelKey) -> AuthResult<&UserConfig> {
        match model {
            ModelKey::Native(role) => Ok(self.fields(*role)),
            ModelKey::Custom(name) => self.custom_models.get(name).ok_or_else(|| {
                AuthError::internal(format!("Custom model {name} has no field declaration"))
            }),
        }
    }

    pub(crate) fn set_model_name(
        &mut self,
        role: EntityRole,
        model_name: Option<&str>,
    ) -> AuthResult<()> {
        let logical = Self::native_model_name(role)?;
        let _ = self.declarations.insert(
            ModelKey::Native(role),
            Some(resolve_field_name(model_name, logical).to_owned()),
        );
        Ok(())
    }

    /// Declare a custom logical model and merge complete field declarations in insertion order.
    /// Repeated declarations replace the physical name without moving the model.
    pub fn register_custom_model(
        &mut self,
        name: impl Into<String>,
        model_name: Option<&str>,
        fields: UserConfig,
    ) -> AuthResult<()> {
        let name = name.into();
        if NATIVE_MODELS.iter().any(|(_, native)| *native == name) {
            return Err(AuthError::config(format!(
                "Model \"{name}\" is reserved for a native model and cannot be declared as a custom model"
            )));
        }
        let physical_name = resolve_field_name(model_name, &name).to_owned();
        let _ = self
            .declarations
            .insert(ModelKey::Custom(name.clone()), Some(physical_name));
        self.registered_declarations.push((
            ModelKey::Custom(name.clone()),
            fields.fields().keys().cloned().collect(),
        ));
        let declaration = self.custom_models.entry(name).or_default();
        if let Some(fields) = fields.additional_fields {
            declaration.fields_mut().extend(fields);
        }
        Ok(())
    }

    /// Read complete final declarations without applying runtime ID replacements.
    pub(crate) fn declared_models(&self) -> AuthResult<indexmap::IndexMap<String, UserConfig>> {
        self.declarations
            .keys()
            .map(|model| {
                Ok((
                    model.logical_name()?.to_owned(),
                    self.declared_fields(model)?.clone(),
                ))
            })
            .collect()
    }

    pub(crate) fn take_registered_declarations(
        &mut self,
    ) -> AuthResult<Vec<(String, Vec<String>)>> {
        std::mem::take(&mut self.registered_declarations)
            .into_iter()
            .map(|(declaration, fields)| {
                let name = match declaration {
                    ModelKey::Native(role) => Self::native_model_name(role)?.to_owned(),
                    ModelKey::Custom(name) => name,
                };
                Ok((name, fields))
            })
            .collect()
    }

    /// Read custom logical names, physical names, and merged field policies in declaration order.
    /// Storage adapters retain responsibility for custom model operations and migrations.
    pub fn custom_models(&self) -> impl Iterator<Item = (&str, &str, &UserConfig)> {
        self.declarations
            .iter()
            .filter_map(move |(declaration, physical)| match declaration {
                ModelKey::Native(_) => None,
                ModelKey::Custom(name) => self
                    .custom_models
                    .get(name)
                    .map(|fields| (name.as_str(), physical.as_deref().unwrap_or(name), fields)),
            })
    }

    pub(crate) fn all_native_model_names() -> Vec<&'static str> {
        NATIVE_MODELS.iter().map(|(_, name)| *name).collect()
    }

    /// Enumerate logical model keys in upstream object order, including custom models.
    #[doc(hidden)]
    pub fn logical_model_names(&self) -> Vec<&str> {
        self.ordered_models().into_keys().collect()
    }

    fn ordered_models(&self) -> indexmap::IndexMap<&str, (ModelKey, Option<&str>)> {
        let active = self.active_models();
        let mut models = indexmap::IndexMap::new();
        for (role, name) in active.iter().filter(|(role, _)| is_core(*role)) {
            let alias = self.declarations.get(&ModelKey::Native(*role));
            let _ = models.insert(
                *name,
                (ModelKey::Native(*role), alias.and_then(Option::as_deref)),
            );
        }
        for (declaration, physical) in &self.declarations {
            match declaration {
                ModelKey::Native(role) => {
                    if let Some((_, name)) = active.iter().find(|(candidate, _)| candidate == role)
                    {
                        let _ = models
                            .entry(*name)
                            .or_insert((ModelKey::Native(*role), physical.as_deref()));
                    }
                }
                ModelKey::Custom(name) => {
                    let _ = models.insert(
                        name.as_str(),
                        (ModelKey::Custom(name.clone()), physical.as_deref()),
                    );
                }
            }
        }
        for (role, name) in active {
            let _ = models.entry(name).or_insert((ModelKey::Native(role), None));
        }
        models.sort_by_cached_key(|name, _| {
            crate::utils::json::array_index(name).map_or((true, 0), |index| (false, index))
        });
        models
    }

    /// Resolve active logical names before physical aliases in schema declaration order.
    #[doc(hidden)]
    pub fn resolve_model_key(
        &self,
        candidate: &str,
        table_matches: &impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<ModelKey> {
        self.resolve_model_entry(candidate, table_matches)
            .map(|(_, key)| key)
    }

    #[cfg(test)]
    pub(crate) fn resolve_model_name(
        &self,
        candidate: &str,
        table_matches: &impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<&str> {
        self.resolve_model_entry(candidate, table_matches)
            .map(|(name, _)| name)
    }

    fn resolve_model_entry(
        &self,
        candidate: &str,
        table_matches: &impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<(&str, ModelKey)> {
        let models = self.ordered_models();
        // Every logical name precedes physical aliases, including aliases of native models.
        models
            .get_key_value(candidate)
            .map(|(name, (key, _))| (*name, key.clone()))
            .or_else(|| {
                models
                    .iter()
                    .find(|(name, (key, physical))| match physical {
                        Some(physical) => resolve_field_name(Some(physical), name) == candidate,
                        None => match key {
                            ModelKey::Native(role) => table_matches(*role, candidate),
                            ModelKey::Custom(_) => false,
                        },
                    })
                    .map(|(name, (key, _))| (*name, key.clone()))
            })
            .filter(|(name, _)| !name.is_empty())
            .ok_or_else(|| AuthError::config(format!("Model \"{candidate}\" not found in schema")))
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]
mod tests {
    use super::*;
    use crate::user_fields::UserFieldConfig;

    #[test]
    fn native_and_custom_aliases_follow_one_declaration_order() {
        for custom_first in [true, false] {
            let mut schema = ModelFields {
                schema_models: Some(vec![(EntityRole::User, "user"), (EntityRole::Team, "team")]),
                ..Default::default()
            };
            if custom_first {
                schema
                    .register_custom_model("badge", Some("shared"), UserConfig::default())
                    .unwrap();
            }
            schema
                .set_model_name(EntityRole::Team, Some("shared"))
                .unwrap();
            if !custom_first {
                schema
                    .register_custom_model("badge", Some("shared"), UserConfig::default())
                    .unwrap();
            }
            let schema = schema.fresh_runtime();
            assert_eq!(
                schema.resolve_model_name("shared", &|_, _| false).unwrap(),
                if custom_first { "badge" } else { "team" }
            );
            assert_eq!(
                schema.resolve_model_name("team", &|_, _| false).unwrap(),
                "team"
            );

            let mut legacy = schema.clone();
            legacy.register(EntityRole::Team, UserConfig::default());
            let adapter_name =
                |role, candidate: &str| role == EntityRole::Team && candidate == "team_table";
            assert_eq!(
                legacy
                    .resolve_model_name("team_table", &adapter_name)
                    .unwrap(),
                "team"
            );
            assert_eq!(
                legacy.resolve_model_name("shared", &adapter_name).unwrap(),
                "badge"
            );
            legacy
                .set_model_name(EntityRole::Team, Some("shared"))
                .unwrap();
            assert_eq!(
                legacy.resolve_model_name("shared", &adapter_name).unwrap(),
                if custom_first { "badge" } else { "team" }
            );

            let mut replaced = schema.clone();
            replaced
                .register_custom_model("badge", None, UserConfig::default())
                .unwrap();
            assert_eq!(
                replaced
                    .resolve_model_name("shared", &|_, _| false)
                    .unwrap(),
                "team"
            );
            replaced
                .register_custom_model("badge", Some("shared"), UserConfig::default())
                .unwrap();
            assert_eq!(
                replaced
                    .resolve_model_name("shared", &|_, _| false)
                    .unwrap(),
                if custom_first { "badge" } else { "team" }
            );
            replaced.set_model_name(EntityRole::Team, Some("")).unwrap();
            assert_eq!(
                replaced.resolve_model_name("shared", &|_, _| true).unwrap(),
                "user"
            );
            assert_eq!(
                replaced
                    .resolve_model_name("shared", &|_, _| false)
                    .unwrap(),
                "badge"
            );

            replaced
                .set_model_name(EntityRole::Team, Some("shared"))
                .unwrap();
            replaced.set_model_name(EntityRole::Team, None).unwrap();
            assert_eq!(
                replaced
                    .resolve_model_name("shared", &|_, _| false)
                    .unwrap(),
                "badge"
            );

            replaced
                .register_custom_model("0", Some("shared"), UserConfig::default())
                .unwrap();
            assert_eq!(
                replaced.resolve_model_name("shared", &|_, _| true).unwrap(),
                "0"
            );
        }
    }

    #[test]
    fn custom_model_declarations_merge_without_losing_schema_position() {
        let mut schema = ModelFields::default();
        let fields = |names: &[&str], required| UserConfig {
            additional_fields: Some(
                names
                    .iter()
                    .map(|name| {
                        (
                            (*name).into(),
                            UserFieldConfig {
                                required: Some(required),
                                ..Default::default()
                            },
                        )
                    })
                    .collect(),
            ),
        };
        schema
            .register_custom_model(
                "badge",
                Some("old_badges"),
                fields(&["label", "rank"], false),
            )
            .unwrap();
        schema
            .register_custom_model("other", Some("shared"), UserConfig::default())
            .unwrap();
        schema
            .register_custom_model("badge", Some("shared"), fields(&["label", "enabled"], true))
            .unwrap();
        let schema = schema.fresh_runtime();
        assert_eq!(
            schema
                .custom_models()
                .map(|(name, _, _)| name)
                .collect::<Vec<_>>(),
            ["badge", "other"]
        );
        let (_, physical, fields) = schema.custom_models().next().unwrap();
        assert_eq!(physical, "shared");
        assert_eq!(
            fields
                .fields()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["label", "rank", "enabled"]
        );
        assert_eq!(fields.fields().get("label").unwrap().required, Some(true));
        assert_eq!(fields.fields().get("rank").unwrap().required, Some(false));
        assert_eq!(
            schema.resolve_model_name("shared", &|_, _| false).unwrap(),
            "badge"
        );
        assert!(
            schema
                .resolve_model_name("old_badges", &|_, _| false)
                .is_err()
        );
    }

    #[test]
    fn custom_model_names_precede_aliases_and_reserve_native_roles() {
        let mut schema = ModelFields::default();
        schema
            .register_custom_model("badge", Some("user"), UserConfig::default())
            .unwrap();
        let aliases = |role, name: &str| role == EntityRole::User && name == "badge";
        assert_eq!(
            schema.resolve_model_name("badge", &aliases).unwrap(),
            "badge"
        );
        assert_eq!(schema.resolve_model_name("user", &aliases).unwrap(), "user");
        for name in [
            "user",
            "passkey",
            "member",
            "invitation",
            "teamMember",
            "organizationRole",
            "rateLimit",
        ] {
            let error = schema
                .register_custom_model(name, None, UserConfig::default())
                .unwrap_err();
            assert_eq!(
                error
                    .instrumentation_message()
                    .expect("fixture error message"),
                format!(
                    "Model \"{name}\" is reserved for a native model and cannot be declared as a custom model"
                )
            );
        }
        assert_eq!(schema.custom_models().count(), 1);
        schema
            .register_custom_model("badge", Some(""), UserConfig::default())
            .unwrap();
        assert_eq!(schema.custom_models().next().unwrap().1, "badge");
        assert_eq!(
            schema
                .resolve_model_name("missingBadge", &aliases)
                .unwrap_err()
                .instrumentation_message()
                .expect("fixture error message"),
            "Model \"missingBadge\" not found in schema"
        );
    }
}
