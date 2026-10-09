use super::ModelFields;
use crate::{
    AuthError, AuthResult,
    store::schema::{EntityRole, resolve_field_name},
    user_fields::UserConfig,
};

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) enum ModelDeclaration {
    Native(EntityRole),
    Custom(String),
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

impl ModelFields {
    pub(crate) fn set_model_name(
        &mut self,
        role: EntityRole,
        model_name: Option<&str>,
    ) -> AuthResult<()> {
        let logical = NATIVE_MODELS
            .iter()
            .find_map(|(candidate, name)| (*candidate == role).then_some(*name))
            .ok_or_else(|| {
                AuthError::config(format!("Model name is not registered for {role:?}"))
            })?;
        let _ = self.declarations.insert(
            ModelDeclaration::Native(role),
            Some(resolve_field_name(model_name, logical).to_owned()),
        );
        Ok(())
    }

    pub(crate) fn register_custom_model(
        &mut self,
        name: String,
        model_name: Option<&str>,
        fields: UserConfig,
    ) -> AuthResult<()> {
        if NATIVE_MODELS.iter().any(|(_, native)| *native == name) {
            return Err(AuthError::config(format!(
                "Model \"{name}\" is reserved for a native model and cannot be declared as a custom model"
            )));
        }
        let physical_name = resolve_field_name(model_name, &name).to_owned();
        let _ = self
            .declarations
            .insert(ModelDeclaration::Custom(name.clone()), Some(physical_name));
        let declaration = self.custom_models.entry(name).or_default();
        if let Some(fields) = fields.additional_fields {
            declaration.fields_mut().extend(fields);
        }
        Ok(())
    }

    /// Read custom logical names, physical names, and merged field policies in declaration order.
    /// Storage adapters retain responsibility for custom model operations and migrations.
    pub fn custom_models(&self) -> impl Iterator<Item = (&str, &str, &UserConfig)> {
        self.declarations
            .iter()
            .filter_map(move |(declaration, physical)| match declaration {
                ModelDeclaration::Native(_) => None,
                ModelDeclaration::Custom(name) => self
                    .custom_models
                    .get(name)
                    .map(|fields| (name.as_str(), physical.as_deref().unwrap_or(name), fields)),
            })
    }

    pub(crate) fn resolve_model_name(
        &self,
        candidate: &str,
        table_matches: &impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<&str> {
        let active = self.schema_models.as_deref().unwrap_or(&[
            (EntityRole::User, "user"),
            (EntityRole::Session, "session"),
            (EntityRole::Account, "account"),
            (EntityRole::Verification, "verification"),
        ]);
        let mut models = indexmap::IndexMap::new();
        for (role, name) in active.iter().filter(|(role, _)| {
            matches!(
                role,
                EntityRole::User
                    | EntityRole::Session
                    | EntityRole::Account
                    | EntityRole::Verification
            )
        }) {
            let alias = self.declarations.get(&ModelDeclaration::Native(*role));
            let _ = models.insert(*name, (Some(*role), alias.and_then(Option::as_deref)));
        }
        for (declaration, physical) in &self.declarations {
            match declaration {
                ModelDeclaration::Native(role) => {
                    if let Some((_, name)) = active.iter().find(|(candidate, _)| candidate == role)
                    {
                        let _ = models
                            .entry(*name)
                            .or_insert((Some(*role), physical.as_deref()));
                    }
                }
                ModelDeclaration::Custom(name) => {
                    let _ = models.insert(name.as_str(), (None, physical.as_deref()));
                }
            }
        }
        for (role, name) in active {
            let _ = models.entry(*name).or_insert((Some(*role), None));
        }
        models.sort_by_cached_key(|name, _| {
            crate::utils::json::array_index(name).map_or((true, 0), |index| (false, index))
        });
        // Every logical name precedes physical aliases, including aliases of native models.
        models
            .get_key_value(candidate)
            .map(|(name, _)| *name)
            .or_else(|| {
                models
                    .iter()
                    .find(|(name, (role, physical))| match physical {
                        Some(physical) => resolve_field_name(Some(physical), name) == candidate,
                        None => role.is_some_and(|role| table_matches(role, candidate)),
                    })
                    .map(|(name, _)| *name)
            })
            .filter(|name| !name.is_empty())
            .ok_or_else(|| AuthError::config(format!("Model \"{candidate}\" not found in schema")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user_fields::UserFieldConfig;

    #[test]
    fn native_and_custom_aliases_follow_one_declaration_order() {
        for custom_first in [true, false] {
            let mut schema = ModelFields::default();
            schema.schema_models =
                Some(vec![(EntityRole::User, "user"), (EntityRole::Team, "team")]);
            if custom_first {
                schema
                    .register_custom_model("badge".into(), Some("shared"), UserConfig::default())
                    .unwrap();
            }
            schema
                .set_model_name(EntityRole::Team, Some("shared"))
                .unwrap();
            if !custom_first {
                schema
                    .register_custom_model("badge".into(), Some("shared"), UserConfig::default())
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
            legacy
                .register(EntityRole::Team, UserConfig::default())
                .unwrap();
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
                .register_custom_model("badge".into(), None, UserConfig::default())
                .unwrap();
            assert_eq!(
                replaced
                    .resolve_model_name("shared", &|_, _| false)
                    .unwrap(),
                "team"
            );
            replaced
                .register_custom_model("badge".into(), Some("shared"), UserConfig::default())
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
                .register_custom_model("0".into(), Some("shared"), UserConfig::default())
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
                "badge".into(),
                Some("old_badges"),
                fields(&["label", "rank"], false),
            )
            .unwrap();
        schema
            .register_custom_model("other".into(), Some("shared"), UserConfig::default())
            .unwrap();
        schema
            .register_custom_model(
                "badge".into(),
                Some("shared"),
                fields(&["label", "enabled"], true),
            )
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
            .register_custom_model("badge".into(), Some("user"), UserConfig::default())
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
                .register_custom_model(name.into(), None, UserConfig::default())
                .unwrap_err();
            assert_eq!(
                error.instrumentation_message(),
                format!(
                    "Model \"{name}\" is reserved for a native model and cannot be declared as a custom model"
                )
            );
        }
        assert_eq!(schema.custom_models().count(), 1);
        schema
            .register_custom_model("badge".into(), Some(""), UserConfig::default())
            .unwrap();
        assert_eq!(schema.custom_models().next().unwrap().1, "badge");
        assert_eq!(
            schema
                .resolve_model_name("missingBadge", &aliases)
                .unwrap_err()
                .instrumentation_message(),
            "Model \"missingBadge\" not found in schema"
        );
    }
}
