use super::ModelFields;
use crate::{
    AuthError, AuthResult,
    store::schema::{EntityRole, resolve_field_name},
    user_fields::UserConfig,
};

impl ModelFields {
    pub(crate) fn register_custom_model(
        &mut self,
        name: String,
        model_name: Option<&str>,
        fields: UserConfig,
    ) -> AuthResult<()> {
        if matches!(
            name.as_str(),
            "user"
                | "session"
                | "account"
                | "verification"
                | "organization"
                | "member"
                | "invitation"
                | "team"
                | "teamMember"
                | "organizationRole"
                | "apikey"
                | "deviceCode"
                | "passkey"
                | "twoFactor"
                | "jwks"
                | "walletAddress"
                | "rateLimit"
        ) {
            return Err(AuthError::config(format!(
                "Model \"{name}\" is reserved for a native model and cannot be declared as a custom model"
            )));
        }
        let physical_name = resolve_field_name(model_name, &name).to_owned();
        let declaration = self.custom_models.entry(name).or_default();
        declaration.0 = physical_name;
        if let Some(fields) = fields.additional_fields {
            declaration.1.fields_mut().extend(fields);
        }
        Ok(())
    }

    /// Read custom logical names, physical names, and merged field policies in declaration order.
    /// Storage adapters retain responsibility for custom model operations and migrations.
    pub fn custom_models(&self) -> impl Iterator<Item = (&str, &str, &UserConfig)> {
        self.custom_models
            .iter()
            .map(|(name, (physical, fields))| (name.as_str(), physical.as_str(), fields))
    }

    pub(crate) fn resolve_model_name(
        &self,
        candidate: &str,
        table_matches: &impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<&str> {
        let models = self.schema_models.as_deref().unwrap_or(&[
            (EntityRole::User, "user"),
            (EntityRole::Session, "session"),
            (EntityRole::Account, "account"),
            (EntityRole::Verification, "verification"),
        ]);
        // Every logical name precedes physical aliases, including aliases of native models.
        models
            .iter()
            .find(|(_, name)| *name == candidate)
            .map(|(_, name)| *name)
            .or_else(|| {
                self.custom_models
                    .get_key_value(candidate)
                    .map(|(name, _)| name.as_str())
            })
            .or_else(|| {
                models
                    .iter()
                    .find(|(role, _)| table_matches(*role, candidate))
                    .map(|(_, name)| *name)
            })
            .or_else(|| {
                self.custom_models()
                    .find(|(_, physical, _)| *physical == candidate)
                    .map(|(name, _, _)| name)
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
