use super::*;
use crate::user_fields::{
    FieldTransforms, UserFieldConfig, UserFieldReference, UserFieldTransform,
};

fn field(field_type: UserFieldType, required: bool) -> UserFieldConfig {
    UserFieldConfig {
        field_type,
        required: Some(required),
        ..Default::default()
    }
}

impl ModelFields {
    /// Return complete upstream declarations in their original schema order.
    #[doc(hidden)]
    pub fn plugin_native_fields(role: EntityRole) -> UserConfig {
        use UserFieldType::{Boolean, Date, Number, String};
        let declarations = match role {
            EntityRole::ApiKey => vec![
                ("configId", String, true),
                ("name", String, false),
                ("start", String, false),
                ("referenceId", String, true),
                ("prefix", String, false),
                ("key", String, true),
                ("refillInterval", Number, false),
                ("refillAmount", Number, false),
                ("lastRefillAt", Date, false),
                ("enabled", Boolean, false),
                ("rateLimitEnabled", Boolean, false),
                ("rateLimitTimeWindow", Number, false),
                ("rateLimitMax", Number, false),
                ("requestCount", Number, false),
                ("remaining", Number, false),
                ("lastRequest", Date, false),
                ("expiresAt", Date, false),
                ("createdAt", Date, true),
                ("updatedAt", Date, true),
                ("permissions", String, false),
                ("metadata", String, false),
            ],
            EntityRole::Passkey => vec![
                ("name", String, false),
                ("publicKey", String, true),
                ("userId", String, true),
                ("credentialID", String, true),
                ("counter", Number, true),
                ("deviceType", String, true),
                ("backedUp", Boolean, true),
                ("transports", String, false),
                ("createdAt", Date, false),
                ("aaguid", String, false),
            ],
            EntityRole::TwoFactor => vec![
                ("secret", String, true),
                ("backupCodes", String, true),
                ("userId", String, true),
                ("verified", Boolean, false),
                ("failedVerificationCount", Number, false),
                ("lockedUntil", Date, false),
            ],
            EntityRole::DeviceCode => vec![
                ("deviceCode", String, true),
                ("userCode", String, true),
                ("userId", String, false),
                ("expiresAt", Date, true),
                ("status", String, true),
                ("lastPolledAt", Date, false),
                ("pollingInterval", Number, false),
                ("clientId", String, false),
                ("scope", String, false),
            ],
            _ => Vec::new(),
        };
        let mut fields = UserConfig {
            additional_fields: Some(
                declarations
                    .into_iter()
                    .map(|(name, kind, required)| {
                        let mut declaration = field(kind, required);
                        if role == EntityRole::ApiKey {
                            declaration.input = Some(false);
                        }
                        if matches!(
                            (role, name),
                            (EntityRole::ApiKey, "configId" | "referenceId" | "key")
                                | (EntityRole::Passkey, "userId" | "credentialID")
                        ) {
                            declaration.index = Some(true);
                        }
                        (name.to_owned(), declaration)
                    })
                    .collect(),
            ),
        };
        if role == EntityRole::ApiKey {
            for (name, value) in [
                ("configId", Value::from("default")),
                ("enabled", Value::Bool(true)),
                ("rateLimitEnabled", Value::Bool(true)),
                ("rateLimitTimeWindow", Value::Number(86_400_000.0)),
                ("rateLimitMax", Value::Number(10.0)),
                ("requestCount", Value::Number(0.0)),
            ] {
                if let Some(field) = fields.fields_mut().get_mut(name) {
                    field.default_value = Some(value);
                }
            }
            if let Some(field) = fields.fields_mut().get_mut("metadata") {
                field.input = Some(true);
                field.transform = Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(|value| {
                        Ok(value.stringify()?.map(Value::String).unwrap_or_default())
                    })),
                    output: Some(UserFieldTransform::new(|value| {
                        if value.is_truthy() {
                            crate::utils::json::parse_client_json(value)
                        } else {
                            Ok(Value::Null)
                        }
                    })),
                });
            }
        } else if role == EntityRole::TwoFactor {
            for (name, declaration) in fields.fields_mut() {
                if matches!(
                    name.as_str(),
                    "secret" | "backupCodes" | "userId" | "failedVerificationCount" | "lockedUntil"
                ) {
                    declaration.returned = Some(false);
                }
                if matches!(
                    name.as_str(),
                    "verified" | "failedVerificationCount" | "lockedUntil"
                ) {
                    declaration.input = Some(false);
                }
                if matches!(name.as_str(), "secret" | "userId") {
                    declaration.index = Some(true);
                }
                match name.as_str() {
                    "verified" => declaration.default_value = Some(true.into()),
                    "failedVerificationCount" => declaration.default_value = Some(0.into()),
                    "userId" => {
                        declaration.references = Some(UserFieldReference {
                            model: "user".into(),
                            field: "id".into(),
                            ..Default::default()
                        })
                    }
                    _ => {}
                }
            }
        } else if role == EntityRole::Passkey
            && let Some(field) = fields.fields_mut().get_mut("userId")
        {
            field.references = Some(UserFieldReference {
                model: "user".into(),
                field: "id".into(),
                ..Default::default()
            });
        }
        fields
    }

    /// Merge complete replacement declarations without changing existing schema positions.
    #[doc(hidden)]
    pub fn plugin_fields(&self, role: EntityRole) -> UserConfig {
        let fields = if self
            .schema_models
            .as_ref()
            .is_some_and(|models| models.iter().any(|(model, _)| *model == role))
        {
            self.fields(role).clone()
        } else {
            // Standalone store calls retain native defaults without plugin initialization.
            let mut fields = Self::plugin_native_fields(role);
            fields
                .fields_mut()
                .extend(self.fields(role).fields().clone());
            fields
        };
        UserConfig {
            additional_fields: Some(
                fields
                    .ordered_fields(&[])
                    .into_iter()
                    .map(|(name, field)| (name.to_owned(), field.clone()))
                    .collect(),
            ),
        }
    }
}
