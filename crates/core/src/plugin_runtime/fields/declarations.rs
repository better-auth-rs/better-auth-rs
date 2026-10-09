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
            EntityRole::Organization => vec![
                ("name", String, true),
                ("slug", String, true),
                ("logo", String, false),
                ("createdAt", Date, true),
                ("metadata", String, false),
            ],
            EntityRole::Team => vec![
                ("name", String, true),
                ("memberCount", Number, true),
                ("organizationId", String, true),
                ("createdAt", Date, true),
                ("updatedAt", Date, false),
            ],
            EntityRole::Member => vec![
                ("organizationId", String, true),
                ("userId", String, true),
                ("role", String, true),
                ("createdAt", Date, true),
            ],
            EntityRole::Invitation => vec![
                ("organizationId", String, true),
                ("email", String, true),
                ("role", String, false),
                ("teamId", String, false),
                ("status", String, true),
                ("expiresAt", Date, true),
                ("createdAt", Date, true),
                ("inviterId", String, true),
            ],
            EntityRole::OrganizationRole => vec![
                ("organizationId", String, true),
                ("role", String, true),
                ("permission", String, true),
                ("createdAt", Date, true),
                ("updatedAt", Date, false),
            ],
            EntityRole::RateLimit => vec![
                ("key", String, true),
                ("count", Number, true),
                ("lastRequest", Number, true),
            ],
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
            EntityRole::Jwk => vec![
                ("publicKey", String, true),
                ("privateKey", String, true),
                ("createdAt", Date, true),
                ("expiresAt", Date, false),
                ("alg", String, false),
                ("crv", String, false),
            ],
            EntityRole::WalletAddress => vec![
                ("userId", String, true),
                ("address", String, true),
                ("chainId", Number, true),
                ("isPrimary", Boolean, false),
                ("createdAt", Date, true),
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
        if matches!(
            role,
            EntityRole::Organization
                | EntityRole::Team
                | EntityRole::Member
                | EntityRole::Invitation
                | EntityRole::OrganizationRole
        ) {
            for (name, declaration) in fields.fields_mut() {
                match (role, name.as_str()) {
                    (
                        EntityRole::Team
                        | EntityRole::Member
                        | EntityRole::Invitation
                        | EntityRole::OrganizationRole,
                        "organizationId",
                    ) => {
                        declaration.references = Some(UserFieldReference {
                            model: "organization".into(),
                            field: "id".into(),
                            ..Default::default()
                        });
                        declaration.index = Some(true);
                    }
                    (EntityRole::Member, "userId") | (EntityRole::Invitation, "inviterId") => {
                        declaration.references = Some(UserFieldReference {
                            model: "user".into(),
                            field: "id".into(),
                            ..Default::default()
                        });
                        if role == EntityRole::Member {
                            declaration.index = Some(true);
                        }
                    }
                    (EntityRole::Team, "memberCount") => {
                        declaration.default_value = Some(0.into());
                        declaration.input = Some(false);
                        declaration.returned = Some(false);
                    }
                    (EntityRole::Organization, "slug") => {
                        declaration.unique = Some(true);
                        declaration.index = Some(true);
                    }
                    (EntityRole::Invitation, "email") | (EntityRole::OrganizationRole, "role") => {
                        declaration.index = Some(true);
                    }
                    (EntityRole::Member, "role") => {
                        declaration.default_value = Some("member".into())
                    }
                    (EntityRole::Invitation, "status") => {
                        declaration.default_value = Some("pending".into())
                    }
                    (EntityRole::Invitation | EntityRole::OrganizationRole, "createdAt") => {
                        declaration.default_value_fn =
                            Some(Arc::new(|| Ok(Value::Date(chrono::Utc::now().into()))));
                    }
                    (EntityRole::Team | EntityRole::OrganizationRole, "updatedAt") => {
                        declaration.on_update =
                            Some(Arc::new(|| Ok(Value::Date(chrono::Utc::now().into()))));
                    }
                    _ => {}
                }
                if matches!(
                    (role, name.as_str()),
                    (EntityRole::Organization, "name" | "slug")
                        | (EntityRole::Member, "role")
                        | (
                            EntityRole::Invitation,
                            "email" | "role" | "teamId" | "status"
                        )
                ) {
                    declaration.sortable = Some(true);
                }
            }
        } else if role == EntityRole::RateLimit {
            if let Some(field) = fields.fields_mut().get_mut("key") {
                field.unique = Some(true);
            }
            if let Some(field) = fields.fields_mut().get_mut("lastRequest") {
                field.bigint = Some(true);
                field.default_value_fn = Some(Arc::new(|| {
                    Ok(chrono::Utc::now().timestamp_millis().into())
                }));
            }
        } else if role == EntityRole::ApiKey {
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
        } else if role == EntityRole::WalletAddress {
            if let Some(field) = fields.fields_mut().get_mut("isPrimary") {
                field.required = None;
                field.default_value = Some(false.into());
            }
            if let Some(field) = fields.fields_mut().get_mut("userId") {
                field.index = Some(true);
                field.references = Some(UserFieldReference {
                    model: "user".into(),
                    field: "id".into(),
                    ..Default::default()
                });
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
