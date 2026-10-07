use super::{TypedTransactionFuture, database_hooks::DatabaseHookUpdate};
use crate::{AuthConfig, AuthResult, CreateSession, FieldMap, SessionView};

/// A secondary creation write between database insertion and creation-after hooks.
pub struct SessionCreateWriter {
    /// Insert the session in the database before calling the writer.
    pub write_database: bool,
    /// Queue the writer after creation-after hooks instead of writing immediately.
    pub deferred: bool,
    /// Receive the original creation object and the final session returned by the adapter.
    pub write: Box<dyn FnOnce(FieldMap, SessionView) -> TypedTransactionFuture<'static, ()> + Send>,
}

/// Prepared public fields shared by database and secondary Session creation.
#[doc(hidden)]
pub struct PreparedSessionCreate {
    fields: FieldMap,
    original: Option<FieldMap>,
}

impl PreparedSessionCreate {
    pub fn new(
        mut input: CreateSession,
        config: &AuthConfig,
        secondary_only: bool,
    ) -> AuthResult<Self> {
        let _ = input.additional_fields.remove("id");
        let mut fields = FieldMap::new();
        if secondary_only {
            let id = config
                .advanced
                .generate_id("session", None)?
                .unwrap_or_else(|| crate::id::random_id(None));
            if !id.is_empty() {
                let _ = fields.insert("id".into(), id.into());
            }
        }
        let defaults = config.session_default_fields()?;
        let _ = fields.insert(
            "ipAddress".into(),
            input.ip_address.unwrap_or_default().into(),
        );
        let _ = fields.insert(
            "userAgent".into(),
            input.user_agent.unwrap_or_default().into(),
        );
        for (name, value) in [
            ("impersonatedBy", input.impersonated_by),
            ("activeOrganizationId", input.active_organization_id),
        ] {
            if let Some(value) = value {
                let _ = fields.insert(name.into(), value.into());
            }
        }
        fields.extend(input.additional_fields.clone());
        fields.extend([
            ("expiresAt".into(), input.expires_at.into()),
            ("userId".into(), input.user_id.into_field_value()),
            ("token".into(), crate::id::random_id(None).into()),
            ("createdAt".into(), chrono::Utc::now().into()),
            ("updatedAt".into(), chrono::Utc::now().into()),
        ]);
        fields.extend(defaults);
        // CreateSession callers supply explicit overrides, including native public fields.
        fields.extend(input.additional_fields);
        Ok(Self {
            fields,
            original: None,
        })
    }

    pub fn fields_mut(&mut self) -> &mut FieldMap {
        &mut self.fields
    }

    /// An empty patch still detaches later property replacements from the original object.
    pub fn apply(&mut self, outcome: DatabaseHookUpdate<FieldMap>) -> bool {
        match outcome {
            DatabaseHookUpdate::Continue => true,
            DatabaseHookUpdate::Cancel => false,
            DatabaseHookUpdate::Patch(patch) => {
                if self.original.is_none() {
                    self.original = Some(self.fields.clone());
                }
                self.fields.extend(patch);
                true
            }
        }
    }

    pub fn into_parts(self) -> (FieldMap, FieldMap) {
        (
            self.original.unwrap_or_else(|| self.fields.clone()),
            self.fields,
        )
    }
}

/// Compose native and configured creation fields before ordered adapter conversion.
#[doc(hidden)]
pub fn session_create_schema(
    config: &crate::config::SessionConfig,
    input: &FieldMap,
) -> crate::user_fields::UserConfig {
    use crate::user_fields::{UserConfig, UserFieldConfig, UserFieldReference, UserFieldType};
    let field = |field_type, required| UserFieldConfig {
        field_type,
        required: Some(required),
        ..Default::default()
    };
    let mut fields: indexmap::IndexMap<_, _> = [
        ("expiresAt".into(), field(UserFieldType::Date, true)),
        ("token".into(), field(UserFieldType::String, true)),
        (
            "createdAt".into(),
            UserFieldConfig {
                default_value_fn: Some(std::sync::Arc::new(|| Ok(chrono::Utc::now().into()))),
                ..field(UserFieldType::Date, true)
            },
        ),
        ("updatedAt".into(), field(UserFieldType::Date, true)),
        ("ipAddress".into(), field(UserFieldType::String, false)),
        ("userAgent".into(), field(UserFieldType::String, false)),
        (
            "userId".into(),
            UserFieldConfig {
                references: Some(UserFieldReference {
                    model: "user".into(),
                    field: "id".into(),
                }),
                ..field(UserFieldType::String, true)
            },
        ),
    ]
    .into();
    for name in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
        if input.contains_key(name) {
            let _ = fields.insert(name.into(), field(UserFieldType::String, false));
        }
    }
    fields.extend(config.fields().clone());
    UserConfig {
        additional_fields: Some(fields),
    }
    .adapter_fields(&[])
}

/// Recover native values from the final physical fields without consuming shared aliases.
#[doc(hidden)]
pub fn session_create_native_fields(
    schema: &crate::user_fields::UserConfig,
    storage: &FieldMap,
) -> FieldMap {
    [
        "token",
        "userId",
        "expiresAt",
        "createdAt",
        "updatedAt",
        "ipAddress",
        "userAgent",
        "impersonatedBy",
        "activeOrganizationId",
        "activeTeamId",
    ]
    .into_iter()
    .filter(|name| schema.fields().contains_key(*name))
    .map(|name| {
        let mut value = storage
            .get(schema.record_storage_key(name))
            .cloned()
            .unwrap_or_default();
        if matches!(name, "expiresAt" | "createdAt" | "updatedAt")
            && let crate::FieldValue::String(text) = &value
        {
            value = crate::FieldValue::Date(
                crate::utils::date::parse_adapter_date(text)
                    .map(crate::FieldDate::from)
                    .unwrap_or_else(crate::FieldDate::invalid),
            );
        }
        (name.into(), value)
    })
    .collect()
}

/// Materialize secondary fields only after the complete before-hook chain.
#[doc(hidden)]
pub fn session_from_create_fields(fields: FieldMap) -> AuthResult<SessionView> {
    use crate::FromFieldMap;
    let mut session = SessionView::from_field_values(fields)?;
    session.active = true;
    Ok(session)
}
