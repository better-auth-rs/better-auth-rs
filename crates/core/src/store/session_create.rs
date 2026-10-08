use super::{TypedTransactionFuture, database_hooks::DatabaseHookUpdate};
use crate::{AuthConfig, AuthResult, CreateSession, FieldMap, SessionView};

/// A secondary creation write between database insertion and creation-after hooks.
pub struct SessionCreateWriter {
    /// Insert the session in the database before calling the writer.
    pub write_database: bool,
    /// Queue the writer after creation-after hooks instead of writing immediately.
    pub deferred: bool,
    /// Receive the original creation object and final session fields in adapter output order.
    pub write: Box<dyn FnOnce(FieldMap, FieldMap) -> TypedTransactionFuture<'static, ()> + Send>,
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
        let _ = input.inherited_fields.remove("id");
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
        fields.extend(input.inherited_fields);
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
        fields.sort_property_order();
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
        self.fields.sort_property_order();
        match outcome {
            DatabaseHookUpdate::Continue => true,
            DatabaseHookUpdate::Cancel => false,
            DatabaseHookUpdate::Patch(patch) => {
                if self.original.is_none() {
                    self.original = Some(self.fields.clone());
                }
                self.fields.extend(patch);
                self.fields.sort_property_order();
                true
            }
        }
    }

    pub fn into_parts(mut self) -> (FieldMap, FieldMap) {
        self.fields.sort_property_order();
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
    session_field_schema(config, input).adapter_fields(&[])
}

/// Preserve complete ordered declarations for adapter readback before ID canonicalization.
#[doc(hidden)]
pub fn session_field_schema(
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
        (
            "token".into(),
            UserFieldConfig {
                unique: Some(true),
                ..field(UserFieldType::String, true)
            },
        ),
        (
            "createdAt".into(),
            UserFieldConfig {
                default_value_fn: Some(std::sync::Arc::new(|| Ok(chrono::Utc::now().into()))),
                ..field(UserFieldType::Date, true)
            },
        ),
        (
            "updatedAt".into(),
            UserFieldConfig {
                on_update: Some(std::sync::Arc::new(|| Ok(chrono::Utc::now().into()))),
                ..field(UserFieldType::Date, true)
            },
        ),
        ("ipAddress".into(), field(UserFieldType::String, false)),
        ("userAgent".into(), field(UserFieldType::String, false)),
        (
            "userId".into(),
            UserFieldConfig {
                index: Some(true),
                references: Some(UserFieldReference {
                    model: "user".into(),
                    field: "id".into(),
                    ..Default::default()
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
    .ordered_declarations(&[])
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
                crate::utils::date::parse_date_constructor(text)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FieldDate, FieldValue, user_fields::UserFieldConfig};

    #[test]
    fn session_hooks_observe_numeric_properties_before_stable_string_properties() -> AuthResult<()>
    {
        let mut config = AuthConfig::new("session-property-order-secret-at-least-32");
        let _ = config.session.fields_mut().insert(
            "4".into(),
            UserFieldConfig {
                default_value: Some("default-four".into()),
                ..Default::default()
            },
        );
        let input = CreateSession {
            inherited_fields: [
                ("10".into(), "inherited-ten".into()),
                ("inherited".into(), "kept".into()),
                ("02".into(), "string-key".into()),
                ("0".into(), "inherited-zero".into()),
            ]
            .into(),
            additional_fields: [
                ("2".into(), "caller-two".into()),
                ("0".into(), "caller-zero".into()),
                ("tail".into(), "caller-tail".into()),
            ]
            .into(),
            user_id: "owner".into(),
            expires_at: FieldDate::from_milliseconds(1_000.0),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        };
        let mut prepared = PreparedSessionCreate::new(input, &config, false)?;
        let initial = [
            "0",
            "2",
            "4",
            "10",
            "ipAddress",
            "userAgent",
            "inherited",
            "02",
            "tail",
            "expiresAt",
            "userId",
            "token",
            "createdAt",
            "updatedAt",
        ];
        assert_eq!(
            prepared
                .fields_mut()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            initial,
        );
        let _ = prepared
            .fields_mut()
            .insert("1".into(), "direct-one".into());
        let _ = prepared
            .fields_mut()
            .insert("first".into(), "first-hook".into());
        assert!(prepared.apply(DatabaseHookUpdate::Continue));
        let detached_order = [
            "0",
            "1",
            "2",
            "4",
            "10",
            "ipAddress",
            "userAgent",
            "inherited",
            "02",
            "tail",
            "expiresAt",
            "userId",
            "token",
            "createdAt",
            "updatedAt",
            "first",
        ];
        assert_eq!(
            prepared
                .fields_mut()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            detached_order,
        );
        assert!(prepared.apply(DatabaseHookUpdate::Patch(FieldMap::new())));
        let _ = prepared
            .fields_mut()
            .insert("3".into(), "direct-three".into());
        let _ = prepared
            .fields_mut()
            .insert("token".into(), "hook-token".into());
        assert!(
            prepared.apply(DatabaseHookUpdate::Patch(
                [
                    ("9".into(), "patch-nine".into()),
                    ("first".into(), "patched-first".into()),
                    ("last".into(), "patch-last".into()),
                ]
                .into(),
            ))
        );
        assert_eq!(
            prepared
                .fields_mut()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "0",
                "1",
                "2",
                "3",
                "4",
                "9",
                "10",
                "ipAddress",
                "userAgent",
                "inherited",
                "02",
                "tail",
                "expiresAt",
                "userId",
                "token",
                "createdAt",
                "updatedAt",
                "first",
                "last",
            ],
        );
        let _ = prepared
            .fields_mut()
            .insert("8".into(), "final-eight".into());
        let (original, actual) = prepared.into_parts();
        assert_eq!(
            original.keys().map(String::as_str).collect::<Vec<_>>(),
            detached_order
        );
        assert_eq!(
            actual.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "0",
                "1",
                "2",
                "3",
                "4",
                "8",
                "9",
                "10",
                "ipAddress",
                "userAgent",
                "inherited",
                "02",
                "tail",
                "expiresAt",
                "userId",
                "token",
                "createdAt",
                "updatedAt",
                "first",
                "last",
            ],
        );
        assert_eq!(actual["0"], FieldValue::from("caller-zero"));
        assert_eq!(actual["4"], FieldValue::from("default-four"));
        assert_eq!(original["first"], FieldValue::from("first-hook"));
        assert_eq!(actual["first"], FieldValue::from("patched-first"));
        assert_ne!(original["token"], actual["token"]);
        assert_eq!(actual["token"], FieldValue::from("hook-token"));
        Ok(())
    }

    #[test]
    fn inherited_session_fields_keep_order_but_yield_to_native_defaults_and_overrides()
    -> AuthResult<()> {
        let mut config = AuthConfig::new("session-inheritance-secret-at-least-32");
        let _ = config.session.fields_mut().insert(
            "marker".into(),
            UserFieldConfig {
                default_value: Some("default".into()),
                ..Default::default()
            },
        );
        let inherited: FieldMap = [
            ("id".into(), "old-id".into()),
            ("token".into(), "old-token".into()),
            ("userId".into(), "old-user".into()),
            ("marker".into(), "old-marker".into()),
            (
                "sameObject".into(),
                FieldMap::from([("value".into(), 1.into())]).into(),
            ),
            ("ownUndefined".into(), FieldValue::Undefined),
        ]
        .into();
        let input = crate::CreateSession {
            inherited_fields: inherited.clone(),
            additional_fields: [("ownUndefined".into(), FieldValue::Null)].into(),
            user_id: "new-user".into(),
            expires_at: FieldDate::from_milliseconds(100.0),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        };
        let (original, actual) = PreparedSessionCreate::new(input, &config, false)?.into_parts();
        assert_eq!(original, actual);
        assert!(!actual.contains_key("id"));
        assert_eq!(actual.get("userId"), Some(&"new-user".into()));
        assert_ne!(actual.get("token"), Some(&"old-token".into()));
        assert_eq!(actual.get("marker"), Some(&"default".into()));
        assert_eq!(actual.get("ownUndefined"), Some(&FieldValue::Null));
        assert!(
            actual
                .get("sameObject")
                .zip(inherited.get("sameObject"))
                .is_some_and(|(left, right)| left.strict_equals(right))
        );
        assert_eq!(
            actual.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "ipAddress",
                "userAgent",
                "token",
                "userId",
                "marker",
                "sameObject",
                "ownUndefined",
                "expiresAt",
                "createdAt",
                "updatedAt"
            ]
        );
        Ok(())
    }
}
