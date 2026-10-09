//! Field policies shared by organization routes and persistence adapters.

use crate::user_fields::UserConfig;

/// Prepare the Organization adapter's metadata value before database field policies run.
pub fn metadata_input(
    value: Option<crate::FieldValue>,
    create: bool,
) -> crate::AuthResult<Option<crate::FieldValue>> {
    let Some(value) = value else { return Ok(None) };
    if create && !value.is_truthy() {
        return Ok(None);
    }
    if create
        || matches!(
            value,
            crate::FieldValue::Object(_)
                | crate::FieldValue::Array(_)
                | crate::FieldValue::Date(_)
                | crate::FieldValue::Null
        )
    {
        Ok(value.stringify()?.map(crate::FieldValue::String))
    } else {
        Ok(Some(value))
    }
}

/// Parse a numeric query string as the upstream adapter's `Number` conversion.
/// Empty and invalid strings remain strings in the adapter.
pub fn numeric_filter(value: &str) -> Option<f64> {
    let value =
        value.trim_matches(|ch: char| (ch.is_whitespace() && ch != '\u{85}') || ch == '\u{feff}');
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(digits) = value.strip_prefix(prefix) {
            if digits.is_empty() {
                return None;
            }
            return digits.chars().try_fold(0.0, |number, ch| {
                ch.to_digit(radix)
                    .map(|digit| number * f64::from(radix) + f64::from(digit))
            });
        }
    }
    if !matches!(value, "Infinity" | "+Infinity" | "-Infinity")
        && !value
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, '.' | '+' | '-' | 'e' | 'E'))
    {
        return None;
    }
    value.parse::<f64>().ok().filter(|number| !number.is_nan())
}

/// Match the Organization adapter's stable key for a team and user pair.
pub fn team_membership_key(team_id: &str, user_id: &str) -> crate::AuthResult<String> {
    team_membership_key_values(&team_id.into(), &user_id.into())
}

/// Retain native selectors in the internal team membership uniqueness key.
pub fn team_membership_key_values(
    team_id: &crate::FieldValue,
    user_id: &crate::FieldValue,
) -> crate::AuthResult<String> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let pair = crate::FieldValue::from(vec![team_id.clone(), user_id.clone()])
        .stringify()?
        .ok_or_else(|| crate::AuthError::internal("A membership key array must serialize"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(pair.as_bytes())))
}

/// Additional fields for the five entities supported by the Organization plugin.
/// Field attributes use the same adapter transforms as application user fields.
#[derive(Clone, Default)]
pub struct OrganizationFields {
    /// Organization field policies.
    pub organization: UserConfig,
    /// Member field policies.
    pub member: UserConfig,
    /// Invitation field policies.
    pub invitation: UserConfig,
    /// Team field policies.
    pub team: UserConfig,
    /// Dynamic organization role field policies.
    pub organization_role: UserConfig,
}

impl OrganizationFields {
    pub(crate) fn fields_for(
        &self,
        role: better_auth_schema_registry::EntityRole,
    ) -> crate::AuthResult<&UserConfig> {
        use better_auth_schema_registry::EntityRole;
        match role {
            EntityRole::Organization => Ok(&self.organization),
            EntityRole::Member => Ok(&self.member),
            EntityRole::Invitation => Ok(&self.invitation),
            EntityRole::Team => Ok(&self.team),
            EntityRole::OrganizationRole => Ok(&self.organization_role),
            _ => Err(crate::AuthError::config(
                "Expected an organization entity role",
            )),
        }
    }

    /// Resolve query policies from the same declarations used for writes and output.
    #[doc(hidden)]
    pub fn query_schema_for(
        &self,
        role: better_auth_schema_registry::EntityRole,
    ) -> crate::AuthResult<UserConfig> {
        self.schema_for(role)
    }

    /// Resolve complete declarations with whole-field replacements in native schema order.
    #[doc(hidden)]
    pub fn schema_for(
        &self,
        role: better_auth_schema_registry::EntityRole,
    ) -> crate::AuthResult<UserConfig> {
        let configured = self.fields_for(role)?;
        let mut fields = crate::plugin_runtime::ModelFields::plugin_native_fields(role);
        fields.fields_mut().extend(configured.fields().clone());
        Ok(fields)
    }

    /// Resolve raw declarations in native schema order and apply dynamic-role storage requirements.
    pub fn into_storage(self) -> Self {
        let mut fields = crate::plugin_runtime::ModelFields::default();
        fields.register_organization_schema(&self, true);
        fields.organization_fields(self)
    }

    /// Return whether all entity policies use only built-in fields.
    pub fn is_empty(&self) -> bool {
        [
            &self.organization,
            &self.member,
            &self.invitation,
            &self.team,
            &self.organization_role,
        ]
        .iter()
        .all(|schema| schema.fields().is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        plugin_runtime::ModelFields,
        user_fields::{UserFieldConfig, UserFieldType},
    };
    use better_auth_schema_registry::EntityRole;

    #[test]
    fn query_and_storage_share_complete_declarations_and_whole_field_replacements() {
        let fields = OrganizationFields {
            organization_role: UserConfig {
                additional_fields: Some(
                    [
                        (
                            "organizationId".into(),
                            UserFieldConfig {
                                field_type: UserFieldType::Boolean,
                                field_name: Some("role".into()),
                                ..Default::default()
                            },
                        ),
                        ("createdAt".into(), UserFieldConfig::default()),
                        ("updatedAt".into(), UserFieldConfig::default()),
                    ]
                    .into(),
                ),
            },
            ..Default::default()
        };
        let query = fields
            .query_schema_for(EntityRole::OrganizationRole)
            .unwrap();
        assert_eq!(
            query
                .fields()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "organizationId",
                "role",
                "permission",
                "createdAt",
                "updatedAt"
            ]
        );
        let organization_id = query.fields().get("organizationId").unwrap();
        assert!(matches!(organization_id.field_type, UserFieldType::Boolean));
        assert_eq!(organization_id.field_name.as_deref(), Some("role"));
        assert!(organization_id.references.is_none());
        assert!(organization_id.index.is_none());
        assert!(organization_id.required.is_none());
        assert!(
            query
                .fields()
                .get("createdAt")
                .unwrap()
                .default_value_fn
                .is_none()
        );
        assert!(query.fields().get("updatedAt").unwrap().on_update.is_none());
        assert_eq!(query.fields().get("role").unwrap().index, Some(true));
        let native = OrganizationFields::default()
            .query_schema_for(EntityRole::OrganizationRole)
            .unwrap();
        assert!(
            native
                .fields()
                .get("createdAt")
                .unwrap()
                .default_value_fn
                .is_some()
        );
        assert!(
            native
                .fields()
                .get("updatedAt")
                .unwrap()
                .on_update
                .is_some()
        );

        let mut registered = ModelFields::default();
        registered.register_organization_schema(&fields, true);
        assert_eq!(
            registered
                .fields(EntityRole::OrganizationRole)
                .fields()
                .keys()
                .collect::<Vec<_>>(),
            query.fields().keys().collect::<Vec<_>>()
        );
        let storage = registered
            .organization_fields(Default::default())
            .schema_for(EntityRole::OrganizationRole)
            .unwrap();
        assert_eq!(
            storage.fields().keys().collect::<Vec<_>>(),
            query.fields().keys().collect::<Vec<_>>()
        );
        assert_eq!(storage.fields().get("role").unwrap().index, Some(true));
        assert!(
            storage
                .fields()
                .values()
                .all(|field| field.required == Some(false))
        );
        assert!(
            storage
                .fields()
                .get("organizationId")
                .unwrap()
                .references
                .is_none()
        );
    }
}
