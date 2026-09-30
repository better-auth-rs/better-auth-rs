//! Field policies shared by organization routes and persistence adapters.

use crate::user_fields::{UserConfig, UserFieldType};
use better_auth_schema_registry::{EntityRole, core_fields};

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
    use base64::Engine;
    use sha2::{Digest, Sha256};
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(serde_json::to_vec(&[team_id, user_id])?)))
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
    /// Validate the caller's schema before applying upstream's eager role partial schema.
    pub fn into_storage(mut self) -> crate::AuthResult<Self> {
        self.validate()?;
        for field in self.organization_role.additional_fields.values_mut() {
            field.required = Some(false);
        }
        Ok(self)
    }

    /// Reject built-in overrides that cannot preserve the typed storage contract.
    pub fn validate(&self) -> crate::AuthResult<()> {
        for (entity, role, fields) in [
            ("organization", EntityRole::Organization, &self.organization),
            ("member", EntityRole::Member, &self.member),
            ("invitation", EntityRole::Invitation, &self.invitation),
            ("team", EntityRole::Team, &self.team),
            (
                "organizationRole",
                EntityRole::OrganizationRole,
                &self.organization_role,
            ),
        ] {
            for field in core_fields(role) {
                let mut public_name = String::new();
                let mut uppercase = false;
                for character in field.name.chars() {
                    if character == '_' {
                        uppercase = true;
                    } else {
                        public_name.push(if uppercase {
                            character.to_ascii_uppercase()
                        } else {
                            character
                        });
                        uppercase = false;
                    }
                }
                if field.name != public_name && fields.additional_fields.contains_key(field.name) {
                    return Err(crate::AuthError::config(format!(
                        "Organization schema {entity}.{} must use the public field name {public_name}",
                        field.name
                    )));
                }
                let Some(policy) = fields.additional_fields.get(&public_name) else {
                    continue;
                };
                if matches!(field.name, "metadata" | "permission" | "member_count")
                    || (role == EntityRole::Organization && field.name == "updated_at")
                {
                    return Err(crate::AuthError::config(format!(
                        "Organization schema {entity}.{public_name} does not support built-in field policies"
                    )));
                }
                let nullable = field.ty.starts_with("Option<");
                let field_type = field.ty.trim_start_matches("Option<").trim_end_matches('>');
                if !matches!(
                    (field_type, &policy.field_type),
                    ("String", UserFieldType::String)
                        | ("DateTimeUtc", UserFieldType::Date)
                        | ("i64", UserFieldType::Number)
                ) {
                    return Err(crate::AuthError::config(format!(
                        "Organization schema {entity}.{public_name} must preserve the built-in {field_type} field type"
                    )));
                }
                if field.name != "id"
                    && policy.required.is_some_and(|required| required == nullable)
                {
                    return Err(crate::AuthError::config(format!(
                        "Organization schema {entity}.{public_name} must preserve the built-in field nullability"
                    )));
                }
            }
        }
        Ok(())
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
        .all(|schema| schema.additional_fields.is_empty())
    }
}
