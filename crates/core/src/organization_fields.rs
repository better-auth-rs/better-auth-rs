//! Field policies shared by organization routes and persistence adapters.

use crate::user_fields::UserConfig;
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
    /// Reject additional fields that would redefine typed built-in fields.
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
                for name in [field.name, &public_name] {
                    if fields.additional_fields.contains_key(name) {
                        return Err(crate::AuthError::config(format!(
                            "Organization schema {entity}.{name} redefines a built-in field; additional fields must use new names"
                        )));
                    }
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
