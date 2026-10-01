//! Field policies shared by organization routes and persistence adapters.

use crate::user_fields::UserConfig;

/// Prepare the Organization adapter's metadata value before database field policies run.
pub fn metadata_input(value: Option<serde_json::Value>, create: bool) -> Option<serde_json::Value> {
    let value = value?;
    if create && !crate::user_fields::is_truthy(&value) {
        return None;
    }
    if create || value.is_object() || value.is_array() || value.is_null() {
        Some(serde_json::Value::String(value.to_string()))
    } else {
        Some(value)
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
    /// Apply the upstream eager partial schema for dynamic-role storage.
    pub fn into_storage(mut self) -> Self {
        for field in self.organization_role.fields_mut().values_mut() {
            field.required = Some(false);
        }
        self
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
