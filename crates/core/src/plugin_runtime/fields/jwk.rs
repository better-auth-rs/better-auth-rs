use super::*;
use crate::store::schema::{core_fields, resolve_field_name};

fn native_name(name: &str) -> bool {
    core_fields(EntityRole::Jwk)
        .iter()
        .any(|field| field.name == name)
        || matches!(name, "publicKey" | "privateKey" | "createdAt" | "expiresAt")
}

pub(super) fn validate_fields(fields: &UserConfig) -> AuthResult<()> {
    for (name, field) in fields.fields() {
        let storage = resolve_field_name(field.field_name.as_deref(), name);
        if native_name(name) || native_name(storage) {
            return Err(AuthError::config(format!(
                "Jwk additional field {name} cannot replace native field {storage}"
            )));
        }
    }
    Ok(())
}
