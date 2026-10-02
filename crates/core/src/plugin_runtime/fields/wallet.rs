use super::*;
use crate::store::schema::{core_fields, resolve_field_name};

fn native_name(name: &str) -> bool {
    core_fields(EntityRole::WalletAddress)
        .iter()
        .any(|field| field.name == name)
        || matches!(name, "userId" | "chainId" | "isPrimary" | "createdAt")
}

pub(super) fn validate_fields(fields: &UserConfig) -> AuthResult<()> {
    for (name, field) in fields.fields() {
        let storage = resolve_field_name(field.field_name.as_deref(), name);
        if native_name(name) || native_name(storage) {
            return Err(AuthError::config(format!(
                "WalletAddress additional field {name} cannot replace native field {storage}"
            )));
        }
    }
    Ok(())
}
