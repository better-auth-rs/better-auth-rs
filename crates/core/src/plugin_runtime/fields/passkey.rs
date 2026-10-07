use super::*;
use crate::Passkey;
use crate::store::schema::core_fields;
use crate::user_fields::UserFieldConfig;

fn native_name(name: &str) -> bool {
    core_fields(EntityRole::Passkey)
        .iter()
        .any(|field| field.name == name)
        || matches!(
            name,
            "publicKey"
                | "userId"
                | "credentialID"
                | "credentialId"
                | "deviceType"
                | "backedUp"
                | "createdAt"
                | "updatedAt"
        )
}

pub(super) fn field_order(name: &str) -> u8 {
    match name {
        "name" => 0,
        "aaguid" => 1,
        _ => 2,
    }
}

pub(super) fn validate_fields(fields: &UserConfig) -> AuthResult<()> {
    for (name, field) in fields.fields() {
        let storage = resolve_field_name(field.field_name.as_deref(), name);
        if matches!(name.as_str(), "name" | "aaguid") {
            if !matches!(field.field_type, UserFieldType::String)
                || field.references.is_some()
                || (native_name(storage) && storage != name)
            {
                return Err(AuthError::config(format!(
                    "Passkey {name} requires a string column without a reference or a different native field"
                )));
            }
        } else if native_name(name) || native_name(storage) {
            return Err(AuthError::config(format!(
                "Passkey additional field {name} cannot replace native field {storage}"
            )));
        }
        for native in ["name", "aaguid"] {
            let column = storage_name(fields, native);
            if name != native && (name == column || storage == column) {
                return Err(AuthError::config(format!(
                    "Passkey field {name} conflicts with {native} storage column {column}"
                )));
            }
        }
    }
    Ok(())
}

fn storage_name<'a>(fields: &'a UserConfig, name: &'a str) -> &'a str {
    resolve_field_name(
        fields
            .fields()
            .get(name)
            .and_then(|field| field.field_name.as_deref()),
        name,
    )
}

pub(crate) struct PasskeyFieldPatch {
    pub name: Option<SchemaValue<Option<String>>>,
    pub aaguid: Option<SchemaValue<Option<String>>>,
    pub additional_fields: FieldMap,
}

impl PasskeyFieldPatch {
    pub(crate) fn apply(self, row: &mut Passkey) {
        if let Some(name) = self.name {
            row.name = name;
        }
        if let Some(aaguid) = self.aaguid {
            row.aaguid = aaguid;
        }
        row.additional_fields.extend(self.additional_fields);
    }
}

impl ModelFields {
    pub(crate) async fn passkey_fields_for_storage(
        &self,
        name: SchemaValue<Option<String>>,
        aaguid: SchemaValue<Option<String>>,
        mut extras: FieldMap,
        create: bool,
        bind: impl Fn(&UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<PasskeyFieldPatch> {
        let mut core = FieldMap::new();
        for (name, value) in [("name", name), ("aaguid", aaguid)] {
            let _ = extras.shift_remove(name);
            if !value.is_undefined() {
                let _ = core.insert(name.into(), value.into_field_value());
            }
        }
        let config = self.fields(EntityRole::Passkey);
        let mut fields = config
            .organization_storage_fields(core, extras, create)
            .await?;
        let name = optional_string(&mut fields, storage_name(config, "name"));
        let aaguid = optional_string(&mut fields, storage_name(config, "aaguid"));
        for (name, field) in config.fields() {
            let storage = resolve_field_name(field.field_name.as_deref(), name);
            if let Some(value) = fields.get_mut(storage) {
                *value = bind(field, std::mem::take(value))?;
            }
        }
        Ok(PasskeyFieldPatch {
            name,
            aaguid,
            additional_fields: fields,
        })
    }

    /// Project declared Passkey fields while retaining credential, owner, and counter snapshots.
    pub async fn project_passkeys(&self, rows: Vec<Passkey>) -> AuthResult<Vec<Passkey>> {
        let fields = self.fields(EntityRole::Passkey);
        let records = rows
            .iter()
            .map(|row| {
                let mut storage = row.additional_fields.clone();
                for (name, value) in [("name", &row.name), ("aaguid", &row.aaguid)] {
                    if !value.is_undefined() {
                        let _ =
                            storage.insert(storage_name(fields, name).into(), value.field_value());
                    }
                }
                AdapterRecord::new(FieldMap::new(), storage)
            })
            .collect();
        self.project_passkey_records(
            rows,
            records,
            crate::user_fields::FieldOutputCapabilities::json_only(true),
            true,
        )
        .await
    }

    /// Project extracted adapter fields without exposing undeclared model columns.
    pub async fn project_passkey_records(
        &self,
        mut rows: Vec<Passkey>,
        records: Vec<AdapterRecord>,
        capabilities: crate::user_fields::FieldOutputCapabilities,
        supports_native_dates: bool,
    ) -> AuthResult<Vec<Passkey>> {
        let fields = self.fields(EntityRole::Passkey);
        let output = fields
            .project_adapter_records_with_capabilities(records, capabilities, supports_native_dates)
            .await?;
        for (row, mut output) in rows.iter_mut().zip(output) {
            for (name, value) in [("name", &mut row.name), ("aaguid", &mut row.aaguid)] {
                if fields.fields().contains_key(name) {
                    *value = output
                        .shift_remove(name)
                        .map(SchemaValue::from_field)
                        .unwrap_or_default();
                }
            }
            row.additional_fields = output;
        }
        Ok(rows)
    }
}
