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
                || storage != name
            {
                return Err(AuthError::config(format!(
                    "Passkey {name} requires its ordinary string column without reference or field-name replacement"
                )));
            }
        } else if native_name(name) || native_name(storage) {
            return Err(AuthError::config(format!(
                "Passkey additional field {name} cannot replace native field {storage}"
            )));
        }
    }
    Ok(())
}

pub(crate) struct PasskeyFieldPatch {
    pub name: Option<Option<String>>,
    pub aaguid: Option<Option<String>>,
    pub additional_fields: Map<String, Value>,
}

impl PasskeyFieldPatch {
    pub(crate) fn apply(self, row: &mut Passkey) {
        if let Some(name) = self.name {
            row.name = name.into();
        }
        if let Some(aaguid) = self.aaguid {
            row.aaguid = aaguid.into();
        }
        row.additional_fields.extend(self.additional_fields);
    }
}

impl ModelFields {
    pub(crate) async fn passkey_fields_for_storage(
        &self,
        name: SchemaValue<Option<String>>,
        aaguid: SchemaValue<Option<String>>,
        mut extras: Map<String, Value>,
        create: bool,
        bind: impl Fn(&UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<PasskeyFieldPatch> {
        let mut core = Map::new();
        for (name, value) in [("name", name), ("aaguid", aaguid)] {
            let _ = extras.remove(name);
            if let Some(value) = value.json()? {
                let _ = core.insert(name.into(), value);
            }
        }
        let config = self.fields(EntityRole::Passkey);
        let mut fields = config
            .organization_storage_fields(core, extras, create)
            .await?;
        let name = optional_string(&mut fields, "name")?;
        let aaguid = optional_string(&mut fields, "aaguid")?;
        for (name, field) in config.fields() {
            let storage = resolve_field_name(field.field_name.as_deref(), name);
            if let Some(value) = fields.get_mut(storage) {
                *value = bind(field, value.take())?;
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
        let records = rows
            .iter()
            .map(|row| {
                let mut storage = row.additional_fields.clone();
                for (name, value) in [("name", &row.name), ("aaguid", &row.aaguid)] {
                    if let Some(value) = value.json()? {
                        let _ = storage.insert(name.into(), value);
                    }
                }
                Ok(AdapterRecord::new(Map::new(), storage))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        self.project_passkey_records(rows, records, true).await
    }

    /// Project extracted adapter fields without exposing undeclared model columns.
    pub async fn project_passkey_records(
        &self,
        mut rows: Vec<Passkey>,
        records: Vec<AdapterRecord>,
        supports_native_json: bool,
    ) -> AuthResult<Vec<Passkey>> {
        let fields = self.fields(EntityRole::Passkey);
        let output = fields
            .project_adapter_records(records, supports_native_json, true)
            .await?;
        for (row, mut output) in rows.iter_mut().zip(output) {
            for (name, value) in [("name", &mut row.name), ("aaguid", &mut row.aaguid)] {
                if fields.fields().contains_key(name) {
                    *value = output
                        .shift_remove(name)
                        .map(|value| value.json())
                        .transpose()?
                        .flatten()
                        .map(serde_json::from_value)
                        .transpose()?
                        .map(SchemaValue::Typed)
                        .unwrap_or_default();
                }
            }
            row.additional_fields = output
                .into_iter()
                .map(|(name, value)| Ok(value.json()?.map(|value| (name, value))))
                .collect::<AuthResult<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect();
        }
        Ok(rows)
    }
}
