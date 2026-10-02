use super::*;
use crate::DeviceCode;

fn native_name(name: &str) -> bool {
    crate::store::schema::core_fields(EntityRole::DeviceCode)
        .iter()
        .any(|field| field.name == name)
        || matches!(
            name,
            "deviceCode"
                | "userCode"
                | "userId"
                | "expiresAt"
                | "lastPolledAt"
                | "pollingInterval"
                | "clientId"
        )
}

pub(super) fn validate_fields(fields: &UserConfig) -> AuthResult<()> {
    for (name, field) in fields.fields() {
        let storage = field.field_name.as_deref().unwrap_or(name);
        if name == "scope" {
            if !matches!(field.field_type, UserFieldType::String)
                || field.references.is_some()
                || storage != name
            {
                return Err(AuthError::config(
                    "DeviceCode scope requires its ordinary string column without reference or field-name replacement",
                ));
            }
        } else if native_name(name) || native_name(storage) {
            return Err(AuthError::config(format!(
                "DeviceCode additional field {name} cannot replace native field {storage}"
            )));
        }
    }
    Ok(())
}

impl ModelFields {
    /// Prepare scope and declared application fields without changing credential or owner bindings.
    pub async fn device_code_fields_for_storage(
        &self,
        scope: SchemaValue<Option<String>>,
        mut additional_fields: Map<String, Value>,
        create: bool,
    ) -> AuthResult<Map<String, Value>> {
        // The typed scope owns omission too; application fields cannot supply an omitted native value.
        let _ = additional_fields.remove("scope");
        let core = scope
            .json()?
            .into_iter()
            .map(|value| ("scope".into(), value))
            .collect();
        self.fields(EntityRole::DeviceCode)
            .organization_storage_fields(core, additional_fields, create)
            .await
    }

    pub(crate) fn take_device_code_scope(
        fields: &mut Map<String, Value>,
    ) -> AuthResult<Option<Option<String>>> {
        optional_string(fields, "scope")
    }

    /// Project stored memory fields while retaining the original credential and authorization state.
    pub async fn project_device_codes(&self, rows: Vec<DeviceCode>) -> AuthResult<Vec<DeviceCode>> {
        let records = rows
            .iter()
            .map(|row| {
                let mut storage = row.additional_fields.clone();
                if let Some(scope) = row.scope.json()? {
                    let _ = storage.insert("scope".into(), scope);
                }
                Ok(AdapterRecord::new(Map::new(), storage))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        self.project_device_code_records(rows, records, true).await
    }

    /// Project extracted Device fields without replacing the raw record's typed bindings.
    pub async fn project_device_code_records(
        &self,
        mut rows: Vec<DeviceCode>,
        records: Vec<AdapterRecord>,
        supports_native_json: bool,
    ) -> AuthResult<Vec<DeviceCode>> {
        let fields = self.fields(EntityRole::DeviceCode);
        let output = fields
            .project_adapter_records(records, supports_native_json, true)
            .await?;
        for (row, mut output) in rows.iter_mut().zip(output) {
            if fields.fields().contains_key("scope") {
                row.scope = output
                    .shift_remove("scope")
                    .map(|value| value.json())
                    .transpose()?
                    .flatten()
                    .map(serde_json::from_value)
                    .transpose()?
                    .map(SchemaValue::Typed)
                    .unwrap_or_default();
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
