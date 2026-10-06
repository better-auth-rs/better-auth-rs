use super::*;
use crate::ApiKey;
use crate::store::schema::core_fields;
use crate::user_fields::UserFieldConfig;

fn native_name(name: &str) -> bool {
    core_fields(EntityRole::ApiKey)
        .iter()
        .any(|field| field.name == name)
        || matches!(
            name,
            "key"
                | "keyHash"
                | "referenceId"
                | "configId"
                | "refillInterval"
                | "refillAmount"
                | "lastRefillAt"
                | "rateLimitEnabled"
                | "rateLimitTimeWindow"
                | "rateLimitMax"
                | "requestCount"
                | "lastRequest"
                | "expiresAt"
                | "createdAt"
                | "updatedAt"
        )
}

pub(super) fn validate_fields(fields: &UserConfig) -> AuthResult<()> {
    for (name, field) in fields.fields() {
        let storage = resolve_field_name(field.field_name.as_deref(), name);
        if name == "name" {
            if !matches!(field.field_type, UserFieldType::String)
                || field.references.is_some()
                || storage != name
            {
                return Err(AuthError::config(
                    "ApiKey name requires its ordinary string column without reference or field-name replacement",
                ));
            }
        } else if native_name(name) || native_name(storage) {
            return Err(AuthError::config(format!(
                "ApiKey additional field {name} cannot replace native field {storage}"
            )));
        }
    }
    Ok(())
}

#[derive(Default)]
pub(crate) struct ApiKeyFieldPatch {
    pub name: Option<Option<String>>,
    pub additional_fields: Map<String, Value>,
}

impl ApiKeyFieldPatch {
    pub(crate) fn apply(self, row: &mut ApiKey) {
        if let Some(name) = self.name {
            row.name = name.into();
        }
        row.additional_fields.extend(self.additional_fields);
    }
}

impl ModelFields {
    pub(crate) async fn api_key_fields_for_storage(
        &self,
        name: Option<Option<String>>,
        mut extras: Map<String, Value>,
        create: bool,
        bind: impl Fn(&UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<ApiKeyFieldPatch> {
        let _ = extras.remove("name");
        let core = name
            .into_iter()
            .map(|name| {
                (
                    "name".to_owned(),
                    name.map(Value::String).unwrap_or(Value::Null),
                )
            })
            .collect();
        let config = self.fields(EntityRole::ApiKey);
        let mut fields = config
            .organization_storage_fields(core, extras, create)
            .await?;
        let name = optional_string(&mut fields, "name")?;
        for (name, field) in config.fields() {
            let storage = resolve_field_name(field.field_name.as_deref(), name);
            if let Some(value) = fields.get_mut(storage) {
                *value = bind(field, value.take())?;
            }
        }
        Ok(ApiKeyFieldPatch {
            name,
            additional_fields: fields,
        })
    }

    /// Project extracted adapter fields without exposing undeclared model columns.
    pub async fn project_api_key_records(
        &self,
        mut rows: Vec<ApiKey>,
        records: Vec<AdapterRecord>,
        capabilities: crate::user_fields::FieldOutputCapabilities,
        supports_native_dates: bool,
    ) -> AuthResult<Vec<ApiKey>> {
        let fields = self.fields(EntityRole::ApiKey);
        let output = fields
            .project_adapter_records_with_capabilities(records, capabilities, supports_native_dates)
            .await?;
        for (row, mut output) in rows.iter_mut().zip(output) {
            if fields.fields().contains_key("name") {
                row.name = output
                    .shift_remove("name")
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
