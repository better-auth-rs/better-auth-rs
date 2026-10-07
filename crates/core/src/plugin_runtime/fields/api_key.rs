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
            if !matches!(
                field.field_type,
                UserFieldType::String | UserFieldType::Enum(_) | UserFieldType::Json
            ) || field.references.is_some()
                || (native_name(storage) && storage != name)
            {
                return Err(AuthError::config(
                    "ApiKey name requires a string, enum, or JSON declaration without a reference or a different native field",
                ));
            }
        } else if native_name(name) || native_name(storage) {
            return Err(AuthError::config(format!(
                "ApiKey additional field {name} cannot replace native field {storage}"
            )));
        }
        let column = storage_name(fields);
        if name != "name" && (name == column || storage == column) {
            return Err(AuthError::config(format!(
                "ApiKey field {name} conflicts with name storage column {column}"
            )));
        }
    }
    Ok(())
}

fn storage_name(fields: &UserConfig) -> &str {
    resolve_field_name(
        fields
            .fields()
            .get("name")
            .and_then(|field| field.field_name.as_deref()),
        "name",
    )
}

#[derive(Default)]
pub(crate) struct ApiKeyFieldPatch {
    pub name: Option<SchemaValue<Option<String>>>,
    pub additional_fields: FieldMap,
}

impl ApiKeyFieldPatch {
    pub(crate) fn apply(self, row: &mut ApiKey) {
        if let Some(name) = self.name {
            row.name = name;
        }
        row.additional_fields.extend(self.additional_fields);
    }
}

impl ModelFields {
    pub(crate) async fn api_key_fields_for_storage(
        &self,
        name: Option<SchemaValue<Option<String>>>,
        mut extras: FieldMap,
        create: bool,
        bind: impl Fn(&UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<ApiKeyFieldPatch> {
        let _ = extras.shift_remove("name");
        let core = name
            .into_iter()
            .map(|name| ("name".to_owned(), name.into_field_value()))
            .collect();
        let config = self.fields(EntityRole::ApiKey);
        let mut fields = config
            .organization_storage_fields_with_binding(core, extras, create, |_, field, value| {
                bind(field, value)
            })
            .await?;
        let name = optional_string(&mut fields, storage_name(config));
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
                    .map(SchemaValue::from_field)
                    .unwrap_or_default();
            }
            row.additional_fields = output;
        }
        Ok(rows)
    }
}
