use super::*;
use crate::id::IdGeneration;
use crate::user_fields::UserFieldConfig;
use crate::{DeviceCode, DeviceCodeOwnership, DeviceCodeWhere, WhereMode, WhereOperator};

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
        let storage = resolve_field_name(field.field_name.as_deref(), name);
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
    /// Bind one ownership condition without invoking application field callbacks.
    /// The returned condition uses its physical storage field name.
    /// The third tuple item retains the original operand for adapter-specific conversion.
    pub fn device_code_ownership_query(
        &self,
        ownership: &DeviceCodeOwnership,
        policy: &IdGeneration,
    ) -> AuthResult<(DeviceCodeWhere, &UserFieldConfig, Value)> {
        static CLIENT_ID: LazyLock<UserFieldConfig> = LazyLock::new(UserFieldConfig::default);
        let (mut query, logical, field) = match ownership {
            DeviceCodeOwnership::ClientId(client) => (
                DeviceCodeWhere::new("clientId", client.clone()),
                "clientId",
                &*CLIENT_ID,
            ),
            DeviceCodeOwnership::FieldEquals { field, value } => {
                let (logical, config) = self.device_code_ownership_field(field, value)?;
                (DeviceCodeWhere::new(field, value.clone()), logical, config)
            }
            DeviceCodeOwnership::FieldIn { field, values }
            | DeviceCodeOwnership::FieldNotIn { field, values } => {
                let (logical, config) = self.device_code_ownership_set_field(field, values)?;
                (
                    DeviceCodeWhere {
                        field: field.clone(),
                        operator: if matches!(ownership, DeviceCodeOwnership::FieldIn { .. }) {
                            WhereOperator::In
                        } else {
                            WhereOperator::NotIn
                        },
                        value: values.clone().into(),
                        mode: WhereMode::Sensitive,
                    },
                    logical,
                    config,
                )
            }
            DeviceCodeOwnership::Where(query) => {
                if query.operator == WhereOperator::In && !matches!(query.value, Value::Array(_)) {
                    return Err(AuthError::internal("Value must be an array"));
                }
                let (logical, field) = self.declared_device_code_ownership_field(&query.field)?;
                if field.references.is_some()
                    && !(field.references_id()
                        && matches!(
                            field.field_type,
                            UserFieldType::String | UserFieldType::Json | UserFieldType::Date
                        ))
                {
                    return Err(AuthError::config(
                        "DeviceCode Where reference fields require the String, Json, or Date type and an id target",
                    ));
                }
                (query.clone(), logical, field)
            }
        };
        let original = query.value.clone();
        if field.references_id() && matches!(policy, IdGeneration::Serial) {
            query.value = crate::id::serial_reference_query_value(query.value)?;
        }
        query.value = crate::user_query::bind_filter(field, &query.value)?;
        query.field = resolve_field_name(field.field_name.as_deref(), logical).to_owned();
        Ok((query, field, original))
    }

    fn declared_device_code_ownership_field(
        &self,
        name: &str,
    ) -> AuthResult<(&str, &UserFieldConfig)> {
        static SCOPE: LazyLock<UserFieldConfig> = LazyLock::new(|| UserFieldConfig {
            required: Some(false),
            ..Default::default()
        });
        crate::user_query::declared_field(name, self.fields(EntityRole::DeviceCode))
            .or_else(|| (name == "scope").then(|| ("scope", &*SCOPE)))
            .ok_or_else(|| {
                AuthError::config(format!(
                    "DeviceCode ownership field {name} is not registered"
                ))
            })
    }

    /// Resolve and validate the supported scalar DeviceCode ownership query without running field callbacks.
    pub fn device_code_ownership_field(
        &self,
        name: &str,
        value: &Value,
    ) -> AuthResult<(&str, &UserFieldConfig)> {
        let (logical, field) = self.declared_device_code_ownership_field(name)?;
        validate_reference(field)?;
        if !matches!(
            field.field_type,
            UserFieldType::String | UserFieldType::Number | UserFieldType::Boolean
        ) {
            return Err(AuthError::config(
                "DeviceCode FieldEquals supports only declared string, number, and boolean fields",
            ));
        }
        if !matches!(
            value,
            Value::Null
                | Value::Bool(_)
                | Value::String(_)
                | Value::Utf16String(_)
                | Value::Number(_)
        ) {
            return Err(AuthError::config(
                "DeviceCode FieldEquals requires a scalar null, string, number, or boolean value",
            ));
        }
        Ok((logical, field))
    }

    /// Validate DeviceCode ownership candidates without invoking field input or output callbacks.
    pub fn device_code_ownership_set_field(
        &self,
        name: &str,
        values: &[Value],
    ) -> AuthResult<(&str, &UserFieldConfig)> {
        let (logical, field) = self.declared_device_code_ownership_field(name)?;
        validate_reference(field)?;
        if !matches!(
            field.field_type,
            UserFieldType::String | UserFieldType::Number
        ) {
            return Err(AuthError::config(
                "DeviceCode field sets support only declared string and number fields",
            ));
        }
        if values.iter().any(|value| {
            !matches!(
                value,
                Value::Null | Value::String(_) | Value::Utf16String(_) | Value::Number(_)
            )
        }) {
            return Err(AuthError::config(
                "DeviceCode field sets require scalar null, string, or number candidates",
            ));
        }
        Ok((logical, field))
    }

    /// Prepare scope and declared application fields without changing credential or owner bindings.
    pub async fn device_code_fields_for_storage(
        &self,
        scope: SchemaValue<Option<String>>,
        additional_fields: FieldMap,
        create: bool,
    ) -> AuthResult<FieldMap> {
        self.device_code_fields_with_binding(scope, additional_fields, create, |_, _, value| {
            Ok(value)
        })
        .await
    }

    /// Bind scope and application fields before omitting callback Undefined values.
    #[doc(hidden)]
    pub async fn device_code_fields_with_binding(
        &self,
        scope: SchemaValue<Option<String>>,
        mut additional_fields: FieldMap,
        create: bool,
        bind: impl Fn(&str, &UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<FieldMap> {
        // The typed scope owns omission too; application fields cannot supply an omitted native value.
        let _ = additional_fields.shift_remove("scope");
        let core = (!scope.is_undefined())
            .then(|| scope.into_field_value())
            .into_iter()
            .map(|value| ("scope".into(), value))
            .collect();
        self.fields(EntityRole::DeviceCode)
            .organization_storage_fields_with_binding(core, additional_fields, create, bind)
            .await
    }

    pub(crate) fn take_device_code_scope(
        fields: &mut FieldMap,
    ) -> Option<SchemaValue<Option<String>>> {
        optional_string(fields, "scope")
    }

    /// Project stored memory fields while retaining the original credential and authorization state.
    pub async fn project_device_codes(
        &self,
        mut rows: Vec<DeviceCode>,
    ) -> AuthResult<Vec<DeviceCode>> {
        let records = rows
            .iter()
            .map(|row| {
                let mut storage = row.additional_fields.clone();
                if !row.scope.is_undefined() {
                    let _ = storage.insert("scope".into(), row.scope.field_value());
                }
                AdapterRecord::new(FieldMap::new(), storage)
            })
            .collect();
        let output = self
            .fields(EntityRole::DeviceCode)
            .project_memory_adapter_records(records)
            .await?;
        for (row, output) in rows.iter_mut().zip(output) {
            self.assign_device_code_output(row, output);
        }
        Ok(rows)
    }

    /// Project extracted Device fields without replacing the raw record's typed bindings.
    pub async fn project_device_code_records(
        &self,
        mut rows: Vec<DeviceCode>,
        records: Vec<AdapterRecord>,
        capabilities: crate::user_fields::FieldOutputCapabilities,
        supports_native_dates: bool,
    ) -> AuthResult<Vec<DeviceCode>> {
        let fields = self.fields(EntityRole::DeviceCode);
        let output = fields
            .project_adapter_records_with_capabilities(records, capabilities, supports_native_dates)
            .await?;
        for (row, output) in rows.iter_mut().zip(output) {
            self.assign_device_code_output(row, output);
        }
        Ok(rows)
    }

    pub(crate) fn assign_device_code_output(&self, row: &mut DeviceCode, mut output: FieldMap) {
        if self
            .fields(EntityRole::DeviceCode)
            .fields()
            .contains_key("scope")
        {
            row.scope = output
                .shift_remove("scope")
                .map(SchemaValue::from_field)
                .unwrap_or_default();
        }
        row.additional_fields = output;
    }
}

fn validate_reference(field: &UserFieldConfig) -> AuthResult<()> {
    if field.references.is_some()
        && !(field.references_id() && matches!(field.field_type, UserFieldType::String))
    {
        return Err(AuthError::config(
            "DeviceCode ownership reference fields require the String type and an id target",
        ));
    }
    Ok(())
}
