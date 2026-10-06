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
    pub fn device_code_ownership_query(
        &self,
        ownership: &DeviceCodeOwnership,
        policy: &IdGeneration,
    ) -> AuthResult<(DeviceCodeWhere, &UserFieldConfig)> {
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
                        value: Value::Array(values.clone()),
                        mode: WhereMode::Sensitive,
                    },
                    logical,
                    config,
                )
            }
            DeviceCodeOwnership::Where(query) => {
                let (logical, field) = self.declared_device_code_ownership_field(&query.field)?;
                validate_query(field, query, policy)?;
                (query.clone(), logical, field)
            }
        };
        validate_finite_binding(field, &query.value)?;
        if field.references_id() && matches!(policy, IdGeneration::Serial) {
            query.value = crate::id::serial_reference_query_value(query.value)?;
        }
        query.value = crate::user_query::bind_filter(field, &query.value)?;
        query.field = resolve_field_name(field.field_name.as_deref(), logical).to_owned();
        Ok((query, field))
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
        if field.references.is_some()
            || !matches!(
                field.field_type,
                UserFieldType::String | UserFieldType::Number | UserFieldType::Boolean
            )
        {
            return Err(AuthError::config(
                "DeviceCode FieldEquals supports only declared string, number, and boolean fields without references",
            ));
        }
        if value.is_array() || value.is_object() {
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
        if field.references.is_some()
            || !matches!(
                field.field_type,
                UserFieldType::String | UserFieldType::Number
            )
        {
            return Err(AuthError::config(
                "DeviceCode field sets support only declared string and number fields without references",
            ));
        }
        if values
            .iter()
            .any(|value| !matches!(value, Value::Null | Value::String(_) | Value::Number(_)))
        {
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
    pub async fn project_device_codes(
        &self,
        mut rows: Vec<DeviceCode>,
    ) -> AuthResult<Vec<DeviceCode>> {
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
        let output = self
            .fields(EntityRole::DeviceCode)
            .project_memory_adapter_records(records)
            .await?;
        for (row, output) in rows.iter_mut().zip(output) {
            self.assign_device_code_output(row, output)?;
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
            self.assign_device_code_output(row, output)?;
        }
        Ok(rows)
    }

    pub(crate) fn assign_device_code_output(
        &self,
        row: &mut DeviceCode,
        mut output: indexmap::IndexMap<String, SchemaValue<Value>>,
    ) -> AuthResult<()> {
        if self
            .fields(EntityRole::DeviceCode)
            .fields()
            .contains_key("scope")
        {
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
        Ok(())
    }
}

fn validate_query(
    field: &UserFieldConfig,
    query: &DeviceCodeWhere,
    policy: &IdGeneration,
) -> AuthResult<()> {
    if field.references.is_some()
        && !(matches!(policy, IdGeneration::Serial)
            && field.references_id()
            && matches!(field.field_type, UserFieldType::String))
    {
        return Err(AuthError::config(
            "DeviceCode Where reference fields require the String type, an id target, and Serial ID generation",
        ));
    }
    if !matches!(
        field.field_type,
        UserFieldType::String
            | UserFieldType::Number
            | UserFieldType::Boolean
            | UserFieldType::StringArray
            | UserFieldType::NumberArray
            | UserFieldType::Json
            | UserFieldType::Enum(_)
    ) {
        return Err(AuthError::config(
            "DeviceCode Where supports scope and declared scalar, array, or JSON fields; Date fields require a query representation that preserves adapter semantics",
        ));
    }
    let scalar = |value: &Value| !value.is_array() && !value.is_object();
    if matches!(query.operator, WhereOperator::In | WhereOperator::NotIn) {
        if !query
            .value
            .as_array()
            .is_some_and(|values| values.iter().all(scalar))
        {
            return Err(AuthError::config(
                "DeviceCode In and NotIn require flat arrays of finite scalar or null values",
            ));
        }
    } else if !scalar(&query.value)
        && !(matches!(field.field_type, UserFieldType::Json)
            && matches!(query.operator, WhereOperator::Eq | WhereOperator::Ne))
    {
        return Err(AuthError::config(
            "DeviceCode Where requires a finite scalar or null operand outside JSON equality and membership; native array and object identity cannot be represented",
        ));
    }
    Ok(())
}

fn validate_finite_binding(field: &UserFieldConfig, value: &Value) -> AuthResult<()> {
    if !field.references_id() && !matches!(field.field_type, UserFieldType::Number) {
        return Ok(());
    }
    let parsed = |value: &Value| {
        value
            .as_str()
            .and_then(crate::organization_fields::numeric_filter)
    };
    let nonfinite = if field.references_id() {
        value
            .as_array()
            .map_or(std::slice::from_ref(value), Vec::as_slice)
            .iter()
            .try_fold(false, |nonfinite, value| {
                crate::query::number(value).map(|number| nonfinite || !number.is_finite())
            })?
    } else {
        match value {
            Value::String(_) => parsed(value).is_some_and(|number| !number.is_finite()),
            Value::Array(values) => values
                .iter()
                .map(parsed)
                .collect::<Option<Vec<_>>>()
                .is_some_and(|values| values.iter().any(|number| !number.is_finite())),
            _ => false,
        }
    };
    if nonfinite {
        return Err(AuthError::config(
            "DeviceCode Where cannot represent a non-finite number after query conversion",
        ));
    }
    Ok(())
}
