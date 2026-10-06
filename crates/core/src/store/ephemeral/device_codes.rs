use super::rows::RowRef;
use super::*;
use crate::store::schema::EntityRole;
use crate::store::schema::resolve_field_name;
use crate::user_fields::project_adapter_value;

#[derive(Clone)]
pub(super) struct DeviceCodeConsumption {
    pub(super) row: DeviceCode,
    ownership_field: Option<String>,
}

impl DeviceCodeConsumption {
    pub(super) fn unchanged(&self, live: &DeviceCode, baseline: &DeviceCode) -> bool {
        same_bindings(live, baseline)
            && self.ownership_field.as_deref().is_none_or(|field| {
                // Compare against the baseline because prepare may change the transaction's field.
                if field == "scope" {
                    live.scope == baseline.scope
                } else {
                    live.additional_fields.get(field) == baseline.additional_fields.get(field)
                }
            })
    }
}

fn scalar_equals(actual: Option<&Value>, expected: &Value) -> bool {
    match (actual, expected) {
        (None | Some(Value::Null), Value::Null) => true,
        (Some(Value::Number(actual)), Value::Number(expected)) => {
            actual.as_f64() == expected.as_f64()
        }
        (Some(actual), expected) => actual == expected,
        _ => false,
    }
}

fn field_equals(row: &DeviceCode, field: &str, expected: &Value) -> bool {
    if field != "scope" {
        return scalar_equals(row.additional_fields.get(field), expected);
    }
    match (&row.scope, expected) {
        (crate::SchemaValue::Undefined | crate::SchemaValue::Typed(None), Value::Null) => true,
        (crate::SchemaValue::Typed(Some(actual)), Value::String(expected)) => actual == expected,
        (crate::SchemaValue::Dynamic(actual), expected) => scalar_equals(Some(actual), expected),
        _ => false,
    }
}

fn field_in(row: &DeviceCode, field: &str, values: &[Value]) -> bool {
    let contains = |actual: &Value| {
        values
            .iter()
            .any(|expected| scalar_equals(Some(actual), expected))
    };
    if field != "scope" {
        return row.additional_fields.get(field).is_some_and(contains);
    }
    match &row.scope {
        crate::SchemaValue::InvalidDate | crate::SchemaValue::Undefined => false,
        crate::SchemaValue::Typed(None) => values.iter().any(Value::is_null),
        crate::SchemaValue::Typed(Some(actual)) => values
            .iter()
            .any(|expected| expected.as_str() == Some(actual.as_str())),
        crate::SchemaValue::Dynamic(actual) => contains(actual),
    }
}

impl EphemeralStore {
    async fn find_device_code(
        &self,
        predicate: impl Fn(&DeviceCode) -> bool + Send,
    ) -> AuthResult<Option<DeviceCode>> {
        let selected = self
            .raw("deviceCode", "findOne", |state| {
                state
                    .device_codes
                    .first_ref(predicate)?
                    .map(|source| {
                        let snapshot = source.read(|row| Ok(row.clone()))?;
                        Ok((snapshot, source))
                    })
                    .transpose()
            })
            .await?;
        let Some((snapshot, source)) = selected else {
            return Ok(None);
        };
        self.project_device_code(snapshot, source).await.map(Some)
    }

    async fn project_device_code(
        &self,
        mut snapshot: DeviceCode,
        source: RowRef<DeviceCode>,
    ) -> AuthResult<DeviceCode> {
        let scope = snapshot.scope.json()?;
        let fields = self.model_fields.fields(EntityRole::DeviceCode);
        let mut output = IndexMap::new();
        for (name, field) in fields.fields() {
            let value = if name == "scope" {
                scope.clone()
            } else {
                source.read(|row| {
                    Ok(row
                        .additional_fields
                        .get(resolve_field_name(field.field_name.as_deref(), name))
                        .cloned())
                })?
            };
            let value = project_adapter_value(value, field, field.references_id(), true).await?;
            if !value.is_undefined() {
                let _ = output.insert(name.clone(), value);
            }
        }
        // Only declared application fields are live; authorization fields retain the selected snapshot.
        self.model_fields
            .assign_device_code_output(&mut snapshot, output)?;
        Ok(snapshot)
    }

    fn bind_device_code_fields(
        &self,
        values: &mut serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<()> {
        for (name, field) in self.model_fields.fields(EntityRole::DeviceCode).fields() {
            if let Some(value) =
                values.get_mut(resolve_field_name(field.field_name.as_deref(), name))
            {
                *value = self.memory_plugin_field_input(field, std::mem::take(value))?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl DeviceCodeStore for EphemeralStore {
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        let mut fields = self
            .model_fields
            .device_code_fields_for_storage(input.scope, input.additional_fields, true)
            .await?;
        self.bind_device_code_fields(&mut fields)?;
        let scope = crate::plugin_runtime::ModelFields::take_device_code_scope(&mut fields)?;
        let device_code = DeviceCode {
            additional_fields: fields,
            id: self
                .generated_id("deviceCode", None, self.lock()?.device_codes.len())?
                .map(crate::SchemaValue::Typed)
                .unwrap_or_default(),
            device_code: input.device_code,
            user_code: input.user_code,
            user_id: input.user_id,
            expires_at: input.expires_at,
            status: input.status,
            last_polled_at: input.last_polled_at,
            polling_interval: input.polling_interval,
            client_id: input
                .client_id
                .map(|value| crate::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
            scope: scope.map(Into::into).unwrap_or_default(),
        };
        let (snapshot, source) = self
            .raw("deviceCode", "create", |state| {
                let source = state.device_codes.push_ref(device_code.clone());
                Ok((device_code, source))
            })
            .await?;
        self.project_device_code(snapshot, source).await
    }

    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.find_device_code(|row| row.device_code == device_code)
            .await
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.find_device_code(|row| row.user_code == user_code)
            .await
    }

    async fn update_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let mut fields = self
            .model_fields
            .device_code_fields_for_storage(update.scope, update.additional_fields, false)
            .await?;
        self.bind_device_code_fields(&mut fields)?;
        let scope = crate::plugin_runtime::ModelFields::take_device_code_scope(&mut fields)?;
        let (snapshot, source) = self
            .raw("deviceCode", "update", |state| {
                let Some(source) = state.device_codes.first_ref(|row| &row.id == id)? else {
                    return Ok(None);
                };

                let snapshot = source.write(|device_code| {
                    device_code.additional_fields.extend(fields);
                    if let Some(scope) = scope {
                        device_code.scope = scope.into();
                    }
                    if let Some(status) = update.status {
                        device_code.status = status;
                    }
                    if let Some(user_id) = update.user_id {
                        device_code.user_id = user_id;
                    }
                    if let Some(last_polled_at) = update.last_polled_at {
                        device_code.last_polled_at = last_polled_at;
                    }

                    Ok(device_code.clone())
                })?;
                Ok(Some((snapshot, source)))
            })
            .await?
            .ok_or_else(|| AuthError::not_found("Device code not found"))?;
        self.project_device_code(snapshot, source).await
    }

    async fn update_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        let mut fields = self
            .model_fields
            .device_code_fields_for_storage(update.scope, update.additional_fields, false)
            .await?;
        self.bind_device_code_fields(&mut fields)?;
        let scope = crate::plugin_runtime::ModelFields::take_device_code_scope(&mut fields)?;
        let row = self
            .raw("deviceCode", "update", |state| {
                let Some(mut device_code) = state.device_codes.get_mut(id)? else {
                    return Ok(None);
                };

                if device_code.status != current_status {
                    return Ok(None);
                }

                device_code.additional_fields.extend(fields);
                if let Some(scope) = scope {
                    device_code.scope = scope.into();
                }
                if let Some(status) = update.status {
                    device_code.status = status;
                }
                if let Some(user_id) = update.user_id {
                    device_code.user_id = user_id;
                }
                if let Some(last_polled_at) = update.last_polled_at {
                    device_code.last_polled_at = last_polled_at;
                }

                Ok(Some(device_code.clone()))
            })
            .await?;
        // Successful boolean writes still await the adapter output policy.
        Ok(!self
            .model_fields
            .project_device_codes(row.into_iter().collect())
            .await?
            .is_empty())
    }

    async fn claim_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        user_id: &str,
    ) -> AuthResult<bool> {
        let mut fields = self
            .model_fields
            .device_code_fields_for_storage(Default::default(), Default::default(), false)
            .await?;
        self.bind_device_code_fields(&mut fields)?;
        let scope = crate::plugin_runtime::ModelFields::take_device_code_scope(&mut fields)?;
        let row = self
            .raw("deviceCode", "incrementOne", |state| {
                let Some(mut device_code) = state.device_codes.get_mut(id)? else {
                    return Ok(None);
                };

                if device_code.status != "pending" || device_code.user_id.is_some() {
                    return Ok(None);
                }

                device_code.additional_fields.extend(fields);
                if let Some(scope) = scope {
                    device_code.scope = scope.into();
                }
                device_code.user_id = Some(user_id.to_string());
                Ok(Some(device_code.clone()))
            })
            .await?;
        // Successful boolean writes still await the adapter output policy.
        Ok(!self
            .model_fields
            .project_device_codes(row.into_iter().collect())
            .await?
            .is_empty())
    }

    async fn consume_device_code(
        &self,
        expected: &DeviceCode,
        ownership: &crate::DeviceCodeOwnership,
    ) -> AuthResult<Option<DeviceCode>> {
        let ownership = match ownership {
            crate::DeviceCodeOwnership::ClientId(client_id) => {
                crate::DeviceCodeOwnership::ClientId(client_id.clone())
            }
            crate::DeviceCodeOwnership::FieldEquals { field, value } => {
                let (logical, config) = self
                    .model_fields
                    .device_code_ownership_field(field, value)?;
                let value = self.memory_field_query(
                    self.model_fields.fields(EntityRole::DeviceCode),
                    logical,
                    value.clone(),
                )?;
                crate::DeviceCodeOwnership::FieldEquals {
                    field: resolve_field_name(config.field_name.as_deref(), logical).into(),
                    value: crate::user_query::bind_filter(config, &value)?,
                }
            }
            crate::DeviceCodeOwnership::FieldIn { field, values }
            | crate::DeviceCodeOwnership::FieldNotIn { field, values } => {
                let (logical, config) = self
                    .model_fields
                    .device_code_ownership_set_field(field, values)?;
                let values = serde_json::from_value(crate::user_query::bind_filter(
                    config,
                    &Value::Array(values.clone()),
                )?)?;
                let field = resolve_field_name(config.field_name.as_deref(), logical).into();
                if matches!(ownership, crate::DeviceCodeOwnership::FieldIn { .. }) {
                    crate::DeviceCodeOwnership::FieldIn { field, values }
                } else {
                    crate::DeviceCodeOwnership::FieldNotIn { field, values }
                }
            }
        };
        let row = self
            .raw("deviceCode", "consumeOne", |state| {
                let row = state.device_codes.remove_first(|row| {
                    same_bindings(row, expected)
                        && row.user_id.is_some()
                        && row.status == "approved"
                        && match &ownership {
                            crate::DeviceCodeOwnership::ClientId(client_id) => matches!(
                                &row.client_id,
                                crate::SchemaValue::Typed(Some(actual)) if actual == client_id
                            ),
                            crate::DeviceCodeOwnership::FieldEquals { field, value } => {
                                field_equals(row, field, value)
                            }
                            crate::DeviceCodeOwnership::FieldIn { field, values } => {
                                field_in(row, field, values)
                            }
                            crate::DeviceCodeOwnership::FieldNotIn { field, values } => {
                                !field_in(row, field, values)
                            }
                        }
                })?;
                if let Some(row) = &row
                    && let Some(consumed) = &self.device_code_consumptions
                {
                    consumed
                        .lock()
                        .map_err(|_| {
                            AuthError::internal("Ephemeral device consumption write set poisoned")
                        })?
                        .push(DeviceCodeConsumption {
                            row: row.clone(),
                            ownership_field: match &ownership {
                                crate::DeviceCodeOwnership::ClientId(_) => None,
                                crate::DeviceCodeOwnership::FieldEquals { field, .. }
                                | crate::DeviceCodeOwnership::FieldIn { field, .. }
                                | crate::DeviceCodeOwnership::FieldNotIn { field, .. } => {
                                    Some(field.clone())
                                }
                            },
                        });
                }
                Ok(row)
            })
            .await?;
        Ok(self
            .model_fields
            .project_device_codes(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn delete_device_code(&self, id: &crate::SchemaValue<String>) -> AuthResult<()> {
        self.raw("deviceCode", "delete", |state| {
            let _ = state.device_codes.remove(id)?;
            Ok(())
        })
        .await
    }

    async fn delete_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        status: &str,
    ) -> AuthResult<bool> {
        self.raw("deviceCode", "delete", |state| {
            let should_delete = state
                .device_codes
                .get(id)?
                .is_some_and(|device_code| device_code.status == status);

            if should_delete {
                let _ = state.device_codes.remove(id)?;
            }

            Ok(should_delete)
        })
        .await
    }
}

#[async_trait]
impl DeviceCodeStore for super::transactions::EphemeralTransaction {
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        self.store.create_device_code(input).await
    }
    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.store.get_device_code_by_device_code(device_code).await
    }
    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.store.get_device_code_by_user_code(user_code).await
    }
    async fn update_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        self.store.update_device_code(id, update).await
    }
    async fn update_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        self.store
            .update_device_code_if_status(id, current_status, update)
            .await
    }
    async fn claim_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        user_id: &str,
    ) -> AuthResult<bool> {
        self.store.claim_device_code(id, user_id).await
    }
    async fn consume_device_code(
        &self,
        expected: &DeviceCode,
        ownership: &crate::DeviceCodeOwnership,
    ) -> AuthResult<Option<DeviceCode>> {
        self.store.consume_device_code(expected, ownership).await
    }
    async fn delete_device_code(&self, id: &crate::SchemaValue<String>) -> AuthResult<()> {
        self.store.delete_device_code(id).await
    }
    async fn delete_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        status: &str,
    ) -> AuthResult<bool> {
        self.store.delete_device_code_if_status(id, status).await
    }
}

pub(super) fn same_bindings(actual: &DeviceCode, expected: &DeviceCode) -> bool {
    actual.id == expected.id
        && actual.device_code == expected.device_code
        && actual.client_id == expected.client_id
        && actual.user_id == expected.user_id
        && actual.status == expected.status
}
