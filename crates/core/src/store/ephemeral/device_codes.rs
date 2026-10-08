use super::rows::{RowRef, Rows};
use super::*;
use crate::store::schema::{EntityRole, resolve_field_name};

#[path = "device_query.rs"]
mod query;

#[derive(Clone)]
struct DeviceCodeOrigin {
    isolated: RowRef<FieldMap>,
    live: RowRef<FieldMap>,
    before: FieldMap,
}

#[derive(Default)]
pub(super) struct DeviceCodeTransaction {
    origins: Vec<DeviceCodeOrigin>,
    pub(super) consumed: Vec<DeviceCodeConsumption>,
}

impl DeviceCodeTransaction {
    pub(super) fn new(live: &Rows<FieldMap>, isolated: &Rows<FieldMap>) -> AuthResult<Self> {
        let live = live.select_refs(|_| true)?;
        let isolated = isolated.select_refs(|_| true)?;
        let origins = live
            .into_iter()
            .zip(isolated)
            .map(|(live, isolated)| {
                let before = live.read(|row| Ok(row.clone()))?;
                Ok(DeviceCodeOrigin {
                    isolated,
                    live,
                    before,
                })
            })
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(Self {
            origins,
            consumed: Vec::new(),
        })
    }
}

#[derive(Clone)]
pub(super) struct DeviceCodeConsumption {
    origin: Option<DeviceCodeOrigin>,
    binding_fields: [String; 5],
    ownership_field: Option<String>,
}

impl DeviceCodeConsumption {
    pub(super) fn unchanged(&self, live: &Rows<FieldMap>) -> AuthResult<bool> {
        let Some(origin) = &self.origin else {
            // Rows created inside this transaction have no pre-transaction owner.
            return Ok(true);
        };
        if !live.contains_ref(&origin.live) {
            return Ok(false);
        }
        origin.live.read(|row| {
            Ok(self
                .binding_fields
                .iter()
                .chain(self.ownership_field.iter())
                .all(|name| match (row.get(name), origin.before.get(name)) {
                    (Some(actual), Some(before)) => actual.same_value_zero(before),
                    (None, None) => true,
                    _ => false,
                }))
        })
    }
}

fn value<'a>(row: &'a FieldMap, name: &str) -> &'a Value {
    row.get(name).unwrap_or(&Value::Undefined)
}

impl EphemeralStore {
    fn device_column(&self, name: &str) -> String {
        let fields = self
            .model_fields
            .plugin_fields(EntityRole::DeviceCode)
            .adapter_fields(&[]);
        fields
            .fields()
            .get(name)
            .map_or(name, |field| {
                resolve_field_name(field.field_name.as_deref(), name)
            })
            .to_owned()
    }

    async fn find_device_code(
        &self,
        field: &str,
        operand: Value,
    ) -> AuthResult<Option<DeviceCode>> {
        let operand = self.plugin_query_value(EntityRole::DeviceCode, field, operand)?;
        let column = self.device_column(field);
        let selected = self
            .raw("deviceCode", "findOne", |state| {
                state.device_codes.first_ref(|row| {
                    crate::query::field_matches_equality(value(row, &column), &operand)
                })
            })
            .await?;
        Ok(self
            .project_device_code_refs(selected.into_iter().collect())
            .await?
            .pop())
    }

    async fn project_device_code_refs(
        &self,
        sources: Vec<RowRef<FieldMap>>,
    ) -> AuthResult<Vec<DeviceCode>> {
        let bindings = sources
            .iter()
            .map(|source| {
                source.read(|row| Ok(self.model_fields.device_code_storage_bindings(row)))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let projected = self
            .project_plugin_refs(EntityRole::DeviceCode, sources)
            .await?;
        Ok(projected
            .into_iter()
            .zip(bindings)
            .map(|(fields, bindings)| DeviceCode::from(fields).with_storage_bindings(bindings))
            .collect())
    }

    async fn project_device_code_snapshots(
        &self,
        rows: Vec<FieldMap>,
    ) -> AuthResult<Vec<DeviceCode>> {
        let mut sources = Rows::default();
        let refs = rows.into_iter().map(|row| sources.push_ref(row)).collect();
        self.project_device_code_refs(refs).await
    }

    async fn update_device_code_guarded(
        &self,
        id: &crate::SchemaValue<String>,
        status: &str,
        unclaimed: bool,
        input: FieldMap,
    ) -> AuthResult<bool> {
        let id = self.plugin_query_value(EntityRole::DeviceCode, "id", id.field_value())?;
        let status = self.plugin_query_value(EntityRole::DeviceCode, "status", status.into())?;
        let owner = if unclaimed {
            Some(self.plugin_query_value(EntityRole::DeviceCode, "userId", Value::Null)?)
        } else {
            None
        };
        let patch = self
            .prepare_plugin_fields(EntityRole::DeviceCode, input, false)
            .await?;
        let status_column = self.device_column("status");
        let owner_column = self.device_column("userId");
        let selected = self
            .raw(
                "deviceCode",
                if unclaimed { "incrementOne" } else { "update" },
                |state| {
                    let selected = state.device_codes.first_ref(|row| {
                        crate::query::field_matches_equality(value(row, "id"), &id)
                            && crate::query::field_matches_equality(
                                value(row, &status_column),
                                &status,
                            )
                            && owner.as_ref().is_none_or(|owner| {
                                crate::query::field_matches_equality(
                                    value(row, &owner_column),
                                    owner,
                                )
                            })
                    })?;
                    if let Some(source) = &selected {
                        source.write(|row| {
                            row.extend(patch);
                            Ok(())
                        })?;
                    }
                    Ok(selected)
                },
            )
            .await?;
        // Output callbacks run after a successful write, including boolean-returning writes.
        Ok(!self
            .project_device_code_refs(selected.into_iter().collect())
            .await?
            .is_empty())
    }
}

#[async_trait]
impl DeviceCodeStore for EphemeralStore {
    async fn create_device_code_record(&self, fields: FieldMap) -> AuthResult<FieldMap> {
        self.create_plugin_record(EntityRole::DeviceCode, fields, FieldMap::new())
            .await
    }

    async fn get_device_code_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        self.get_plugin_record(EntityRole::DeviceCode, id).await
    }

    async fn update_device_code_record(
        &self,
        id: &crate::SchemaValue<String>,
        fields: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.update_plugin_record(EntityRole::DeviceCode, id, fields, FieldMap::new())
            .await
    }

    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        let source = self
            .create_plugin_ref(
                EntityRole::DeviceCode,
                input.into_adapter_fields()?,
                FieldMap::new(),
            )
            .await?;
        self.project_device_code_refs(vec![source])
            .await?
            .pop()
            .ok_or_else(|| AuthError::internal("Created device code was not projected"))
    }

    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.find_device_code("deviceCode", device_code.into())
            .await
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.find_device_code("userCode", user_code.into()).await
    }

    async fn update_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let source = self
            .update_plugin_ref(
                EntityRole::DeviceCode,
                id,
                update.into_adapter_fields()?,
                FieldMap::new(),
            )
            .await?
            .ok_or_else(|| AuthError::not_found("Device code not found"))?;
        self.project_device_code_refs(vec![source])
            .await?
            .pop()
            .ok_or_else(|| AuthError::internal("Updated device code was not projected"))
    }

    async fn update_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        self.update_device_code_guarded(id, current_status, false, update.into_adapter_fields()?)
            .await
    }

    async fn claim_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        user_id: &crate::SchemaValue<String>,
    ) -> AuthResult<bool> {
        self.update_device_code_guarded(
            id,
            "pending",
            true,
            [("userId".into(), user_id.field_value())].into(),
        )
        .await
    }

    async fn consume_device_code(
        &self,
        expected: &DeviceCode,
        ownership: &crate::DeviceCodeOwnership,
    ) -> AuthResult<Option<DeviceCode>> {
        let (mut query, field, original) = self
            .model_fields
            .device_code_ownership_query(ownership, self.config.advanced.database.generate_id())?;
        if matches!(field.field_type, crate::user_fields::UserFieldType::Json) {
            query.value = super::field_bindings::memory_json_query_value(query.value, &original)?;
        }
        let approved =
            self.plugin_query_value(EntityRole::DeviceCode, "status", "approved".into())?;
        let (bindings, unchanged) = expected.consumption_bindings()?;
        let names = ["id", "deviceCode", "clientId", "userId", "status"];
        let columns = names.map(|name| self.device_column(name));
        let row = self
            .raw("deviceCode", "consumeOne", |state| {
                let mut selected = None;
                // Evaluate ownership for every row before deletion; another row can still fail the operation.
                for source in state.device_codes.select_refs(|_| true)? {
                    let matches = source.read(|row| {
                        let owns = query::matches(row, &query)?;
                        Ok(unchanged
                            && owns
                            && names.iter().zip(&columns).all(|(name, column)| {
                                value(row, column).strict_equals(value(bindings, name))
                            })
                            && !value(row, &columns[3]).is_null()
                            && !value(row, &columns[3]).is_undefined()
                            && crate::query::field_matches_equality(
                                value(row, &columns[4]),
                                &approved,
                            ))
                    })?;
                    if selected.is_none() && matches {
                        selected = Some(source);
                    }
                }
                let Some(selected) = selected else {
                    return Ok(None);
                };
                let row = state.device_codes.remove_ref(&selected)?;
                if row.is_some()
                    && let Some(transaction) = &self.device_code_transaction
                {
                    let mut transaction = transaction.lock().map_err(|_| {
                        AuthError::internal("Ephemeral device consumption write set poisoned")
                    })?;
                    let origin = transaction
                        .origins
                        .iter()
                        .find(|origin| origin.isolated.same_row(&selected))
                        .cloned();
                    transaction.consumed.push(DeviceCodeConsumption {
                        origin,
                        binding_fields: columns,
                        ownership_field: (!matches!(
                            ownership,
                            crate::DeviceCodeOwnership::ClientId(_)
                        ))
                        .then(|| query.field.clone()),
                    });
                }
                Ok(row)
            })
            .await?;
        Ok(self
            .project_device_code_snapshots(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn delete_device_code(&self, id: &crate::SchemaValue<String>) -> AuthResult<()> {
        let id = self.plugin_query_value(EntityRole::DeviceCode, "id", id.field_value())?;
        self.raw("deviceCode", "delete", |state| {
            let _ = state
                .device_codes
                .remove_first(|row| crate::query::field_matches_equality(value(row, "id"), &id))?;
            Ok(())
        })
        .await
    }

    async fn delete_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        status: &str,
    ) -> AuthResult<bool> {
        let id = self.plugin_query_value(EntityRole::DeviceCode, "id", id.field_value())?;
        let status = self.plugin_query_value(EntityRole::DeviceCode, "status", status.into())?;
        let column = self.device_column("status");
        self.raw("deviceCode", "delete", |state| {
            Ok(state
                .device_codes
                .remove_first(|row| {
                    crate::query::field_matches_equality(value(row, "id"), &id)
                        && crate::query::field_matches_equality(value(row, &column), &status)
                })?
                .is_some())
        })
        .await
    }
}

#[async_trait]
impl DeviceCodeStore for super::transactions::EphemeralTransaction {
    async fn create_device_code_record(&self, fields: FieldMap) -> AuthResult<FieldMap> {
        self.store.create_device_code_record(fields).await
    }
    async fn get_device_code_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        self.store.get_device_code_record(id).await
    }
    async fn update_device_code_record(
        &self,
        id: &crate::SchemaValue<String>,
        fields: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.store.update_device_code_record(id, fields).await
    }

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
        user_id: &crate::SchemaValue<String>,
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
