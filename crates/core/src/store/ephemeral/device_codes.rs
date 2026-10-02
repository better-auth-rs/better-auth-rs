use super::*;

#[async_trait]
impl DeviceCodeStore for EphemeralStore {
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        let scope = self
            .model_fields
            .device_code_scope_for_storage(input.scope, true)
            .await?;
        let device_code = DeviceCode {
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
        let row = self
            .raw("deviceCode", "create", |state| {
                state.device_codes.push(device_code.clone());
                Ok(device_code)
            })
            .await?;
        Ok(self
            .model_fields
            .project_device_codes(vec![row])
            .await?
            .remove(0))
    }

    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        let row = self
            .raw("deviceCode", "findOne", |state| {
                Ok(state
                    .device_codes
                    .snapshot()?
                    .iter()
                    .find(|value| value.device_code == device_code)
                    .cloned())
            })
            .await?;
        Ok(self
            .model_fields
            .project_device_codes(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        let row = self
            .raw("deviceCode", "findOne", |state| {
                Ok(state
                    .device_codes
                    .snapshot()?
                    .iter()
                    .find(|value| value.user_code == user_code)
                    .cloned())
            })
            .await?;
        Ok(self
            .model_fields
            .project_device_codes(row.into_iter().collect())
            .await?
            .pop())
    }

    async fn update_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let scope = self
            .model_fields
            .device_code_scope_for_storage(update.scope, false)
            .await?;
        let row = self
            .raw("deviceCode", "update", |state| {
                let Some(mut device_code) = state.device_codes.get_mut(id)? else {
                    return Ok(None);
                };

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
            .await?
            .ok_or_else(|| AuthError::not_found("Device code not found"))?;
        Ok(self
            .model_fields
            .project_device_codes(vec![row])
            .await?
            .remove(0))
    }

    async fn update_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        let scope = self
            .model_fields
            .device_code_scope_for_storage(update.scope, false)
            .await?;
        let row = self
            .raw("deviceCode", "update", |state| {
                let Some(mut device_code) = state.device_codes.get_mut(id)? else {
                    return Ok(None);
                };

                if device_code.status != current_status {
                    return Ok(None);
                }

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
        let scope = self
            .model_fields
            .device_code_scope_for_storage(Default::default(), false)
            .await?;
        let row = self
            .raw("deviceCode", "incrementOne", |state| {
                let Some(mut device_code) = state.device_codes.get_mut(id)? else {
                    return Ok(None);
                };

                if device_code.status != "pending" || device_code.user_id.is_some() {
                    return Ok(None);
                }

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
        let crate::DeviceCodeOwnership::ClientId(client_id) = ownership;
        let client_id = crate::SchemaValue::Typed(Some(client_id.clone()));
        let row = self
            .raw("deviceCode", "consumeOne", |state| {
                let row = state.device_codes.remove_first(|row| {
                    same_bindings(row, expected)
                        && row.user_id.is_some()
                        && row.status == "approved"
                        && row.client_id == client_id
                })?;
                if let Some(row) = &row
                    && let Some(consumed) = &self.device_code_consumptions
                {
                    consumed
                        .lock()
                        .map_err(|_| {
                            AuthError::internal("Ephemeral device consumption write set poisoned")
                        })?
                        .push(row.clone());
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
