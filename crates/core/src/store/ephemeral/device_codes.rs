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
