use super::*;

#[async_trait]
impl DeviceCodeStore for EphemeralStore {
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
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
            scope: input
                .scope
                .map(|value| crate::SchemaValue::Typed(Some(value)))
                .unwrap_or_default(),
        };
        self.raw("deviceCode", "create", |state| {
            state.device_codes.push(device_code.clone());
            Ok(device_code)
        })
        .await
    }

    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.raw("deviceCode", "findOne", |state| {
            Ok(state
                .device_codes
                .iter()
                .find(|value| value.device_code == device_code)
                .cloned())
        })
        .await
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.raw("deviceCode", "findOne", |state| {
            Ok(state
                .device_codes
                .iter()
                .find(|value| value.user_code == user_code)
                .cloned())
        })
        .await
    }

    async fn update_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        self.raw("deviceCode", "update", |state| {
            let Some(device_code) = state.device_codes.get_mut(id) else {
                return Ok(None);
            };

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
        .ok_or_else(|| AuthError::not_found("Device code not found"))
    }

    async fn update_device_code_if_status(
        &self,
        id: &crate::SchemaValue<String>,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        self.raw("deviceCode", "update", |state| {
            let Some(device_code) = state.device_codes.get_mut(id) else {
                return Ok(false);
            };

            if device_code.status != current_status {
                return Ok(false);
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

            Ok(true)
        })
        .await
    }

    async fn claim_device_code(
        &self,
        id: &crate::SchemaValue<String>,
        user_id: &str,
    ) -> AuthResult<bool> {
        self.raw("deviceCode", "incrementOne", |state| {
            let Some(device_code) = state.device_codes.get_mut(id) else {
                return Ok(false);
            };

            if device_code.status != "pending" || device_code.user_id.is_some() {
                return Ok(false);
            }

            device_code.user_id = Some(user_id.to_string());
            Ok(true)
        })
        .await
    }

    async fn delete_device_code(&self, id: &crate::SchemaValue<String>) -> AuthResult<()> {
        self.raw("deviceCode", "delete", |state| {
            let _ = state.device_codes.remove(id);
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
                .get(id)
                .is_some_and(|device_code| device_code.status == status);

            if should_delete {
                let _ = state.device_codes.remove(id);
            }

            Ok(should_delete)
        })
        .await
    }
}
