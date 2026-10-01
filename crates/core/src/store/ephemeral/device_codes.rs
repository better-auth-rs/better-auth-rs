use super::*;

#[async_trait]
impl DeviceCodeStore for EphemeralStore {
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        let device_code = DeviceCode {
            id: uuid::Uuid::new_v4().to_string(),
            device_code: input.device_code,
            user_code: input.user_code,
            user_id: input.user_id,
            expires_at: input.expires_at,
            status: input.status,
            last_polled_at: input.last_polled_at,
            polling_interval: input.polling_interval,
            client_id: input.client_id,
            scope: input.scope,
        };
        let _ = self
            .lock()?
            .device_codes
            .insert(device_code.id.clone(), device_code.clone());
        Ok(device_code)
    }

    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        Ok(self
            .lock()?
            .device_codes
            .values()
            .find(|value| value.device_code == device_code)
            .cloned())
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        Ok(self
            .lock()?
            .device_codes
            .values()
            .find(|value| value.user_code == user_code)
            .cloned())
    }

    async fn update_device_code(
        &self,
        id: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let mut state = self.lock()?;
        let device_code = state
            .device_codes
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Device code not found"))?;

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
    }

    async fn update_device_code_if_status(
        &self,
        id: &str,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        let mut state = self.lock()?;
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
    }

    async fn claim_device_code(&self, id: &str, user_id: &str) -> AuthResult<bool> {
        let mut state = self.lock()?;
        let Some(device_code) = state.device_codes.get_mut(id) else {
            return Ok(false);
        };

        if device_code.status != "pending" || device_code.user_id.is_some() {
            return Ok(false);
        }

        device_code.user_id = Some(user_id.to_string());
        Ok(true)
    }

    async fn delete_device_code(&self, id: &str) -> AuthResult<()> {
        let _ = self.lock()?.device_codes.shift_remove(id);
        Ok(())
    }

    async fn delete_device_code_if_status(&self, id: &str, status: &str) -> AuthResult<bool> {
        let mut state = self.lock()?;
        let should_delete = state
            .device_codes
            .get(id)
            .is_some_and(|device_code| device_code.status == status);

        if should_delete {
            let _ = state.device_codes.shift_remove(id);
        }

        Ok(should_delete)
    }
}
