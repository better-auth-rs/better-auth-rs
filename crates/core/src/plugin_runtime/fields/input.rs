use crate::{AuthResult, FieldMap, FieldValue, SchemaField};

fn put<T: SchemaField>(fields: &mut FieldMap, name: &str, value: T) {
    let value = value.into_field();
    if !value.is_undefined() {
        let _ = fields.insert(name.to_owned(), value);
    }
}

fn metadata(fields: &mut FieldMap, text: Option<String>) -> AuthResult<()> {
    if let Some(text) = text {
        let _ = fields.insert("metadata".into(), FieldValue::parse_json(&text)?);
    }
    Ok(())
}

impl crate::CreateApiKey {
    /// Convert ordinary Rust input to the complete logical adapter record.
    #[doc(hidden)]
    pub fn into_adapter_fields(self) -> AuthResult<FieldMap> {
        let mut fields = self.additional_fields;
        put(&mut fields, "referenceId", self.reference_id);
        put(&mut fields, "configId", self.config_id);
        put(&mut fields, "name", self.name);
        put(&mut fields, "prefix", self.prefix);
        put(&mut fields, "key", self.key_hash);
        put(&mut fields, "start", self.start);
        put(&mut fields, "expiresAt", self.expires_at);
        put(&mut fields, "remaining", self.remaining);
        put(&mut fields, "enabled", self.enabled);
        put(&mut fields, "rateLimitEnabled", self.rate_limit_enabled);
        put(
            &mut fields,
            "rateLimitTimeWindow",
            self.rate_limit_time_window,
        );
        put(&mut fields, "rateLimitMax", self.rate_limit_max);
        put(&mut fields, "requestCount", 0.0);
        put(&mut fields, "refillInterval", self.refill_interval);
        put(&mut fields, "refillAmount", self.refill_amount);
        put(&mut fields, "permissions", self.permissions);
        metadata(&mut fields, self.metadata)?;
        Ok(fields)
    }
}

impl crate::UpdateApiKey {
    /// Convert supplied values to a logical patch; omitted fields remain absent.
    #[doc(hidden)]
    pub fn into_adapter_fields(self) -> AuthResult<FieldMap> {
        let mut fields = self.additional_fields;
        macro_rules! supplied {
            ($($member:ident => $name:literal),* $(,)?) => {$(
                if let Some(value) = self.$member { put(&mut fields, $name, value); }
            )*};
        }
        supplied!(name => "name", enabled => "enabled", remaining => "remaining",
            rate_limit_enabled => "rateLimitEnabled", rate_limit_time_window => "rateLimitTimeWindow",
            rate_limit_max => "rateLimitMax", refill_interval => "refillInterval",
            refill_amount => "refillAmount", permissions => "permissions", expires_at => "expiresAt",
            last_request => "lastRequest", request_count => "requestCount", last_refill_at => "lastRefillAt");
        metadata(&mut fields, self.metadata)?;
        Ok(fields)
    }
}

impl crate::CreatePasskey {
    /// Convert native fields and extension fields through the same adapter input boundary.
    #[doc(hidden)]
    pub fn into_adapter_fields(self) -> AuthResult<FieldMap> {
        let mut fields = self.additional_fields;
        put(&mut fields, "userId", self.user_id);
        put(&mut fields, "name", self.name);
        put(&mut fields, "credentialID", self.credential_id);
        put(&mut fields, "publicKey", self.public_key);
        put(&mut fields, "counter", self.counter);
        put(&mut fields, "deviceType", self.device_type);
        put(&mut fields, "backedUp", self.backed_up);
        put(&mut fields, "transports", self.transports);
        put(&mut fields, "aaguid", self.aaguid);
        if let crate::PasskeyCredentialState::Legacy(credential) = self.credential {
            put(&mut fields, "credential", credential);
        }
        Ok(fields)
    }
}

impl crate::UpdatePasskey {
    /// Convert supplied native and extension fields to one logical adapter patch.
    #[doc(hidden)]
    pub fn into_adapter_fields(self) -> AuthResult<FieldMap> {
        let mut fields = self.additional_fields;
        put(&mut fields, "name", self.name);
        put(&mut fields, "aaguid", self.aaguid);
        if let Some(counter) = self.counter {
            put(&mut fields, "counter", counter);
        }
        Ok(fields)
    }
}

impl crate::CreateDeviceCode {
    /// Convert ordinary Rust input to the complete logical adapter record.
    #[doc(hidden)]
    pub fn into_adapter_fields(self) -> AuthResult<FieldMap> {
        let mut fields = self.additional_fields;
        put(&mut fields, "deviceCode", self.device_code);
        put(&mut fields, "userCode", self.user_code);
        put(&mut fields, "userId", self.user_id);
        put(&mut fields, "expiresAt", self.expires_at);
        put(&mut fields, "status", self.status);
        put(&mut fields, "lastPolledAt", self.last_polled_at);
        put(&mut fields, "pollingInterval", self.polling_interval);
        if let Some(client_id) = self.client_id {
            put(&mut fields, "clientId", client_id);
        } else {
            let _ = fields.shift_remove("clientId");
        }
        let _ = fields.shift_remove("scope");
        put(&mut fields, "scope", self.scope);
        Ok(fields)
    }
}

impl crate::UpdateDeviceCode {
    /// Convert supplied values to a logical patch; omitted fields remain absent.
    #[doc(hidden)]
    pub fn into_adapter_fields(self) -> AuthResult<FieldMap> {
        let mut fields = self.additional_fields;
        let _ = fields.shift_remove("scope");
        put(&mut fields, "scope", self.scope);
        if let Some(status) = self.status {
            put(&mut fields, "status", status);
        }
        if let Some(user_id) = self.user_id {
            put(&mut fields, "userId", user_id);
        }
        if let Some(last_polled_at) = self.last_polled_at {
            put(&mut fields, "lastPolledAt", last_polled_at);
        }
        Ok(fields)
    }
}

impl crate::CreateTwoFactor {
    /// Convert ordinary Rust input without supplying adapter-owned defaults.
    #[doc(hidden)]
    pub fn into_adapter_fields(self) -> AuthResult<FieldMap> {
        let mut fields = self.additional_fields;
        put(&mut fields, "secret", self.secret);
        put(&mut fields, "backupCodes", self.backup_codes);
        put(&mut fields, "userId", self.user_id);
        put(&mut fields, "verified", self.verified);
        Ok(fields)
    }
}

impl crate::UpdateTwoFactor {
    /// Convert supplied native and extension values into one logical patch.
    #[doc(hidden)]
    pub fn into_adapter_fields(self) -> AuthResult<FieldMap> {
        let mut fields = self.additional_fields;
        if let Some(value) = self.secret {
            put(&mut fields, "secret", value);
        }
        if let Some(value) = self.backup_codes {
            put(&mut fields, "backupCodes", value);
        }
        if let Some(value) = self.verified {
            put(&mut fields, "verified", value);
        }
        Ok(fields)
    }
}
