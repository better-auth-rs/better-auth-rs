use crate::{
    AuthError, AuthRecordFields, AuthResult, FieldDate, FieldMap, FromFieldMap, SchemaValue,
    StructuredCloneContext,
};
use serde::{Deserialize, Serialize};

/// Device authorization fields after adapter output projection.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DeviceCode {
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub id: SchemaValue<String>,
    #[serde(
        default,
        rename = "deviceCode",
        skip_serializing_if = "SchemaValue::is_json_omitted"
    )]
    pub device_code: SchemaValue<String>,
    #[serde(
        default,
        rename = "userCode",
        skip_serializing_if = "SchemaValue::is_json_omitted"
    )]
    pub user_code: SchemaValue<String>,
    #[serde(
        default,
        rename = "userId",
        skip_serializing_if = "SchemaValue::is_json_omitted"
    )]
    pub user_id: SchemaValue<Option<String>>,
    #[serde(
        default,
        rename = "expiresAt",
        skip_serializing_if = "SchemaValue::is_json_omitted"
    )]
    pub expires_at: SchemaValue<FieldDate>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub status: SchemaValue<String>,
    #[serde(
        default,
        rename = "lastPolledAt",
        skip_serializing_if = "SchemaValue::is_json_omitted"
    )]
    pub last_polled_at: SchemaValue<Option<FieldDate>>,
    #[serde(
        default,
        rename = "pollingInterval",
        skip_serializing_if = "SchemaValue::is_json_omitted"
    )]
    pub polling_interval: SchemaValue<Option<f64>>,
    #[serde(
        default,
        rename = "clientId",
        skip_serializing_if = "SchemaValue::is_json_omitted"
    )]
    pub client_id: SchemaValue<Option<String>>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_json_omitted")]
    pub scope: SchemaValue<Option<String>>,
    /// Declared application fields after adapter output projection.
    #[serde(with = "crate::field_value::serde::map", flatten, default)]
    pub additional_fields: FieldMap,
    #[serde(skip)]
    consumption: Option<ConsumptionBindings>,
}

#[derive(Clone)]
struct ConsumptionBindings {
    physical: FieldMap,
    projected: FieldMap,
}

impl DeviceCode {
    fn binding_values(&self) -> FieldMap {
        [
            ("id".into(), self.id.field_value()),
            ("deviceCode".into(), self.device_code.field_value()),
            ("clientId".into(), self.client_id.field_value()),
            ("userId".into(), self.user_id.field_value()),
            ("status".into(), self.status.field_value()),
        ]
        .into()
    }

    /// Seal physical values captured before output callbacks against the final public bindings.
    /// Adapter implementations must supply the five logical binding names without output conversion.
    #[doc(hidden)]
    pub fn with_storage_bindings(mut self, physical: FieldMap) -> Self {
        self.consumption = Some(ConsumptionBindings {
            physical,
            projected: self.binding_values(),
        });
        self
    }

    /// Return original storage bindings and whether the caller retained the projected bindings.
    #[doc(hidden)]
    pub fn consumption_bindings(&self) -> AuthResult<(&FieldMap, bool)> {
        let saved = self.consumption.as_ref().ok_or_else(|| {
            AuthError::internal("Device code has no adapter consumption bindings")
        })?;
        let unchanged = self.binding_values().iter().all(|(name, value)| {
            saved
                .projected
                .get(name)
                .is_some_and(|saved| saved.same_value_zero(value))
        });
        Ok((&saved.physical, unchanged))
    }
}

impl From<FieldMap> for DeviceCode {
    fn from(mut fields: FieldMap) -> Self {
        Self {
            id: SchemaValue::from_field(fields.shift_remove("id").unwrap_or_default()),
            device_code: SchemaValue::from_field(
                fields.shift_remove("deviceCode").unwrap_or_default(),
            ),
            user_code: SchemaValue::from_field(fields.shift_remove("userCode").unwrap_or_default()),
            user_id: SchemaValue::from_field(fields.shift_remove("userId").unwrap_or_default()),
            expires_at: SchemaValue::from_field(
                fields.shift_remove("expiresAt").unwrap_or_default(),
            ),
            status: SchemaValue::from_field(fields.shift_remove("status").unwrap_or_default()),
            last_polled_at: SchemaValue::from_field(
                fields.shift_remove("lastPolledAt").unwrap_or_default(),
            ),
            polling_interval: SchemaValue::from_field(
                fields.shift_remove("pollingInterval").unwrap_or_default(),
            ),
            client_id: SchemaValue::from_field(fields.shift_remove("clientId").unwrap_or_default()),
            scope: SchemaValue::from_field(fields.shift_remove("scope").unwrap_or_default()),
            additional_fields: fields,
            consumption: None,
        }
    }
}

impl FromFieldMap for DeviceCode {
    fn from_field_values(fields: FieldMap) -> AuthResult<Self> {
        Ok(fields.into())
    }
}

impl AuthRecordFields for DeviceCode {
    fn field_values(&self) -> AuthResult<FieldMap> {
        let mut fields: FieldMap = [
            ("id".into(), self.id.field_value()),
            ("deviceCode".into(), self.device_code.field_value()),
            ("userCode".into(), self.user_code.field_value()),
            ("userId".into(), self.user_id.field_value()),
            ("expiresAt".into(), self.expires_at.field_value()),
            ("status".into(), self.status.field_value()),
            ("lastPolledAt".into(), self.last_polled_at.field_value()),
            (
                "pollingInterval".into(),
                self.polling_interval.field_value(),
            ),
            ("clientId".into(), self.client_id.field_value()),
            ("scope".into(), self.scope.field_value()),
        ]
        .into();
        fields.extend(self.additional_fields.clone());
        Ok(fields)
    }

    fn structured_clone(&self, context: &mut StructuredCloneContext) -> AuthResult<Self> {
        let mut result = self.clone();
        result.id = context.clone_field(&self.id)?;
        result.device_code = context.clone_field(&self.device_code)?;
        result.user_code = context.clone_field(&self.user_code)?;
        result.user_id = context.clone_field(&self.user_id)?;
        result.expires_at = context.clone_field(&self.expires_at)?;
        result.status = context.clone_field(&self.status)?;
        result.last_polled_at = context.clone_field(&self.last_polled_at)?;
        result.polling_interval = context.clone_field(&self.polling_interval)?;
        result.client_id = context.clone_field(&self.client_id)?;
        result.scope = context.clone_field(&self.scope)?;
        result.additional_fields = context.clone_map(&self.additional_fields)?;
        result.consumption = self
            .consumption
            .as_ref()
            .map(|saved| {
                Ok::<_, crate::AuthError>(ConsumptionBindings {
                    physical: context.clone_map(&saved.physical)?,
                    projected: context.clone_map(&saved.projected)?,
                })
            })
            .transpose()?;
        Ok(result)
    }
}

impl std::fmt::Debug for DeviceCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceCode")
            .field("fields", &self.field_values())
            .finish()
    }
}

impl PartialEq for DeviceCode {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.device_code == other.device_code
            && self.user_code == other.user_code
            && self.user_id == other.user_id
            && self.expires_at == other.expires_at
            && self.status == other.status
            && self.last_polled_at == other.last_polled_at
            && self.polling_interval == other.polling_interval
            && self.client_id == other.client_id
            && self.scope == other.scope
            && self.additional_fields == other.additional_fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FieldValue;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn function(calls: &Arc<AtomicUsize>) -> FieldValue {
        let observed = calls.clone();
        let factory: crate::user_fields::UserFieldFactory = Arc::new(move || {
            let _ = observed.fetch_add(1, Ordering::SeqCst);
            Ok(FieldValue::Undefined)
        });
        FieldValue::Function(crate::FieldFunction::from(factory))
    }

    #[test]
    fn snapshot_preserves_binding_aliases_and_rejects_saved_functions() -> AuthResult<()> {
        let shared = FieldValue::from(FieldMap::from([("owner".into(), true.into())]));
        let device = DeviceCode::from(FieldMap::from([("id".into(), shared.clone())]))
            .with_storage_bindings(FieldMap::from([("id".into(), shared.clone())]));
        let snapshot = device.structured_clone(&mut StructuredCloneContext::new())?;
        let (physical, unchanged) = snapshot.consumption_bindings()?;
        assert!(unchanged);
        assert!(physical["id"].strict_equals(&snapshot.id.field_value()));
        assert!(!physical["id"].strict_equals(&shared));

        let calls = Arc::new(AtomicUsize::new(0));
        let nested: FieldValue = vec![function(&calls)].into();
        for physical in [true, false] {
            let mut device = device.clone();
            let saved = device.consumption.as_mut().unwrap();
            let fields = if physical {
                &mut saved.physical
            } else {
                &mut saved.projected
            };
            let _ = fields.insert("hidden".into(), nested.clone());
            assert!(matches!(
                device.structured_clone(&mut StructuredCloneContext::new()),
                Err(AuthError::DataClone)
            ));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn json_omits_function_properties_and_preserves_containers() -> AuthResult<()> {
        let calls = Arc::new(AtomicUsize::new(0));
        let function = function(&calls);
        let device = DeviceCode::from(FieldMap::from([
            ("id".into(), function.clone()),
            ("extra".into(), function.clone()),
            ("array".into(), vec![function.clone()].into()),
            (
                "object".into(),
                FieldMap::from([("nested".into(), function.clone())]).into(),
            ),
        ]));
        assert_eq!(
            serde_json::to_value(device)?,
            serde_json::json!({"array": [null], "object": {}})
        );
        for (metadata, expected) in [
            (None, Some(serde_json::Value::Null)),
            (Some(FieldValue::Null), Some(serde_json::Value::Null)),
            (Some(FieldValue::Undefined), None),
            (Some(function), None),
        ] {
            let user = crate::CreateUser {
                metadata,
                ..Default::default()
            };
            assert_eq!(
                serde_json::to_value(user)?.get("metadata"),
                expected.as_ref()
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        Ok(())
    }
}
