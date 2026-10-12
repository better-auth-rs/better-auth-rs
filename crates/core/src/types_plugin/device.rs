use crate::{
    AuthError, AuthRecordFields, AuthResult, DeviceCodeOwnership, DeviceCodeWhere, FieldDate,
    FieldMap, FieldValue, SchemaValue, WhereMode, WhereOperator,
    entity::record_fields::ClonedFields,
};

impl DeviceCodeOwnership {
    /// Express an ownership condition through the adapter's shared field query policy.
    #[doc(hidden)]
    pub fn query(&self) -> DeviceCodeWhere {
        match self {
            Self::ClientId(client) => DeviceCodeWhere::new("clientId", client.clone()),
            Self::FieldEquals { field, value } => DeviceCodeWhere::new(field, value.clone()),
            Self::FieldIn { field, values } | Self::FieldNotIn { field, values } => {
                DeviceCodeWhere {
                    field: field.clone(),
                    operator: if matches!(self, Self::FieldIn { .. }) {
                        WhereOperator::In
                    } else {
                        WhereOperator::NotIn
                    },
                    value: values.clone().into(),
                    mode: WhereMode::Sensitive,
                }
            }
            Self::Where(query) => query.clone(),
        }
    }
}

/// Device authorization fields after adapter output projection.
#[derive(Clone, Default)]
pub struct DeviceCode {
    /// Source property order, independent of the current typed values.
    pub field_order: Vec<String>,
    pub id: SchemaValue<String>,
    pub device_code: SchemaValue<String>,
    pub user_code: SchemaValue<String>,
    pub user_id: SchemaValue<Option<String>>,
    pub expires_at: SchemaValue<FieldDate>,
    pub status: SchemaValue<String>,
    pub last_polled_at: SchemaValue<Option<FieldDate>>,
    pub polling_interval: SchemaValue<Option<f64>>,
    pub client_id: SchemaValue<Option<String>>,
    pub scope: SchemaValue<Option<String>>,
    /// Declared application fields after adapter output projection.
    pub additional_fields: FieldMap,
    pub(crate) consumption: Option<ConsumptionBindings>,
}

#[derive(Clone)]
pub(crate) struct ConsumptionBindings {
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

    pub(crate) fn consumption_clone_fields(&self) -> Vec<FieldValue> {
        self.consumption
            .iter()
            .flat_map(|saved| {
                ClonedFields::map_values(&saved.physical)
                    .chain(ClonedFields::map_values(&saved.projected))
            })
            .collect()
    }

    pub(crate) fn restore_consumption(
        &self,
        fields: &mut ClonedFields,
    ) -> AuthResult<Option<ConsumptionBindings>> {
        self.consumption
            .as_ref()
            .map(|saved| {
                Ok(ConsumptionBindings {
                    physical: fields.map(&saved.physical)?,
                    projected: fields.map(&saved.projected)?,
                })
            })
            .transpose()
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
#[expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Assertions report exact contract mismatches while Result propagates fixture errors."
)]
mod tests {
    use super::*;
    use crate::StructuredCloneContext;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn function(calls: &Arc<AtomicUsize>) -> FieldValue {
        let observed = calls.clone();
        let factory: crate::user_fields::UserFieldFactory =
            crate::user_fields::UserFieldFactory::new(move || {
                let _ = observed.fetch_add(1, Ordering::SeqCst);
                Ok(FieldValue::Undefined)
            });
        FieldValue::Function(crate::FieldFunction::from(factory))
    }

    #[test]
    fn snapshot_preserves_binding_aliases_and_rejects_saved_functions() -> AuthResult<()> {
        let shared = FieldValue::from(FieldMap::from([("owner".into(), true.into())]));
        let device = DeviceCode::from(FieldMap::from([
            ("scope".into(), FieldValue::Undefined),
            ("id".into(), shared.clone()),
        ]))
        .with_storage_bindings(FieldMap::from([("id".into(), shared.clone())]));
        let snapshot = device.structured_clone(&mut StructuredCloneContext::new())?;
        let (physical, unchanged) = snapshot.consumption_bindings()?;
        assert!(unchanged);
        assert!(physical["id"].strict_equals(&snapshot.id.field_value()));
        assert!(!physical["id"].strict_equals(&shared));
        assert_eq!(snapshot.field_order, ["scope", "id"]);
        assert_eq!(
            snapshot
                .field_values()?
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["scope", "id"],
        );
        let restored: DeviceCode = serde_json::from_value(serde_json::to_value(&device)?)?;
        assert!(restored.consumption_bindings().is_err());

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
