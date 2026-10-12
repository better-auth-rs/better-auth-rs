use crate::{AuthError, AuthResult, FieldDate, FieldValue, types::InvitationStatus};
use std::{borrow::Cow, collections::HashSet};

/// Convert a schema's default Rust type without crossing a JSON boundary.
pub trait SchemaField: Clone {
    /// Return the original field value when the Rust type does not match.
    fn from_field(value: FieldValue) -> Result<Self, FieldValue>;

    /// Move this Rust value into an adapter field while retaining object handles.
    fn into_field(self) -> FieldValue;

    /// Restore this field's native representation from its fully cloned adapter value.
    fn restore_cloned_field(&self, value: FieldValue) -> AuthResult<Self> {
        value.decode()
    }
}

impl SchemaField for FieldValue {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        Ok(value)
    }

    fn into_field(self) -> FieldValue {
        self
    }
}

macro_rules! field {
    ($type:ty, $variant:ident) => {
        impl SchemaField for $type {
            fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
                match value {
                    FieldValue::$variant(value) => Ok(value),
                    value => Err(value),
                }
            }

            fn into_field(self) -> FieldValue {
                FieldValue::$variant(self)
            }
        }
    };
}

field!(String, String);
field!(bool, Bool);
field!(f64, Number);
field!(FieldDate, Date);
field!(crate::FieldFunction, Function);
field!(crate::FieldObject, Object);
field!(crate::FieldArray, Array);

impl SchemaField for chrono::DateTime<chrono::Utc> {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        match &value {
            FieldValue::Date(date) => match date.to_datetime() {
                Ok(Some(date)) => Ok(date),
                Ok(None) | Err(_) => Err(value),
            },
            _ => Err(value),
        }
    }

    fn into_field(self) -> FieldValue {
        FieldValue::Date(self.into())
    }
}

impl SchemaField for crate::Utf16String {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        match value {
            FieldValue::String(value) => Ok(value.into()),
            FieldValue::Utf16String(value) => Ok(value),
            value => Err(value),
        }
    }

    fn into_field(self) -> FieldValue {
        self.into()
    }
}

macro_rules! integer {
    ($($type:ty),+ $(,)?) => {$(
        impl SchemaField for $type {
            fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
                match value {
                    FieldValue::Number(number)
                        if number.fract() == 0.0
                            && number >= <$type>::MIN as f64
                            && number < (<$type>::MAX as f64 + 1.0) => Ok(number as Self),
                    value => Err(value),
                }
            }

            fn into_field(self) -> FieldValue {
                FieldValue::Number(self as f64)
            }
        }

        impl From<$type> for FieldValue {
            fn from(value: $type) -> Self {
                FieldValue::Number(value as f64)
            }
        }
    )+};
}

integer!(i8, i16, i32, i64, isize, u8, u16, u32, u64, usize);

impl<T: SchemaField> SchemaField for Option<T> {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        match value {
            FieldValue::Null | FieldValue::Undefined => Ok(None),
            value => T::from_field(value).map(Some),
        }
    }

    fn into_field(self) -> FieldValue {
        self.map_or(FieldValue::Null, SchemaField::into_field)
    }

    fn restore_cloned_field(&self, value: FieldValue) -> AuthResult<Self> {
        match self {
            Some(source) => source.restore_cloned_field(value).map(Some),
            None => value.decode(),
        }
    }
}

impl<T: SchemaField> SchemaField for Vec<T> {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        let FieldValue::Array(values) = &value else {
            return Err(value);
        };
        let Some(values) = values.owned_values() else {
            return Err(value);
        };
        values
            .into_iter()
            .map(T::from_field)
            .collect::<Result<_, _>>()
            .map_err(|_| value)
    }

    fn into_field(self) -> FieldValue {
        self.into_iter()
            .map(SchemaField::into_field)
            .collect::<Vec<_>>()
            .into()
    }

    fn restore_cloned_field(&self, value: FieldValue) -> AuthResult<Self> {
        let values = value.decode::<Vec<FieldValue>>()?;
        if values.len() != self.len() {
            return Err(AuthError::internal(
                "Cloned array does not retain the source field count",
            ));
        }
        self.iter()
            .zip(values)
            .map(|(source, value)| source.restore_cloned_field(value))
            .collect()
    }
}

impl SchemaField for Cow<'_, str> {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        String::from_field(value).map(Cow::Owned)
    }

    fn into_field(self) -> FieldValue {
        self.into_owned().into()
    }
}

impl SchemaField for InvitationStatus {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        match value.as_str() {
            Some("pending") => Ok(Self::Pending),
            Some("accepted") => Ok(Self::Accepted),
            Some("rejected") => Ok(Self::Rejected),
            Some("canceled") => Ok(Self::Canceled),
            _ => Err(value),
        }
    }

    fn into_field(self) -> FieldValue {
        self.to_string().into()
    }
}

impl<T: SchemaField> SchemaField for &T {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        Err(value)
    }

    fn into_field(self) -> FieldValue {
        (*self).clone().into_field()
    }
}

impl SchemaField for serde_json::Value {
    fn from_field(value: FieldValue) -> Result<Self, FieldValue> {
        json_structure(&value, &mut HashSet::new()).ok_or(value)
    }

    fn into_field(self) -> FieldValue {
        self.into()
    }
}

// Typed probing reads only owned storage and does not evaluate getters or JSON conversion methods.
fn json_structure(
    value: &FieldValue,
    active: &mut HashSet<crate::field_value::ContainerIdentity>,
) -> Option<serde_json::Value> {
    use crate::field_value::ContainerIdentity;
    use serde_json::Value;

    Some(match value {
        FieldValue::Null => Value::Null,
        FieldValue::Bool(value) => Value::Bool(*value),
        FieldValue::Number(value) if value.is_finite() => {
            serde_json::from_str(&super::number_string(*value)).ok()?
        }
        FieldValue::String(value) => Value::String(value.clone()),
        FieldValue::Array(values) => {
            let identity = ContainerIdentity::Array(values.identity());
            if !active.insert(identity) {
                return None;
            }
            let values = values
                .owned_values()?
                .iter()
                .map(|value| json_structure(value, active))
                .collect::<Option<_>>()?;
            let _ = active.remove(&identity);
            Value::Array(values)
        }
        FieldValue::Object(object) => {
            let identity = ContainerIdentity::Object(object.identity());
            if !active.insert(identity) {
                return None;
            }
            let fields = object
                .owned_fields()?
                .into_iter()
                .map(|(name, value)| Some((name, json_structure(&value, active)?)))
                .collect::<Option<_>>()?;
            let _ = active.remove(&identity);
            Value::Object(fields)
        }
        _ => return None,
    })
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors."
)]
mod json_tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn json_import_preserves_negative_zero_extremes_and_nested_fields() -> crate::AuthResult<()> {
        let source: serde_json::Value = serde_json::from_str(
            "{\"values\":[-0.0,1.7976931348623157e308,-1.7976931348623157e308],\"nested\":{\"value\":false}}",
        )?;
        let value = FieldValue::from(source.clone());
        let fields = value.as_object().unwrap().snapshot_fields()?;
        let values = fields["values"].as_array().unwrap();
        assert!(values.get(0)?.unwrap().as_f64().unwrap().is_sign_negative());
        assert_eq!(values.get(1)?.unwrap().as_f64(), Some(f64::MAX));
        assert_eq!(values.get(2)?.unwrap().as_f64(), Some(-f64::MAX));
        assert_eq!(source.clone().into_field(), value);
        let mut json_expected = source;
        json_expected["values"][0] = serde_json::json!(0);
        assert_eq!(
            <serde_json::Value as SchemaField>::from_field(value),
            Ok(json_expected)
        );
        for native in [
            FieldValue::Undefined,
            f64::NAN.into(),
            f64::INFINITY.into(),
            f64::NEG_INFINITY.into(),
            FieldDate::invalid().into(),
        ] {
            assert!(<serde_json::Value as SchemaField>::from_field(native).is_err());
        }
        Ok(())
    }

    #[test]
    fn json_probe_inspects_owned_structure_without_running_methods() -> AuthResult<()> {
        let calls = Arc::new(AtomicUsize::new(0));
        let value: FieldValue = crate::FieldMap::from([
            (
                "toJSON".into(),
                crate::FieldFunction::contextual({
                    let calls = calls.clone();
                    move |_, _| {
                        let _ = calls.fetch_add(1, Ordering::SeqCst);
                        Ok("converted".into())
                    }
                })
                .into(),
            ),
            ("value".into(), 1.into()),
        ])
        .into();
        let result = <serde_json::Value as SchemaField>::from_field(value.clone());
        assert!(matches!(result, Err(original) if original.strict_equals(&value)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(value.json()?, Some(serde_json::json!("converted")));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let value: FieldValue = crate::FieldMap::from([
            ("toJSON".into(), "ordinary property".into()),
            ("value".into(), vec![FieldValue::Null, true.into()].into()),
        ])
        .into();
        assert_eq!(
            <serde_json::Value as SchemaField>::from_field(value),
            Ok(serde_json::json!({"toJSON": "ordinary property", "value": [null, true]})),
        );
        let object = crate::FieldObject::from(crate::FieldMap::new());
        object.set("self", FieldValue::Object(object.clone()))?;
        let value = FieldValue::Object(object.clone());
        let result = <serde_json::Value as SchemaField>::from_field(value.clone());
        let _ = object.delete("self")?;
        assert!(matches!(result, Err(original) if original.strict_equals(&value)));
        Ok(())
    }
}
