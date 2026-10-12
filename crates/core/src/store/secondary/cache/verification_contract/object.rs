use super::*;
use crate::field_value::{FieldProperty, FieldPropertyDescriptor};
use std::sync::{OnceLock, Weak};

pub(super) struct Root {
    pub(super) value: FieldValue,
    expected: Arc<OnceLock<FieldValue>>,
    properties: crate::FieldObject,
}

impl Root {
    pub(super) fn new(kind: &str) -> AuthResult<Self> {
        Self::build(|fields| {
            Ok(match kind {
                "array" => {
                    let array = crate::FieldArray::with_length_and_properties(3, fields);
                    array.set(0, "array-value".into())?;
                    array.set(2, FieldValue::Undefined)?;
                    array.into()
                }
                "date" => crate::FieldDate::from_milliseconds_with_properties(
                    (NOW - 4_000) as f64,
                    fields,
                )
                .into(),
                "expiry" => crate::FieldDate::from_milliseconds_with_properties(
                    (NOW + 60_000) as f64,
                    fields,
                )
                .into(),
                "function" => crate::FieldFunction::contextual_with_properties(
                    |_, _| Ok(FieldValue::Undefined),
                    fields,
                )
                .into(),
                _ => fields.into(),
            })
        })
    }

    pub(super) fn build(
        create: impl FnOnce(crate::FieldObject) -> AuthResult<FieldValue>,
    ) -> AuthResult<Self> {
        let properties: crate::FieldObject = FieldMap::new().into();
        let fields = properties.clone();
        let value = create(fields)?;
        let expected = Arc::new(OnceLock::new());
        expected.set(value.clone()).unwrap();
        Ok(Self {
            value,
            expected,
            properties,
        })
    }

    pub(super) fn weak(&self) -> Weak<OnceLock<FieldValue>> {
        Arc::downgrade(&self.expected)
    }

    pub(super) fn data(&self, name: &str, value: FieldValue) {
        self.properties
            .define_own_property(name, FieldPropertyDescriptor::data(value).into())
            .unwrap();
    }

    pub(super) fn getter(
        &self,
        name: &str,
        enumerable: bool,
        callback: impl Fn(&FieldValue) -> AuthResult<FieldValue> + Send + Sync + 'static,
    ) {
        self.properties
            .define_own_property(
                name,
                FieldPropertyDescriptor {
                    enumerable,
                    configurable: true,
                    property: FieldProperty::Accessor {
                        get: Some(crate::FieldFunction::contextual(move |receiver, _| {
                            callback(receiver)
                        })),
                        set: None,
                    },
                }
                .into(),
            )
            .unwrap();
    }
}
