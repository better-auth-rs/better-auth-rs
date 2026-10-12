use super::*;
use better_auth_core::{
    FieldFunction, FieldObject,
    field_value::{FieldProperty, FieldPropertyDescriptor},
};
use std::sync::Weak;

pub(crate) struct Root {
    pub(crate) value: FieldValue,
    owner: Arc<OnceLock<FieldValue>>,
    fields: FieldObject,
}

impl Root {
    pub(crate) fn new(kind: &str) -> Self {
        let fields: FieldObject = FieldMap::new().into();
        let object = fields.clone();
        let value: FieldValue = match kind {
            "date" => FieldDate::from_milliseconds_with_properties(NOW as f64, object).into(),
            "function" => {
                FieldFunction::contextual_with_properties(|_, _| Ok(FieldValue::Undefined), object)
                    .into()
            }
            _ => object.into(),
        };
        let owner = Arc::new(OnceLock::new());
        owner.set(value.clone()).unwrap();
        Self {
            value,
            owner,
            fields,
        }
    }

    pub(crate) fn owner(&self) -> Weak<OnceLock<FieldValue>> {
        Arc::downgrade(&self.owner)
    }

    pub(crate) fn data(&self, name: &str, value: FieldValue) {
        self.fields
            .define_own_property(name, FieldPropertyDescriptor::data(value).into())
            .unwrap();
    }

    pub(crate) fn getter(
        &self,
        name: &str,
        enumerable: bool,
        read: impl Fn(&FieldValue) -> AuthResult<FieldValue> + Send + Sync + 'static,
    ) {
        self.fields
            .define_own_property(
                name,
                FieldPropertyDescriptor {
                    enumerable,
                    configurable: true,
                    property: FieldProperty::Accessor {
                        get: Some(FieldFunction::contextual(move |receiver, _| read(receiver))),
                        set: None,
                    },
                }
                .into(),
            )
            .unwrap();
    }
}
