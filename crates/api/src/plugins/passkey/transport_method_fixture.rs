#![expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Native method contracts assert receiver identity, exact errors, and committed storage. Fixture locks must be available."
)]
use better_auth_core::{
    AuthError, AuthResult, FieldFunction, FieldMap, FieldValue,
    field_value::{FieldProperty, FieldPropertyDescriptor},
};
use std::sync::{Arc, Mutex};

pub(super) const CASES: [&str; 10] = [
    "array",
    "object",
    "number",
    "null",
    "undefined",
    "unread-result",
    "getter-error",
    "call-error",
    "api-error",
    "noncallable",
];

pub(super) struct Transport {
    pub(super) receiver: Arc<FieldValue>,
    pub(super) result: FieldValue,
    pub(super) original: FieldValue,
    pub(super) events: Arc<Mutex<Vec<&'static str>>>,
}

impl Transport {
    pub(super) fn new(name: &'static str) -> AuthResult<Self> {
        let original = if name == "api-error" {
            AuthError::from_status(
                "CONFLICT",
                FieldMap::from([("message".into(), "Original transport error".into())]).into(),
            )
            .into_thrown_value()?
        } else {
            FieldMap::from([
                ("marker".into(), name.into()),
                ("ownUndefined".into(), FieldValue::Undefined),
            ])
            .into()
        };
        let events = Arc::new(Mutex::new(Vec::new()));
        let result = match name {
            "array" => vec![FieldValue::from("internal"), "hybrid".into()].into(),
            "number" => 17.into(),
            "null" => FieldValue::Null,
            "undefined" => FieldValue::Undefined,
            _ => FieldValue::from(FieldMap::from([
                ("marker".into(), "retained result".into()),
                ("ownUndefined".into(), FieldValue::Undefined),
            ])),
        };
        if name == "unread-result" {
            let original = original.clone();
            let events = events.clone();
            result.define_model_property(
                "toJSON",
                FieldPropertyDescriptor {
                    enumerable: false,
                    configurable: true,
                    property: FieldProperty::Accessor {
                        get: Some(FieldFunction::contextual(move |_, arguments| {
                            assert!(arguments.is_empty());
                            events.lock().unwrap().push("result:read");
                            Err(AuthError::from_thrown(original.clone()))
                        })),
                        set: None,
                    },
                }
                .into(),
            )?;
        }
        let receiver = Arc::new(FieldValue::from(FieldMap::new()));
        let method = FieldFunction::contextual({
            let owner = Arc::downgrade(&receiver);
            let events = events.clone();
            let original = original.clone();
            let result = result.clone();
            move |this, arguments| {
                assert!(this.strict_equals(owner.upgrade().unwrap().as_ref()));
                assert_eq!(arguments, &[FieldValue::from(",")]);
                events.lock().unwrap().push("split:call");
                if matches!(name, "call-error" | "api-error") {
                    Err(AuthError::from_thrown(original.clone()))
                } else {
                    Ok(result.clone())
                }
            }
        });
        receiver.define_model_property(
            "split",
            FieldPropertyDescriptor {
                enumerable: true,
                configurable: true,
                property: FieldProperty::Accessor {
                    get: Some(FieldFunction::contextual({
                        let owner = Arc::downgrade(&receiver);
                        let events = events.clone();
                        let original = original.clone();
                        move |this, arguments| {
                            assert!(this.strict_equals(owner.upgrade().unwrap().as_ref()));
                            assert!(arguments.is_empty());
                            events.lock().unwrap().push("split:get");
                            match name {
                                "getter-error" => Err(AuthError::from_thrown(original.clone())),
                                "noncallable" => Ok(17.into()),
                                _ => Ok(method.clone().into()),
                            }
                        }
                    })),
                    set: None,
                },
            }
            .into(),
        )?;
        Ok(Self {
            receiver,
            result,
            original,
            events,
        })
    }

    pub(super) fn fails(name: &str) -> bool {
        matches!(
            name,
            "getter-error" | "call-error" | "api-error" | "noncallable"
        )
    }

    pub(super) fn assert_calls(&self, name: &str) {
        let expected = if matches!(name, "getter-error" | "noncallable") {
            vec!["split:get"]
        } else {
            vec!["split:get", "split:call"]
        };
        assert_eq!(*self.events.lock().unwrap(), expected, "{name}");
    }

    pub(super) fn assert_original(&self, error: &AuthError) {
        assert!(
            error
                .raw_value()
                .is_some_and(|value| value.strict_equals(&self.original))
        );
    }
}
