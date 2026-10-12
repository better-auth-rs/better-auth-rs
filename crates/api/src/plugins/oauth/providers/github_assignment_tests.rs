//! Native carrier regressions exercise the production GitHub profile consumer before JSON conversion.

#![expect(
    clippy::unwrap_used,
    reason = "Regression assertions retain original receivers, setter failures, and complete native responses."
)]

use super::*;
use async_trait::async_trait;
use better_auth_core::{
    FieldArray, FieldDate, FieldFunction, FieldObject, FieldProperty, FieldPropertyDescriptor,
};
use std::sync::{Arc, Mutex, OnceLock, Weak};

type Events = Arc<Mutex<Vec<&'static str>>>;

struct Mapper {
    profile: Weak<FieldValue>,
    events: Events,
}

#[async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile_native(&self, profile: &FieldValue) -> AuthResult<FieldValue> {
        assert!(profile.strict_equals(&self.profile.upgrade().unwrap()));
        self.events.lock().unwrap().push("mapper");
        Ok(FieldMap::new().into())
    }
}

fn carrier(kind: &str, fields: FieldObject) -> AuthResult<FieldValue> {
    Ok(match kind {
        "object" => fields.into(),
        "array" => FieldArray::from_values_with_properties(Vec::new(), fields).into(),
        "date" => FieldDate::from_milliseconds_with_properties(0.0, fields).into(),
        "function" => FieldFunction::contextual_with_properties(
            |_, _| {
                Err(AuthError::internal(
                    "The GitHub profile must not be invoked",
                ))
            },
            fields,
        )
        .into(),
        _ => return Err(AuthError::internal("Unknown native profile carrier")),
    })
}

#[tokio::test]
async fn github_email_assignment_uses_native_carriers_and_preserves_setter_effects() {
    for kind in ["object", "array", "date", "function"] {
        for mode in ["absent", "data", "accessor", "setter-error", "readonly"] {
            let events = Events::default();
            let owner = Arc::new(OnceLock::<Weak<FieldValue>>::new());
            let stored = Arc::new(Mutex::new(FieldValue::Null));
            let email: FieldValue = literal([("address", "selected@github.test".into())]).into();
            let verified: FieldValue = literal([("checked", true.into())]).into();
            let thrown: FieldValue = literal([("failure", "native-email-setter".into())]).into();
            let mut properties = literal([
                ("name", "Native GitHub".into()),
                ("avatar_url", "native.png".into()),
            ])
            .into_iter()
            .map(|(name, value)| (name, FieldPropertyDescriptor::data(value)))
            .collect::<indexmap::IndexMap<_, _>>();
            if matches!(mode, "accessor" | "setter-error") {
                let getter = {
                    let owner = owner.clone();
                    let events = events.clone();
                    let stored = stored.clone();
                    FieldFunction::contextual(move |receiver, _| {
                        assert!(receiver.strict_equals(&owner.get().unwrap().upgrade().unwrap()));
                        events.lock().unwrap().push("get");
                        Ok(stored.lock().unwrap().clone())
                    })
                };
                let setter = {
                    let owner = owner.clone();
                    let events = events.clone();
                    let stored = stored.clone();
                    let thrown = thrown.clone();
                    FieldFunction::contextual(move |receiver, arguments| {
                        assert!(receiver.strict_equals(&owner.get().unwrap().upgrade().unwrap()));
                        assert_eq!(arguments.len(), 1);
                        events.lock().unwrap().push("set");
                        *stored.lock().unwrap() = arguments.first().unwrap().clone();
                        if mode == "setter-error" {
                            return Err(AuthError::from_thrown(thrown.clone()));
                        }
                        Ok(FieldValue::Undefined)
                    })
                };
                let _ = properties.insert(
                    "email".into(),
                    FieldPropertyDescriptor {
                        enumerable: false,
                        configurable: true,
                        property: FieldProperty::Accessor {
                            get: Some(getter),
                            set: Some(setter),
                        },
                    },
                );
            } else if mode != "absent" {
                let _ = properties.insert(
                    "email".into(),
                    FieldPropertyDescriptor {
                        enumerable: false,
                        configurable: true,
                        property: FieldProperty::Data {
                            value: FieldValue::Null,
                            writable: mode != "readonly",
                        },
                    },
                );
            }
            let profile = Arc::new(carrier(kind, properties.into()).unwrap());
            owner.set(Arc::downgrade(&profile)).unwrap();
            let before = profile.own_property_descriptor("email").unwrap();
            assert!(events.lock().unwrap().is_empty());
            let mapper = Mapper {
                profile: Arc::downgrade(&profile),
                events: events.clone(),
            };
            let emails: FieldValue = vec![FieldValue::from(literal([
                ("email", email.clone()),
                ("primary", true.into()),
                ("verified", verified.clone()),
            ]))]
            .into();
            let result = github(&profile, &emails, Some(&mapper)).await;
            if mode == "setter-error" {
                assert!(
                    result
                        .unwrap_err()
                        .raw_value()
                        .unwrap()
                        .strict_equals(&thrown)
                );
                assert!(stored.lock().unwrap().strict_equals(&email));
                assert_eq!(*events.lock().unwrap(), ["get", "set"]);
            } else if mode == "readonly" {
                assert!(
                    matches!(result, Err(AuthError::TypeError(message)) if message == "Attempted to assign to readonly property.")
                );
                assert_eq!(profile.own_property_descriptor("email").unwrap(), before);
                assert!(events.lock().unwrap().is_empty());
            } else {
                let response = result.unwrap().value;
                assert_eq!(
                    response,
                    FieldValue::from(literal([
                        (
                            "user",
                            literal([
                                ("name", "Native GitHub".into()),
                                ("email", email.clone()),
                                ("image", "native.png".into()),
                                ("emailVerified", verified.clone()),
                            ])
                            .into()
                        ),
                        ("data", profile.as_ref().clone()),
                    ]))
                );
                assert!(
                    response
                        .model_property("data")
                        .unwrap()
                        .strict_equals(&profile)
                );
                assert!(
                    response
                        .model_property("user")
                        .unwrap()
                        .model_property("email")
                        .unwrap()
                        .strict_equals(&email)
                );
                let descriptor = profile.own_property_descriptor("email").unwrap().unwrap();
                if mode == "accessor" {
                    assert_eq!(Some(descriptor), before);
                    assert_eq!(
                        *events.lock().unwrap(),
                        ["get", "set", "get", "mapper", "get"]
                    );
                } else {
                    assert_eq!(
                        descriptor,
                        FieldPropertyDescriptor {
                            enumerable: mode == "absent",
                            configurable: true,
                            property: FieldProperty::Data {
                                value: email,
                                writable: true
                            },
                        }
                    );
                    assert_eq!(*events.lock().unwrap(), ["mapper"]);
                }
            }
        }
    }
}

#[tokio::test]
async fn github_primitive_email_assignment_retains_the_existing_error() {
    let emails: FieldValue = vec![FieldValue::from(literal([
        ("email", "selected@github.test".into()),
        ("primary", true.into()),
    ]))]
    .into();
    for profile in [
        false.into(),
        7.into(),
        "profile".into(),
        Utf16String::from_units(vec![0xd800]).into(),
    ] {
        let error = github(&profile, &emails, None).await.unwrap_err();
        assert!(
            matches!(error, AuthError::TypeError(message) if message == "Cannot assign property 'email' to a primitive value")
        );
    }
}
