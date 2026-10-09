use super::*;
use crate::{
    AuthConfig, CreateUser, UpdateUser, UserView,
    store::{EphemeralStore, UserStore},
};
use std::sync::mpsc::{self, Sender};

fn emit(events: &Sender<&'static str>, event: &'static str) -> AuthResult<()> {
    events
        .send(event)
        .map_err(|error| AuthError::internal(error.to_string()))
}

fn fields(events: &Sender<&'static str>) -> UserConfig {
    let factory_events = events.clone();
    let factory: UserFieldFactory = Arc::new(move || {
        emit(&factory_events, "factory")?;
        Err(AuthError::FieldInput {
            code: "FACTORY_REJECTED",
            message: "field factory rejected".into(),
        })
    });
    let input_events = events.clone();
    let output_events = events.clone();
    let later_events = events.clone();
    let later: UserFieldFactory = Arc::new(move || {
        emit(&later_events, "later")?;
        Ok("later".into())
    });
    UserConfig {
        additional_fields: Some(
            [
                (
                    "label".into(),
                    UserFieldConfig {
                        default_value: Some("constant must not replace factory errors".into()),
                        default_value_fn: Some(factory.clone()),
                        on_update: Some(factory),
                        transform: Some(FieldTransforms {
                            input: Some(UserFieldTransform::new(move |value| {
                                emit(&input_events, "input")?;
                                Ok(value)
                            })),
                            output: Some(UserFieldTransform::new(move |value| {
                                emit(&output_events, "output")?;
                                Ok(value)
                            })),
                        }),
                        ..Default::default()
                    },
                ),
                (
                    "later".into(),
                    UserFieldConfig {
                        default_value_fn: Some(later.clone()),
                        on_update: Some(later),
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        ),
    }
}

fn assert_factory_error<T>(result: AuthResult<T>) {
    assert!(matches!(
        result,
        Err(AuthError::FieldInput { code: "FACTORY_REJECTED", message })
            if message == "field factory rejected"
    ));
}

#[test]
fn public_input_preserves_undefined_results_and_skips_callbacks_for_undefined_input()
-> AuthResult<()> {
    for create in [true, false] {
        let (events, receiver) = mpsc::channel();
        let validator_events = events.clone();
        let transform_events = events.clone();
        let factory_events = events.clone();
        let mut fields = UserConfig::default();
        fields.fields_mut().extend([
            (
                "ownValidator".into(),
                UserFieldConfig {
                    validator: Some(FieldValidators {
                        input: Some(Arc::new(|_| {
                            Err(AuthError::internal("undefined validator ran"))
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
            (
                "ownTransform".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new(|_| {
                            Err(AuthError::internal("undefined transform ran"))
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
            (
                "validated".into(),
                UserFieldConfig {
                    validator: Some(FieldValidators {
                        input: Some(Arc::new(move |_| {
                            emit(&validator_events, "validator")?;
                            Ok(Value::Undefined)
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
            (
                "transformed".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new(move |_| {
                            emit(&transform_events, "transform")?;
                            Ok(Value::Undefined)
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
            (
                "factory".into(),
                UserFieldConfig {
                    default_value_fn: Some(Arc::new(move || {
                        emit(&factory_events, "factory")?;
                        Ok(Value::Undefined)
                    })),
                    ..Default::default()
                },
            ),
            (
                "literal".into(),
                UserFieldConfig {
                    default_value: Some(Value::Undefined),
                    required: Some(false),
                    ..Default::default()
                },
            ),
        ]);
        let input = FieldMap::from([
            ("ownValidator".into(), Value::Undefined),
            ("ownTransform".into(), Value::Undefined),
            ("validated".into(), "input".into()),
            ("transformed".into(), "input".into()),
        ]);
        let parsed = fields.parse_input(&input, create)?;
        let mut expected = input;
        let _ = expected.insert("validated".into(), Value::Undefined);
        let _ = expected.insert("transformed".into(), Value::Undefined);
        if create {
            let _ = expected.insert("factory".into(), Value::Undefined);
        }
        assert_eq!(parsed, expected);
        assert_eq!(
            parsed.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            receiver.try_iter().collect::<Vec<_>>(),
            if create {
                vec!["validator", "transform", "factory"]
            } else {
                vec!["validator", "transform"]
            }
        );
    }
    let fields = UserConfig {
        additional_fields: Some(
            [(
                "required".into(),
                UserFieldConfig {
                    required: Some(true),
                    default_value: Some(Value::Undefined),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    assert!(matches!(
        fields.parse_input(&FieldMap::new(), true),
        Err(AuthError::FieldInput {
            code: "MISSING_FIELD",
            ..
        })
    ));
    Ok(())
}

#[test]
fn factory_errors_follow_input_presence_and_stop_synthetic_output() -> AuthResult<()> {
    for protected in [false, true] {
        let (events, receiver) = mpsc::channel();
        let mut fields = fields(&events);
        let input = if protected {
            fields
                .fields_mut()
                .get_mut("label")
                .ok_or_else(|| AuthError::internal("Test label is missing"))?
                .input = Some(false);
            [("label".into(), "rejected client input".into())].into()
        } else {
            FieldMap::new()
        };
        if protected {
            let parsed = fields.parse_input(&input, true)?;
            let factory = fields
                .fields()
                .get("label")
                .and_then(|field| field.default_value_fn.clone())
                .ok_or_else(|| AuthError::internal("Test factory is missing"))?;
            assert!(
                parsed
                    .get("label")
                    .is_some_and(|value| { value.strict_equals(&Value::Function(factory.into())) })
            );
            assert_eq!(parsed.get("later"), Some(&Value::from("later")));
            assert_eq!(receiver.try_iter().collect::<Vec<_>>(), ["later"]);
        } else {
            assert_factory_error(fields.parse_input(&input, true));
            assert_eq!(receiver.try_iter().collect::<Vec<_>>(), ["factory"]);
        }
        assert_factory_error(UserView::synthetic_output(
            FieldMap::new(),
            &fields,
            &fields,
        ));
        assert_eq!(receiver.try_iter().collect::<Vec<_>>(), ["factory"]);
    }
    Ok(())
}

#[test]
fn synthetic_output_uses_complete_declarations_and_preserves_undefined_factory_results()
-> AuthResult<()> {
    let (events, receiver) = mpsc::channel();
    let optional = |default_value| UserFieldConfig {
        required: Some(false),
        default_value,
        ..Default::default()
    };
    let application = UserConfig {
        additional_fields: Some(
            [
                ("emailVerified".into(), optional(None)),
                ("provided".into(), optional(Some("fallback".into()))),
                ("fallback".into(), optional(Some("default".into()))),
                ("noDefault".into(), optional(Some(Value::Undefined))),
                (
                    "factory".into(),
                    UserFieldConfig {
                        default_value_fn: Some(Arc::new(move || {
                            emit(&events, "factory")?;
                            Ok(Value::Undefined)
                        })),
                        ..optional(None)
                    },
                ),
                (
                    "required".into(),
                    UserFieldConfig {
                        required: Some(true),
                        default_value: Some(Value::Undefined),
                        ..Default::default()
                    },
                ),
                (
                    "hidden".into(),
                    UserFieldConfig {
                        returned: Some(false),
                        default_value_fn: Some(Arc::new(|| {
                            Err(AuthError::internal("hidden factory ran"))
                        })),
                        ..Default::default()
                    },
                ),
                (
                    "id".into(),
                    UserFieldConfig {
                        returned: Some(false),
                        ..Default::default()
                    },
                ),
                ("pluginChoice".into(), optional(Some("application".into()))),
            ]
            .into(),
        ),
    };
    let plugin = UserConfig {
        additional_fields: Some([("pluginChoice".into(), optional(Some("plugin".into())))].into()),
    };
    let (adapter, endpoint) = crate::plugin_runtime::resolve_user_fields(&application, plugin);
    let date: Value = crate::FieldDate::from_milliseconds(0.0).into();
    let id: Value = FieldMap::from([("native".into(), true.into())]).into();
    let input = FieldMap::from([
        ("id".into(), id.clone()),
        ("name".into(), "Owner".into()),
        ("email".into(), "owner@synthetic.test".into()),
        ("emailVerified".into(), Value::Undefined),
        ("createdAt".into(), date.clone()),
        ("updatedAt".into(), date.clone()),
        ("provided".into(), Value::Null),
        ("fallback".into(), Value::Undefined),
        ("unknown".into(), "omit".into()),
    ]);
    let output = UserView::synthetic_output(input, &adapter, &endpoint)?;
    let expected = FieldMap::from([
        ("name".into(), "Owner".into()),
        ("email".into(), "owner@synthetic.test".into()),
        ("emailVerified".into(), Value::Null),
        ("image".into(), Value::Null),
        ("createdAt".into(), date.clone()),
        ("updatedAt".into(), date.clone()),
        ("pluginChoice".into(), "plugin".into()),
        ("provided".into(), Value::Null),
        ("fallback".into(), "default".into()),
        ("noDefault".into(), Value::Null),
        ("factory".into(), Value::Undefined),
        ("id".into(), id),
    ]);
    assert_eq!(output, expected);
    assert_eq!(
        output.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    for name in ["id", "createdAt", "updatedAt"] {
        assert!(output[name].strict_equals(&expected[name]));
    }
    assert_eq!(receiver.try_iter().collect::<Vec<_>>(), ["factory"]);
    Ok(())
}

#[tokio::test]
async fn factory_errors_stop_shared_storage_boundaries_before_binding() {
    for create in [false, true] {
        for boundary in ["fields", "record", "organization"] {
            let (events, receiver) = mpsc::channel();
            let fields = fields(&events);
            let bind = |_: &str, _: &UserFieldConfig, value| {
                emit(&events, "bind")?;
                Ok(value)
            };
            let result = match boundary {
                "record" => {
                    fields
                        .record_storage_fields_with_binding(FieldMap::new(), create, bind)
                        .await
                }
                "organization" => {
                    fields
                        .organization_storage_fields_with_binding(
                            FieldMap::new(),
                            FieldMap::new(),
                            create,
                            bind,
                        )
                        .await
                }
                _ => {
                    fields
                        .storage_fields_with_binding(FieldMap::new(), create, bind)
                        .await
                }
            };
            assert_factory_error(result);
            assert_eq!(receiver.try_iter().collect::<Vec<_>>(), ["factory"]);
        }
    }
}

#[tokio::test]
async fn factory_errors_preserve_stored_users_and_skip_output_callbacks() -> AuthResult<()> {
    let (events, receiver) = mpsc::channel();
    let store = EphemeralStore::new(Arc::new(AuthConfig {
        user: fields(&events),
        ..Default::default()
    }));
    let mut seed = CreateUser::new()
        .with_name("Original")
        .with_email("original@factory.test");
    seed.additional_fields = [("label".into(), "seed".into())].into();
    let original = store.create_user(seed).await?;
    assert_eq!(
        receiver.try_iter().collect::<Vec<_>>(),
        ["input", "later", "output"]
    );
    let stored = store
        .get_user_by_id(original.id.typed()?)
        .await?
        .ok_or_else(|| AuthError::internal("Original user is missing before rejected writes"))?;
    assert_eq!(receiver.try_iter().collect::<Vec<_>>(), ["output"]);
    assert_factory_error(
        store
            .create_user(
                CreateUser::new()
                    .with_name("Rejected")
                    .with_email("rejected@factory.test"),
            )
            .await,
    );
    assert_eq!(receiver.try_iter().collect::<Vec<_>>(), ["factory"]);
    assert!(
        store
            .get_user_by_email("rejected@factory.test")
            .await?
            .is_none()
    );
    assert_factory_error(
        store
            .update_user(
                original.id.typed()?,
                UpdateUser {
                    name: Some("Changed".into()).into(),
                    ..Default::default()
                },
            )
            .await,
    );
    assert_eq!(receiver.try_iter().collect::<Vec<_>>(), ["factory"]);
    assert_eq!(
        store.get_user_by_id(original.id.typed()?).await?,
        Some(stored)
    );
    assert_eq!(receiver.try_iter().collect::<Vec<_>>(), ["output"]);
    Ok(())
}
