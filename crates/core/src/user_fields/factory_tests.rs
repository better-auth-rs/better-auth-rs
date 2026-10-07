use super::*;
use crate::{AuthConfig, AuthStore, CreateUser, UpdateUser, UserView, store::EphemeralStore};
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
#[expect(
    clippy::panic_in_result_fn,
    reason = "The test propagates setup errors and asserts the original callback error and complete event sequence."
)]
fn factory_errors_stop_public_input_and_synthetic_output() -> AuthResult<()> {
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
        assert_factory_error(fields.parse_input(&input, true));
        assert_eq!(receiver.try_iter().collect::<Vec<_>>(), ["factory"]);
        assert_factory_error(UserView::synthetic_output(
            FieldMap::new(),
            &fields,
            &Default::default(),
        ));
        assert_eq!(receiver.try_iter().collect::<Vec<_>>(), ["factory"]);
    }
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
#[expect(
    clippy::panic_in_result_fn,
    reason = "The test propagates store errors and asserts that rejected writes preserve rows and callback order."
)]
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
        Some(original)
    );
    assert_eq!(receiver.try_iter().collect::<Vec<_>>(), ["output"]);
    Ok(())
}
