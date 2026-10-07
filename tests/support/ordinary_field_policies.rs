use better_auth::__private_core::{
    AuthError, FieldValue,
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
    },
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, Ordering},
};

pub(crate) type Trace = Arc<Mutex<Vec<Value>>>;

#[expect(
    clippy::expect_used,
    reason = "The trace mutex must remain unpoisoned so the contract retains every callback event"
)]
fn push(events: &Trace, value: Value) {
    events.lock().expect("Field trace lock").push(value);
}

#[expect(
    clippy::expect_used,
    reason = "The trace mutex must remain unpoisoned so each operation retains its complete callback sequence"
)]
pub(crate) fn take(events: &Trace) -> Vec<Value> {
    std::mem::take(&mut *events.lock().expect("Field trace lock"))
}

pub(crate) fn policies(
    model: &'static str,
    events: Option<Trace>,
    failure: Arc<AtomicU8>,
) -> UserConfig {
    let mut fields = UserConfig {
        additional_fields: Some(
            [
                (
                    "label".into(),
                    UserFieldConfig {
                        field_name: Some("stored_label".into()),
                        required: Some(false),
                        default_value: Some(" Default ".into()),
                        ..Default::default()
                    },
                ),
                (
                    "activatedAt".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Date,
                        field_name: Some("stored_activation".into()),
                        required: Some(false),
                        ..Default::default()
                    },
                ),
                (
                    "details".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Json,
                        field_name: Some("stored_details".into()),
                        required: Some(false),
                        ..Default::default()
                    },
                ),
                (
                    "revision".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Number,
                        field_name: Some("stored_revision".into()),
                        required: Some(false),
                        default_value_fn: Some(Arc::new({
                            let events = events.clone();
                            move || {
                                if let Some(events) = &events {
                                    push(events, json!(["default", "revision"]));
                                }
                                1.5.into()
                            }
                        })),
                        on_update: Some(Arc::new({
                            let events = events.clone();
                            move || {
                                if let Some(events) = &events {
                                    push(events, json!(["onUpdate", "revision"]));
                                }
                                2.5.into()
                            }
                        })),
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        ),
    };
    if let Some(events) = events {
        for (name, field) in fields.fields_mut() {
            let input_events = events.clone();
            let output_events = events.clone();
            let input_name = name.clone();
            let output_name = name.clone();
            let input_failure = failure.clone();
            let output_failure = failure.clone();
            field.transform = Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    push(
                        &input_events,
                        json!([
                            "input",
                            input_name,
                            value.json()?.unwrap_or(json!({"type":"undefined"}))
                        ]),
                    );
                    if input_name == "revision" && input_failure.load(Ordering::SeqCst) == 1 {
                        return Err(AuthError::internal(format!("ordinary {model} input error")));
                    }
                    Ok(match value {
                        FieldValue::String(value) if input_name == "label" => value.trim().into(),
                        value => value,
                    })
                })),
                output: Some(UserFieldTransform::new(move |value| {
                    push(
                        &output_events,
                        json!([
                            "output",
                            output_name,
                            value.json()?.unwrap_or(json!({"type":"undefined"}))
                        ]),
                    );
                    if output_name == "label" && output_failure.load(Ordering::SeqCst) == 2 {
                        return Err(AuthError::internal(format!(
                            "ordinary {model} output error"
                        )));
                    }
                    Ok(match value {
                        FieldValue::String(value) if output_name == "label" => {
                            format!("{value}:out").into()
                        }
                        value => value,
                    })
                })),
            });
        }
    }
    fields
}
