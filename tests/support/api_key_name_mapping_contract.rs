use super::contract::{Fixture, Scenario, Trace, policies};
use better_auth::__private_core::{
    AuthResult, AuthSchema, AuthStore, FieldValue,
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

#[derive(Clone, Copy)]
pub(crate) enum NameMapping {
    Default,
    Empty,
    Renamed,
}

impl NameMapping {
    pub(crate) const ALL: [Self; 3] = [Self::Default, Self::Empty, Self::Renamed];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Empty => "empty",
            Self::Renamed => "renamed",
        }
    }

    pub(crate) fn column(self) -> &'static str {
        match self {
            Self::Default | Self::Empty => "name",
            Self::Renamed => "stored_name",
        }
    }
}

#[expect(
    clippy::expect_used,
    reason = "The mapped name trace must retain each input, output, and onUpdate callback"
)]
fn name_mapping_policies(
    mapping: NameMapping,
    events: Option<Trace>,
    failure: Arc<AtomicU8>,
) -> UserConfig {
    let mut config = policies(events.clone(), failure.clone());
    let mut field = UserFieldConfig {
        field_name: match mapping {
            NameMapping::Default => None,
            NameMapping::Empty => Some(String::new()),
            NameMapping::Renamed => Some("stored_name".into()),
        },
        required: Some(false),
        ..Default::default()
    };
    if let Some(events) = events {
        let updates = events.clone();
        field.on_update = Some(Arc::new(move || {
            updates
                .lock()
                .expect("mapped name trace lock")
                .push(json!(["onUpdate", "name"]));
            Ok(" Renewed ".into())
        }));
        let inputs = events.clone();
        let input_failure = failure.clone();
        field.transform = Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                inputs.lock().expect("mapped name trace lock").push(json!([
                    "input",
                    "name",
                    value.json()?.unwrap_or(json!({"type":"undefined"})),
                ]));
                if input_failure.load(Ordering::SeqCst) == 1 {
                    return Err(better_auth::__private_core::AuthError::internal(
                        "ordinary API Key input error",
                    ));
                }
                Ok(match value {
                    FieldValue::String(value) => value.trim().into(),
                    value => value,
                })
            })),
            output: Some(UserFieldTransform::new(move |value| {
                events.lock().expect("mapped name trace lock").push(json!([
                    "output",
                    "name",
                    value.json()?.unwrap_or(json!({"type":"undefined"})),
                ]));
                if failure.load(Ordering::SeqCst) == 2 {
                    return Err(better_auth::__private_core::AuthError::internal(
                        "ordinary API Key output error",
                    ));
                }
                Ok(match value {
                    FieldValue::String(value) => format!("{value}:out").into(),
                    value => value,
                })
            })),
        });
    }
    let _ = config.fields_mut().shift_insert(0, "name".into(), field);
    config
}

pub(crate) async fn observe_name_mapping<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    mapping: NameMapping,
    scenario: Scenario,
) -> AuthResult<Value> {
    let fixture = Fixture::new(raw, true, |events, failure| {
        name_mapping_policies(mapping, events, failure)
    })
    .await?;
    match scenario {
        Scenario::Operations => fixture.operations().await,
        Scenario::Failure { operation, phase } => fixture.error(operation, phase).await,
    }
}
