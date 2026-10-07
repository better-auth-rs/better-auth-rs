use super::*;
use tracing::{Subscriber, field::Visit};
use tracing_subscriber::{Layer, layer::Context};

#[derive(Clone, Default)]
pub(super) struct Events(Arc<Mutex<Vec<Value>>>);

#[expect(
    clippy::expect_used,
    reason = "Tracing callbacks cannot return errors; recorder poisoning must fail the test"
)]
impl Events {
    fn push(&self, value: Value) {
        self.0
            .lock()
            .expect("Member join recorder available")
            .push(value);
    }

    pub(super) fn take(&self) -> Vec<Value> {
        std::mem::take(&mut *self.0.lock().expect("Member join recorder available"))
    }
}

#[derive(Default)]
struct SpanName(Option<String>);

impl Visit for SpanName {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "otel.name" {
            self.0 = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
}

impl<S: Subscriber> Layer<S> for Events {
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        _: &tracing::Id,
        _: Context<'_, S>,
    ) {
        if attributes.metadata().target() != "better-auth" {
            return;
        }
        let mut name = SpanName::default();
        attributes.record(&mut name);
        let Some(name) = name.0 else {
            return;
        };
        let Some(query) = name.strip_prefix("db ") else {
            return;
        };
        let Some((operation, model)) = query.split_once(' ') else {
            return;
        };
        let model = match model {
            "member_join_user" => "user",
            "member_join_member" => "member",
            name => name,
        };
        self.push(json!(["query", operation, model]));
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    model: String,
    field: String,
}

fn field(
    model: &str,
    name: &str,
    declaration: &Value,
    scenario: &Scenario,
    events: Option<&Events>,
) -> AuthResult<UserFieldConfig> {
    let references = declaration
        .get("references")
        .map(|value| {
            serde_json::from_value::<Reference>(value.clone()).map(|reference| UserFieldReference {
                model: reference.model,
                field: reference.field,
            })
        })
        .transpose()?;
    let transform = events.map(|events| {
        let events = events.clone();
        let label = format!("{model}.{name}");
        let failure = scenario.failure.clone();
        FieldTransforms {
            output: Some(UserFieldTransform::new(move |value| {
                events.push(json!(["output", label, values::observe(&value)?]));
                if failure.as_deref() == Some(label.as_str()) {
                    return Err(AuthResponse::json(
                        400,
                        &json!({
                            "code": "MEMBER_JOIN_OUTPUT_REJECTED",
                            "message": "Member join output callback rejected",
                        }),
                    )?
                    .with_header("x-member-join-callback", "original")
                    .into());
                }
                Ok(value)
            })),
            ..Default::default()
        }
    });
    Ok(UserFieldConfig {
        required: Some(false),
        field_name: declaration
            .get("fieldName")
            .and_then(Value::as_str)
            .map(str::to_owned),
        unique: declaration.get("unique").and_then(Value::as_bool),
        references,
        transform,
        ..Default::default()
    })
}

fn fields(
    model: &str,
    baseline: Value,
    overrides: &serde_json::Map<String, Value>,
    scenario: &Scenario,
    events: Option<&Events>,
) -> AuthResult<UserConfig> {
    let mut declarations = baseline
        .as_object()
        .cloned()
        .ok_or_else(|| AuthError::internal("Expected member join declarations"))?;
    for (name, replacement) in overrides {
        let current = declarations
            .entry(name.clone())
            .or_insert_with(|| json!({}));
        current
            .as_object_mut()
            .ok_or_else(|| AuthError::internal("Expected baseline field declaration"))?
            .extend(
                replacement
                    .as_object()
                    .ok_or_else(|| AuthError::internal("Expected replacement field declaration"))?
                    .clone(),
            );
    }
    Ok(UserConfig {
        additional_fields: Some(
            declarations
                .iter()
                .map(|(name, declaration)| {
                    Ok((
                        name.clone(),
                        field(model, name, declaration, scenario, events)?,
                    ))
                })
                .collect::<AuthResult<_>>()?,
        ),
    })
}

pub(super) fn config(
    scenario: &Scenario,
    joins: bool,
    events: Option<&Events>,
) -> AuthResult<AuthConfig> {
    let mut config = AuthConfig::default();
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.advanced.database.joins = Some(joins);
    config.advanced.database.default_find_many_limit = Some(scenario.limit()?.unwrap_or(100.0));
    config.user = fields(
        "user",
        json!({
            "image": {}, "name": {}, "memberRef": {"fieldName": "stored_member_ref"},
        }),
        &scenario.user_fields,
        scenario,
        events,
    )?;
    Ok(config)
}

pub(super) fn organization_fields(
    scenario: &Scenario,
    events: Option<&Events>,
) -> AuthResult<OrganizationFields> {
    Ok(OrganizationFields {
        member: fields(
            "member",
            json!({
                "label": {}, "detail": {}, "role": {}, "ownerRef": {"fieldName": "stored_owner_ref"},
            }),
            &scenario.member_fields,
            scenario,
            events,
        )?,
        ..Default::default()
    })
}
