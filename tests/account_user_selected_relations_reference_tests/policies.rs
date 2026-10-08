use super::*;
use tracing::{Subscriber, field::Visit};
use tracing_subscriber::{Layer, layer::Context};

#[derive(Clone, Default)]
pub(super) struct Events(Arc<Mutex<Vec<Value>>>);

#[expect(
    clippy::expect_used,
    reason = "Tracing callbacks cannot return errors; recorder poisoning must fail the test."
)]
impl Events {
    fn push(&self, event: Value) {
        self.0
            .lock()
            .expect("Account/User recorder available")
            .push(event);
    }

    pub(super) fn take(&self) -> Vec<Value> {
        std::mem::take(&mut *self.0.lock().expect("Account/User recorder available"))
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
        // SeaORM spans name the bundled tables; the oracle names logical models.
        let model = match model {
            "users" => "user",
            "accounts" => "account",
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
                ..Default::default()
            })
        })
        .transpose()?;
    let label = format!("{model}.{name}");
    let replacement = scenario
        .replacements
        .get(&label)
        .map(|value| {
            let [before, after]: [Value; 2] = serde_json::from_value(value.clone())?;
            Ok::<_, AuthError>((values::revive(&before)?, values::revive(&after)?))
        })
        .transpose()?;
    let transform = events.map(|events| {
        let events = events.clone();
        FieldTransforms {
            output: Some(UserFieldTransform::new(move |value| {
                events.push(json!(["output", label, values::observe(&value)?]));
                Ok(match &replacement {
                    Some((before, after)) if value == *before => after.clone(),
                    _ => value,
                })
            })),
            ..Default::default()
        }
    });
    Ok(UserFieldConfig {
        required: Some(false),
        unique: declaration.get("unique").and_then(Value::as_bool),
        references,
        transform,
        ..Default::default()
    })
}

fn fields(
    model: &str,
    defaults: Value,
    overrides: &serde_json::Map<String, Value>,
    scenario: &Scenario,
    events: Option<&Events>,
) -> AuthResult<UserConfig> {
    let mut declarations = defaults
        .as_object()
        .cloned()
        .ok_or_else(|| AuthError::internal("Expected Account/User field declarations"))?;
    // Upstream replaces each declaration, so an empty userId removes the default reference.
    declarations.extend(overrides.clone());
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
    config.advanced.database.default_find_many_limit = Some(scenario.limit.unwrap_or(100.0));
    config.user = fields(
        "user",
        json!({"image": {}, "name": {}}),
        &scenario.user_fields,
        scenario,
        events,
    )?;
    config.account.additional_fields = fields("account", json!({
        "accessToken": {}, "accountId": {}, "userId": {"references": {"model": "user", "field": "id"}},
    }), &scenario.account_fields, scenario, events)?.additional_fields.ok_or_else(|| AuthError::internal("Missing Account field declarations"))?;
    Ok(config)
}
