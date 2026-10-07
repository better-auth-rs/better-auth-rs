use super::core::user_fields::{
    FieldTransforms, UserConfig, UserFieldConfig, UserFieldFactory, UserFieldTransform,
};
use super::*;
use serde_json::{Map, json};

type FieldCalls = Arc<Mutex<Vec<Value>>>;

fn record(calls: &FieldCalls, model: &str, kind: &str) -> AuthResult<()> {
    calls
        .lock()
        .map_err(|_| AuthError::internal("field callback capture poisoned"))?
        .push(json!({"model": model, "kind": kind}));
    Ok(())
}

fn factory(
    calls: FieldCalls,
    model: &'static str,
    kind: &'static str,
    value: &'static str,
) -> UserFieldFactory {
    Arc::new(move || {
        record(&calls, model, kind)?;
        Ok(value.into())
    })
}

fn transform(calls: FieldCalls, model: &'static str, kind: &'static str) -> UserFieldTransform {
    UserFieldTransform::new(move |value| {
        record(&calls, model, kind)?;
        Ok(value)
    })
}

fn configured_fields(unique: Option<bool>, model: &'static str, calls: &FieldCalls) -> UserConfig {
    let mut fields = UserConfig::default();
    let _ = fields.fields_mut().insert(
        "label".into(),
        UserFieldConfig {
            unique,
            default_value_fn: Some(factory(
                calls.clone(),
                model,
                "defaultValue",
                "ordinary-label",
            )),
            on_update: Some(factory(calls.clone(), model, "onUpdate", "updated-label")),
            transform: Some(FieldTransforms {
                input: Some(transform(calls.clone(), model, "input")),
                output: Some(transform(calls.clone(), model, "output")),
            }),
            ..Default::default()
        },
    );
    fields
}

#[tokio::test]
async fn unique_field_metadata_matches_real_initialization_without_callbacks() -> AuthResult<()> {
    let expected: Value = serde_json::from_str(include_str!(
        "../fixtures/telemetry-fields-unique-1.7.6.json"
    ))?;
    let mut cases = Vec::new();
    for (name, unique) in [
        ("omitted", None),
        ("false", Some(false)),
        ("true", Some(true)),
    ] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let (mut config, reports) = configuration();
        config.logger.disabled = Some(true);
        config.user = configured_fields(unique, "user", &calls);
        config.session.additional_fields =
            configured_fields(unique, "session", &calls).additional_fields;
        let _auth = BetterAuth::stateless(config).build().await?;
        let report = reports.config()?;
        let mut observed = Map::new();
        for model in ["user", "session"] {
            let fields = report.get(model).cloned().ok_or_else(|| {
                AuthError::internal(format!(
                    "initialization report has no {model} configuration"
                ))
            })?;
            let _ = observed.insert(model.into(), fields);
        }
        let callbacks = calls
            .lock()
            .map_err(|_| AuthError::internal("field callback capture poisoned"))?
            .clone();
        assert!(
            callbacks.is_empty(),
            "initialization must not invoke field callbacks: {name}: {callbacks:?}"
        );
        cases.push(json!({"name": name, "config": observed, "callbacks": callbacks}));
    }
    assert_eq!(json!({"version": "1.7.6", "cases": cases}), expected);
    Ok(())
}
