use super::*;
use better_auth_core::user_fields::{
    FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
};

pub(super) fn baseline() -> AuthConfig {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.session.expires_in = Some(chrono::Duration::seconds(3600));
    config.session.cookie_cache = None;
    config
}

pub(super) fn configured(
    scenario: &Scenario,
    joins: bool,
    events: Option<&Events>,
) -> AuthResult<AuthConfig> {
    let mut config = baseline();
    config.advanced.database.joins = Some(joins);
    let relations: Value = serde_json::from_str(include_str!(
        "../fixtures/account-user-selected-relations-1.7.6.json"
    ))?;
    let relation = relations["scenarios"]
        .as_array()
        .and_then(|scenarios| {
            scenarios
                .iter()
                .find(|value| value["name"] == scenario.relation)
        })
        .ok_or_else(|| AuthError::internal("Missing selected relation declaration"))?;
    config.user = UserConfig {
        additional_fields: Some(fields(
            "user",
            &["image", "name"],
            &relation["userFields"],
            events,
        )?),
    };
    config.account.additional_fields = fields(
        "account",
        &["accessToken", "accountId", "userId"],
        &relation["accountFields"],
        events,
    )?;
    Ok(config)
}

fn fields(
    model: &str,
    names: &[&str],
    declarations: &Value,
    events: Option<&Events>,
) -> AuthResult<indexmap::IndexMap<String, UserFieldConfig>> {
    names.iter().map(|&name| {
        let default = if model == "account" && name == "userId" {
            json!({"references": {"model": "user", "field": "id"}})
        } else { json!({}) };
        let declaration = declarations.get(name).unwrap_or(&default);
        let references = declaration.get("references").map(|reference| {
            let model = reference["model"].as_str().ok_or_else(|| AuthError::internal("Missing relation model"))?;
            let field = reference["field"].as_str().ok_or_else(|| AuthError::internal("Missing relation field"))?;
            Ok::<_, AuthError>(UserFieldReference { model: model.into(), field: field.into() })
        }).transpose()?;
        let transform = events.map(|events| {
            let events = events.clone();
            let model = model.to_owned();
            let name = name.to_owned();
            FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    events.push(json!({"kind": "output", "model": model, "field": name, "value": values::observe(&value)?}))?;
                    Ok(value)
                })),
                ..Default::default()
            }
        });
        Ok((name.into(), UserFieldConfig {
            required: Some(false), unique: declaration.get("unique").and_then(Value::as_bool),
            references, transform, ..Default::default()
        }))
    }).collect()
}
