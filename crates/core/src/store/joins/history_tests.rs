use super::*;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    version: String,
    cases: Vec<Case>,
    transactions: Vec<Transaction>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    backend: String,
    joins: bool,
    name: String,
    mode: String,
    observations: Vec<Observation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Transaction {
    backend: String,
    joins: bool,
    transaction: bool,
    warm_parent: bool,
    finish: String,
    observations: Vec<Observation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    scope: String,
    operation: String,
    #[serde(default)]
    events: Vec<Value>,
    result: Value,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/schema-join-reference-history-1.7.6.json"
    ))
    .unwrap()
}

fn config(mode: &str) -> AuthConfig {
    let mut config = AuthConfig::default();
    for name in ["id", "image"] {
        if mode == "alias" && name == "image" {
            continue;
        }
        let field = if mode == "alias" {
            UserFieldConfig {
                field_name: Some("stored_id".into()),
                ..Default::default()
            }
        } else {
            UserFieldConfig {
                references: Some(UserFieldReference {
                    model: "account".into(),
                    field: "id".into(),
                }),
                ..Default::default()
            }
        };
        let _ = config.user.fields_mut().insert(name.into(), field);
    }
    if mode == "invalid-target" {
        let _ = config.account.additional_fields.insert(
            "userId".into(),
            UserFieldConfig {
                references: Some(UserFieldReference {
                    model: "user".into(),
                    field: "missingUserField".into(),
                }),
                ..Default::default()
            },
        );
    }
    config
}

fn assert_join(
    config: &AuthConfig,
    schema: &ModelFields,
    boundary_joins: Option<bool>,
    observation: &Observation,
) {
    let account = config.account.field_schema();
    let (base, target, model) = match observation.operation.as_str() {
        "owner" => (
            (EntityRole::Account, "account", &account),
            (EntityRole::User, "user", &config.user),
            "user",
        ),
        "accounts" => (
            (EntityRole::User, "user", &config.user),
            (EntityRole::Account, "account", &account),
            "account",
        ),
        operation => panic!("Unexpected join operation: {operation}"),
    };
    let result = resolve_references(base, target, schema, |_, _| false);
    let actual = match result {
        Ok(ResolvedJoin { from, to, .. }) => {
            if let Some(joins) = boundary_joins {
                let events: Vec<_> = observation
                    .events
                    .iter()
                    .filter(|event| event[0] == "findOne")
                    .collect();
                assert_eq!(events.len(), 1);
                let event = events.first().unwrap();
                if joins {
                    assert_eq!(
                        event[1]["join"][model]["on"],
                        json!({ "from": from, "to": to })
                    );
                } else {
                    assert_eq!(event[1]["join"], json!({ "$undefined": true }));
                }
            } else {
                assert_eq!(observation.events, [json!(["query", "findOne", base.1])]);
            }
            Value::Null
        }
        Err(error) => {
            assert!(observation.events.is_empty());
            json!({ "error": error.instrumentation_message() })
        }
    };
    assert_eq!(
        actual, observation.result,
        "{}/{}",
        observation.scope, observation.operation
    );
}

#[test]
fn schema_history_boundary_references_match_pinned_capture() {
    let fixture = fixture();
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.cases.len(), 48);
    let mut paired = 0;
    for case in fixture
        .cases
        .iter()
        .filter(|case| case.backend == "boundary")
    {
        if matches!(
            case.name.as_str(),
            "input-callback-failure" | "output-without-where" | "output-callback-failure"
        ) {
            continue;
        }
        let config = config(&case.mode);
        let schema = ModelFields::default();
        for observation in &case.observations {
            let fresh;
            let active = if observation.scope == "parent" {
                &schema
            } else {
                fresh = schema.fresh_runtime();
                &fresh
            };
            match observation.operation.as_str() {
                "owner" | "accounts" => assert_join(&config, active, Some(case.joins), observation),
                "read-user" => {
                    let fields = active
                        .runtime_fields(EntityRole::User, &config.user)
                        .unwrap();
                    resolve_field("user", &fields, "name").unwrap();
                    active.canonicalize_id(EntityRole::User).unwrap();
                }
                "read-user-empty" => {}
                "read-user-invalid" => {
                    let fields = active
                        .runtime_fields(EntityRole::User, &config.user)
                        .unwrap();
                    let error = resolve_field("user", &fields, "missingUserField").unwrap_err();
                    assert_eq!(
                        json!({ "error": error.instrumentation_message() }),
                        observation.result
                    );
                    assert!(observation.events.is_empty());
                }
                operation => panic!("Unexpected boundary operation: {operation}"),
            }
        }
        assert!(config.user.fields().contains_key("id"));
        paired += 1;
    }
    assert_eq!(paired, 14);
}

#[test]
fn schema_history_runtime_lifetimes_match_pinned_transactions() {
    let fixture = fixture();
    assert_eq!(fixture.transactions.len(), 32);
    for case in fixture.transactions {
        let config = config("duplicate");
        let parent = ModelFields::default();
        let mut transaction: Option<ModelFields> = None;
        let mut nested: Option<ModelFields> = None;
        assert!(matches!(case.finish.as_str(), "commit" | "rollback"));
        assert_eq!(
            case.observations
                .iter()
                .filter(|item| item.scope == "parent" && item.operation == "read-user")
                .count(),
            usize::from(case.warm_parent)
        );
        for observation in &case.observations {
            let fresh;
            let active = match observation.scope.as_str() {
                "parent" => &parent,
                "transaction" => transaction.get_or_insert_with(|| {
                    if case.transaction {
                        parent.fresh_runtime()
                    } else {
                        parent.clone()
                    }
                }),
                "nested" => nested.get_or_insert_with(|| {
                    let current = transaction.as_ref().unwrap();
                    if case.backend == "memory" {
                        current.fresh_runtime()
                    } else {
                        current.clone()
                    }
                }),
                "fresh" => {
                    fresh = parent.fresh_runtime();
                    &fresh
                }
                scope => panic!("Unexpected transaction scope: {scope}"),
            };
            match observation.operation.as_str() {
                "owner" => assert_join(
                    &config,
                    active,
                    (case.backend == "boundary").then_some(case.joins),
                    observation,
                ),
                "read-user" => active.canonicalize_id(EntityRole::User).unwrap(),
                "transaction-result" => {}
                operation => panic!("Unexpected transaction operation: {operation}"),
            }
        }
        assert!(config.user.fields()["id"].references.is_some());
    }
}
