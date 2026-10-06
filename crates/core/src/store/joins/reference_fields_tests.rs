use super::*;
use indexmap::IndexMap;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    model: String,
    field: String,
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Field {
    field_name: Option<String>,
    references: Option<Reference>,
}

impl From<Field> for UserFieldConfig {
    fn from(field: Field) -> Self {
        Self {
            field_name: field.field_name,
            references: field.references.map(|reference| UserFieldReference {
                model: reference.model,
                field: reference.field,
            }),
            ..Default::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Operation {
    Accounts,
    Owner,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Case {
    name: String,
    #[serde(default)]
    user_fields: IndexMap<String, Field>,
    #[serde(default)]
    account_fields: IndexMap<String, Field>,
    #[serde(default)]
    errors: IndexMap<String, String>,
    joins: bool,
    operation: Operation,
    events: Vec<Value>,
    result: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    version: String,
    cases: Vec<Case>,
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract asserts captured errors and resolved columns while propagating fixture I/O and decoding errors."
)]
fn selected_reference_fields_match_upstream() -> Result<(), Box<dyn std::error::Error>> {
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/schema-join-reference-field-1.7.6.json"),
    )?)?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.cases.len(), 52);
    for case in fixture.cases {
        let mut config = AuthConfig::default();
        config.user.fields_mut().extend(
            case.user_fields
                .into_iter()
                .map(|(name, field)| (name, field.into())),
        );
        config.account.additional_fields.extend(
            case.account_fields
                .into_iter()
                .map(|(name, field)| (name, field.into())),
        );
        let account = config.account.field_schema();
        let (base, model, joined_table, operation) = match case.operation {
            Operation::Accounts => (
                ("user", &config.user),
                ("account", &account),
                "auth_accounts",
                "accounts",
            ),
            Operation::Owner => (
                ("account", &account),
                ("user", &config.user),
                "auth_users",
                "owner",
            ),
        };
        let resolved =
            resolve_references(
                base,
                model,
                &ModelFields::default(),
                |role, name| match role {
                    EntityRole::User => name == "auth_users",
                    EntityRole::Account => name == "auth_accounts",
                    _ => false,
                },
            );
        let actual = match resolved {
            Ok((from, to)) => {
                assert_eq!(case.events.len(), 1, "{} {operation}", case.name);
                let event = case.events.first().ok_or("Missing captured read")?;
                assert_eq!(event.get(0), Some(&json!("findOne")));
                if case.joins {
                    let on = event
                        .get(1)
                        .and_then(|input| input.get("join"))
                        .and_then(|join| join.get(joined_table))
                        .and_then(|join| join.get("on"));
                    assert_eq!(
                        on,
                        Some(&json!({"from": from, "to": to})),
                        "{} {operation}",
                        case.name
                    );
                }
                Value::Null
            }
            Err(error) => {
                assert!(
                    case.events.is_empty(),
                    "Reference errors must precede reads and callbacks"
                );
                json!({"error": error.instrumentation_message()})
            }
        };
        assert_eq!(actual, case.result, "{} {operation}", case.name);
        assert_eq!(
            case.result.get("error").and_then(Value::as_str),
            case.errors.get(operation).map(String::as_str)
        );
    }
    Ok(())
}
