use better_auth_core::{
    AuthConfig, AuthResult, AuthStore, CreateAccount, CreateUser, CreateVerification, FieldMap,
    UpdateAccount,
    id::{IdGeneration, IdGenerator},
    store::{EphemeralStore, RuntimeStore, StatelessSchema, database_hooks::VerificationUpdate},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
        UserFieldType,
    },
};
use serde_json::{Map, Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

type Trace = Arc<Mutex<Vec<Value>>>;
type Store = dyn AuthStore<StatelessSchema>;

#[derive(Clone, Copy)]
enum Family {
    Account,
    Verification,
}

impl Family {
    fn name(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Verification => "verification",
        }
    }

    fn configure(self, config: &mut AuthConfig, fields: &UserConfig) {
        match self {
            Self::Account => config.account.additional_fields = fields.fields().clone(),
            Self::Verification => config.verification.additional_fields = fields.fields().clone(),
        }
    }
}

#[derive(Clone, Copy)]
enum Scenario {
    Display,
    SerialReference,
    ArrayReference,
}

impl Scenario {
    fn name(self) -> &'static str {
        match self {
            Self::Display => "display",
            Self::SerialReference => "serial-reference",
            Self::ArrayReference => "array-reference",
        }
    }
}

#[expect(
    clippy::expect_used,
    reason = "A poisoned trace means the ordinary callback contract cannot continue"
)]
fn event(events: &Trace, value: Value) {
    events.lock().expect("display trace lock").push(value);
}

fn fields(scenario: Scenario, events: Option<&Trace>) -> UserConfig {
    let entries = match scenario {
        Scenario::Display => vec![
            ("settings", "stored_settings", UserFieldType::Json),
            ("labels", "stored_labels", UserFieldType::StringArray),
            ("displayOrder", "stored_order", UserFieldType::NumberArray),
        ],
        Scenario::SerialReference => {
            vec![("displayRefs", "stored_display_refs", UserFieldType::Json)]
        }
        Scenario::ArrayReference => vec![(
            "displayRefs",
            "stored_display_refs",
            UserFieldType::StringArray,
        )],
    };
    UserConfig {
        additional_fields: Some(
            entries
                .into_iter()
                .map(|(name, alias, field_type)| {
                    let reference = !matches!(scenario, Scenario::Display);
                    let transform = events.map(|events| {
                        let input = events.clone();
                        let output = events.clone();
                        FieldTransforms {
                            input: Some(UserFieldTransform::new(move |value| {
                                event(&input, json!(["input", name, value.json()?]));
                                Ok(value)
                            })),
                            output: Some(UserFieldTransform::new(move |value| {
                                event(&output, json!(["output", name, value.json()?]));
                                Ok(value)
                            })),
                        }
                    });
                    (
                        name.into(),
                        UserFieldConfig {
                            field_type,
                            field_name: Some(alias.into()),
                            required: Some(false),
                            references: reference.then(|| UserFieldReference {
                                model: "user".into(),
                                field: "id".into(),
                                ..Default::default()
                            }),
                            transform,
                            ..Default::default()
                        },
                    )
                })
                .collect(),
        ),
    }
}

fn config(scenario: Scenario) -> AuthConfig {
    let mut config = AuthConfig::new("ordinary-memory-record-fields-secret-at-least-32-characters")
        .base_url("http://memory-record-fields.test");
    config.advanced.database.generate_id = match scenario {
        Scenario::Display => None,
        Scenario::SerialReference => Some(IdGeneration::Serial),
        Scenario::ArrayReference => {
            let sequence = AtomicUsize::new(0);
            Some(IdGeneration::Custom(IdGenerator::new(move |request| {
                Ok(Some(format!(
                    "display-{}-{}",
                    request.model,
                    sequence.fetch_add(1, Ordering::SeqCst) + 1
                )))
            })))
        }
    };
    config
}

fn display_input(updated: bool) -> Map<String, Value> {
    if updated {
        Map::from_iter([
            ("settings".into(), json!({"theme":"dark", "compact":false})),
            ("labels".into(), json!(["updated"])),
            ("displayOrder".into(), json!([3])),
        ])
    } else {
        Map::from_iter([
            ("settings".into(), json!({"theme":"light", "compact":true})),
            ("labels".into(), json!(["first", "second"])),
            ("displayOrder".into(), json!([1, 2])),
        ])
    }
}

async fn seed(store: &Store) -> AuthResult<Vec<String>> {
    let mut ids = Vec::new();
    for label in ["first", "second"] {
        let row = store
            .create_user(
                CreateUser::new()
                    .with_name(format!("{label} display seed"))
                    .with_email(format!("{label}@memory-record-fields.test")),
            )
            .await?;
        ids.push(row.id.typed()?.clone());
    }
    Ok(ids)
}

#[expect(
    clippy::expect_used,
    reason = "The fixed ordinary fixture timestamp must parse"
)]
async fn create(
    store: &Store,
    family: Family,
    owner: &str,
    extras: Map<String, Value>,
) -> AuthResult<(String, Value)> {
    let extras = FieldMap::from_json(extras)?;
    match family {
        Family::Account => {
            let row = store
                .create_account(CreateAccount {
                    user_id: owner.to_owned().into(),
                    provider_id: "ordinary".into(),
                    account_id: "display-row".into(),
                    additional_fields: extras,
                    ..Default::default()
                })
                .await?;
            Ok((
                row.id.typed()?.clone(),
                Value::Object(row.additional_fields.json()?),
            ))
        }
        Family::Verification => {
            let row = store
                .create_verification(CreateVerification {
                    identifier: "ordinary-display".into(),
                    value: "display-value".into(),
                    expires_at: "2100-01-01T00:00:00Z"
                        .parse::<chrono::DateTime<chrono::Utc>>()
                        .expect("fixed ordinary fixture timestamp parses")
                        .into(),
                    additional_fields: extras,
                    ..Default::default()
                })
                .await?;
            Ok((
                row.id.typed()?.clone(),
                Value::Object(row.additional_fields.json()?),
            ))
        }
    }
}

#[expect(
    clippy::expect_used,
    reason = "The contract reads only a record created by the same ordinary fixture"
)]
async fn read(store: &Store, family: Family) -> AuthResult<Value> {
    let fields = match family {
        Family::Account => {
            store
                .get_account("ordinary", "display-row")
                .await?
                .expect("ordinary display account exists")
                .additional_fields
        }
        Family::Verification => {
            store
                .get_verification_by_identifier("ordinary-display")
                .await?
                .expect("ordinary display verification exists")
                .additional_fields
        }
    };
    Ok(Value::Object(fields.json()?))
}

#[expect(
    clippy::expect_used,
    reason = "The ordinary update must return the fixture record"
)]
async fn update(store: &Store, family: Family, id: &str) -> AuthResult<Value> {
    let fields = match family {
        Family::Account => {
            store
                .update_account(
                    id,
                    UpdateAccount {
                        additional_fields: FieldMap::from_json(display_input(true))?,
                        ..Default::default()
                    },
                )
                .await?
                .additional_fields
        }
        Family::Verification => {
            store
                .update_verification(
                    "ordinary-display",
                    VerificationUpdate {
                        additional_fields: FieldMap::from_json(display_input(true))?,
                        ..Default::default()
                    },
                )
                .await?
                .expect("ordinary display update returns a record")
                .additional_fields
        }
    };
    Ok(Value::Object(fields.json()?))
}

#[expect(
    clippy::expect_used,
    reason = "The fixed seed and complete callback trace must remain available"
)]
async fn observe(family: Family, scenario: Scenario) -> AuthResult<Value> {
    let events = Trace::default();
    let mut config = config(scenario);
    family.configure(&mut config, &fields(scenario, Some(&events)));
    let mut raw_config = config.clone();
    let mut raw_fields = fields(scenario, None);
    for (name, field) in raw_fields.fields_mut() {
        field.references = None;
        if name == "settings" {
            field.field_type = UserFieldType::String;
        } else if name == "displayRefs" {
            field.field_type = UserFieldType::StringArray;
        }
    }
    family.configure(&mut raw_config, &raw_fields);
    let store = EphemeralStore::new(Arc::new(config));
    let raw = store.with_runtime(Arc::new(raw_config), Vec::new(), Default::default())?;
    let store: Arc<Store> = Arc::new(store);
    let users = seed(store.as_ref()).await?;
    let extras = match scenario {
        Scenario::Display => display_input(false),
        Scenario::SerialReference | Scenario::ArrayReference => {
            Map::from_iter([("displayRefs".into(), json!(users))])
        }
    };
    event(&events, json!(["operation", "create"]));
    let (id, created) = create(
        store.as_ref(),
        family,
        users.first().expect("first seed user exists"),
        extras,
    )
    .await?;
    event(&events, json!(["operation", "read"]));
    let read_value = read(store.as_ref(), family).await?;
    let result = if matches!(scenario, Scenario::Display) {
        event(&events, json!(["operation", "update"]));
        let updated = update(store.as_ref(), family, &id).await?;
        event(&events, json!(["operation", "reread"]));
        let reread = read(store.as_ref(), family).await?;
        json!({"created":created, "read":read_value, "updated":updated, "reread":reread})
    } else {
        json!({"created":created, "read":read_value})
    };
    let stored = read(raw.as_ref(), family).await?;
    Ok(json!({
        "model":family.name(),
        "scenario":scenario.name(),
        "events":events.lock().expect("display trace lock").clone(),
        "result":result,
        "stored":stored,
    }))
}

async fn contract() -> Result<(), Box<dyn std::error::Error>> {
    let expected: Value = serde_json::from_str(include_str!(
        "fixtures/memory-record-representation-1.7.6.json"
    ))?;
    let mut cases = Vec::new();
    for family in [Family::Account, Family::Verification] {
        for scenario in [
            Scenario::Display,
            Scenario::SerialReference,
            Scenario::ArrayReference,
        ] {
            cases.push(observe(family, scenario).await?);
        }
    }
    assert_eq!(json!({"version":"1.7.6", "cases":cases}), expected);
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "Fixture setup errors and complete contract differences must fail this test"
)]
async fn memory_account_and_verification_display_fields_match_pinned_representations() {
    contract()
        .await
        .expect("Memory record representation contract passes");
}
