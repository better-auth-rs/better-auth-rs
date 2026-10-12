#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing."
)]

use super::*;
use crate::AuthRecordFields;
use crate::plugin_runtime::ModelFields;
use crate::store::{ApiKeyStore, DeviceCodeStore, PasskeyStore, TwoFactorStore, UserStore};

mod cleanup_tests;
mod operations;

const OPERATIONS: [(&str, &str, &str); 10] = [
    ("passkey", "findOne", "counter"),
    ("apikey", "decrement", "remaining"),
    ("apikey", "last-request", "lastRequest"),
    ("twoFactor", "backup-codes", "backupCodes"),
    ("twoFactor", "record-failure", "lockedUntil"),
    ("twoFactor", "reset-failures", "lockedUntil"),
    ("twoFactor", "reset-expired", "lockedUntil"),
    ("deviceCode", "claim", "userId"),
    ("deviceCode", "status-update", "status"),
    ("deviceCode", "status-delete", "status"),
];

fn role(model: &str) -> AuthResult<EntityRole> {
    match model {
        "passkey" => Ok(EntityRole::Passkey),
        "apikey" => Ok(EntityRole::ApiKey),
        "twoFactor" => Ok(EntityRole::TwoFactor),
        "deviceCode" => Ok(EntityRole::DeviceCode),
        _ => Err(AuthError::internal("Unknown atomic ID alias model")),
    }
}

fn observe_value(value: &Value) -> AuthResult<JsonValue> {
    match value {
        Value::Undefined => Ok(json!({"type":"undefined"})),
        Value::Date(_) => Ok(json!({"type":"date", "value":required(value.json()?)?})),
        value => required(value.json()?),
    }
}

fn revive_fields(value: &JsonValue) -> AuthResult<FieldMap> {
    required(value.as_object())?
        .iter()
        .map(|(name, value)| {
            let value = match value.get("type").and_then(JsonValue::as_str) {
                Some("undefined") => Value::Undefined,
                Some("date") => required(value.get("value").and_then(JsonValue::as_str))?
                    .parse::<DateTime<Utc>>()
                    .map(Value::from)
                    .map_err(|error| {
                        AuthError::internal(format!("Invalid fixture date: {error}"))
                    })?,
                _ => Value::from_json(value.clone())?,
            };
            Ok((name.clone(), value))
        })
        .collect()
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract rejects writes to every unrelated table while preserving fallible snapshot reads."
)]
fn observe_model_memory(store: &EphemeralStore, model: &str) -> AuthResult<JsonValue> {
    let state = store.operation(|op| op.capture_state())?;
    let observed = ["user", "session", "account", "verification", model];
    let mut result = serde_json::Map::new();
    for name in state.keys() {
        let rows = state.fixture_table(&name).snapshot()?;
        if observed.contains(&name.as_str()) {
            let rows = rows
                .into_iter()
                .map(|row| observe_fields(row, true))
                .collect::<AuthResult<Vec<_>>>()?;
            let _ = result.insert(name, json!(rows));
        } else {
            assert!(rows.is_empty(), "Unexpected write to {name}");
        }
    }
    Ok(result.into())
}

fn configured_writer(model: &str, serial: bool) -> EphemeralStore {
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(if serial {
        IdGeneration::Serial
    } else {
        IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(format!("{}-query-id", request.model)))
        }))
    });
    let mut fields = ModelFields::default();
    if model == "twoFactor" {
        fields.register_native_user_fields("two_factor.enabled");
    }
    let (config, _, fields) = fields.resolve(&config);
    let mut writer = EphemeralStore::new(Arc::new(config));
    fields
        .bind_execution_gate(writer.operations.clone())
        .expect("Fresh fields must bind to the writer's Memory gate");
    writer.model_fields = fields;
    writer
}

fn configured_reader(
    writer: &EphemeralStore,
    model: &str,
    field: &str,
    events: &Events,
) -> AuthResult<EphemeralStore> {
    let role = role(model)?;
    let mut declaration =
        required(ModelFields::plugin_native_fields(role).fields().get(field))?.clone();
    let input_events = events.clone();
    let output_events = events.clone();
    let input_field = field.to_owned();
    let output_field = field.to_owned();
    declaration.transform = Some(FieldTransforms {
        input: Some(UserFieldTransform::new(move |value| {
            record(
                &input_events,
                json!(["input", input_field, observe_value(&value)?]),
            )?;
            Ok(value)
        })),
        output: Some(UserFieldTransform::new(move |value| {
            record(
                &output_events,
                json!(["output", output_field, observe_value(&value)?]),
            )?;
            Ok(value)
        })),
    });
    let mut reader = writer.clone();
    let fields = ModelFields::default();
    fields.bind_execution_gate(reader.operations.clone())?;
    reader.model_fields = fields;
    if model == "twoFactor" {
        reader
            .model_fields
            .register_native_user_fields("two_factor.enabled");
    }
    reader.model_fields.register(
        role,
        UserConfig {
            additional_fields: Some(
                [
                    (
                        "id".into(),
                        UserFieldConfig {
                            field_name: Some("old_id".into()),
                            ..Default::default()
                        },
                    ),
                    (field.to_owned(), declaration),
                ]
                .into(),
            ),
        },
    );
    Ok(reader)
}

async fn create_record(
    store: &EphemeralStore,
    model: &str,
    fields: FieldMap,
) -> AuthResult<FieldMap> {
    let record = match model {
        "user" => {
            return required(store.create_user_fields_optional(fields).await?)?.field_values();
        }
        "passkey" => store.create_passkey_record(fields).await?,
        "apikey" => store.create_api_key_record(fields).await?,
        "twoFactor" => store.create_two_factor_record(fields).await?,
        "deviceCode" => store.create_device_code_record(fields).await?,
        _ => return Err(AuthError::internal("Unknown atomic fixture seed model")),
    };
    required(record)
}

async fn seed(writer: &EphemeralStore, model: &str, setup: &JsonValue) -> AuthResult<String> {
    let input = &setup["input"];
    let seed_model = required(input["model"].as_str())?;
    let fields = revive_fields(&input["data"])?;
    let data = observe_fields(fields.clone(), false)?;
    let observed_input = if seed_model == "user" {
        json!({"model":seed_model, "forceAllowId":true, "data":data})
    } else {
        json!({"model":seed_model, "data":data})
    };
    let before = observe_model_memory(writer, model)?;
    let result = create_record(writer, seed_model, fields).await?;
    let id = required(result.get("id").and_then(Value::as_str))?.to_owned();
    let after = observe_model_memory(writer, model)?;
    assert_eq!(
        json!({"input":observed_input,"before":before,"result":observe_fields(result, false)?,"after":after}),
        *setup
    );
    Ok(id)
}

async fn verify_case(expected: &JsonValue) -> AuthResult<()> {
    let model = required(expected["model"].as_str())?;
    let operation = required(expected["operation"].as_str())?;
    let field = required(expected["field"].as_str())?;
    let serial = required(expected["serial"].as_bool())?;
    assert_eq!(expected["idFieldName"], "old_id");
    let writer = configured_writer(model, serial);
    let setup = required(expected["setup"].as_array())?;
    let [owner_setup, selected_setup] = setup.as_slice() else {
        return Err(AuthError::internal(
            "Atomic ID alias fixture must seed exactly two rows",
        ));
    };
    let owner = seed(&writer, model, owner_setup).await?;
    let id = seed(&writer, model, selected_setup).await?;
    let events = Events::default();
    let reader = configured_reader(&writer, model, field, &events)?;
    let steps = required(expected["steps"].as_array())?;
    assert_eq!(steps.len(), 2);
    for (index, step) in steps.iter().enumerate() {
        let (method, input) = operations::request(model, operation, &id, &owner)?;
        let before = observe_model_memory(&writer, model)?;
        let outcome = operations::execute(&reader, operation, &id, &owner).await?;
        let after = observe_model_memory(&writer, model)?;
        let observed_events = std::mem::take(&mut *events_lock(&events)?);
        assert_eq!(step["attempt"], index + 1);
        assert_eq!(step["method"], method);
        assert_eq!(step["input"], input);
        assert_eq!(step["before"], before);
        assert_eq!(step["after"], after);
        assert_eq!(step["events"], json!(observed_events));
        outcome.verify(step, operation, model);
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The frozen source fixture defines all twenty model, operation, and ID-generation combinations."
)]
async fn plugin_business_queries_retain_the_first_id_alias() -> AuthResult<()> {
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/plugin-query-id-alias-1.7.6.json"
    )))?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["backend"], "memory");
    let cases = required(fixture["cases"].as_array())?;
    let identities: Vec<_> = cases
        .iter()
        .map(|case| {
            json!([
                case["model"],
                case["operation"],
                case["field"],
                case["serial"]
            ])
        })
        .collect();
    let expected: Vec<_> = OPERATIONS
        .into_iter()
        .flat_map(|(model, operation, field)| {
            [false, true].map(|serial| json!([model, operation, field, serial]))
        })
        .collect();
    assert_eq!(identities, expected);
    for case in cases {
        verify_case(case).await?;
    }
    Ok(())
}
