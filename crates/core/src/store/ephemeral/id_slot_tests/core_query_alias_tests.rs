#![expect(
    clippy::indexing_slicing,
    reason = "Fixture indexing must fail when an expected record or property is missing."
)]

use super::*;

mod operations;

const OPERATIONS: [(&str, &str); 12] = [
    ("user", "findOne"),
    ("user", "update"),
    ("user", "delete"),
    ("user", "findMany-in"),
    ("user", "list-count-id"),
    ("user", "list-count-_id"),
    ("user", "list-count-search-id"),
    ("account", "update"),
    ("account", "updateMany-id"),
    ("account", "updateMany-provider-id"),
    ("account", "delete"),
    ("verification", "delete"),
];
const CHANGED_AT: &str = "2031-01-02T03:04:05.000Z";

fn configured_fields<'a>(
    config: &'a mut AuthConfig,
    model: &str,
) -> AuthResult<&'a mut IndexMap<String, UserFieldConfig>> {
    match model {
        "user" => Ok(config.user.fields_mut()),
        "account" => Ok(&mut config.account.additional_fields),
        "verification" => Ok(&mut config.verification.additional_fields),
        _ => Err(AuthError::internal("Unknown core ID alias model")),
    }
}

pub(super) fn configured_writer(model: &str, serial: bool) -> AuthResult<EphemeralStore> {
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(if serial {
        IdGeneration::Serial
    } else {
        IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(format!("{}-query-id", request.model)))
        }))
    });
    let _ =
        configured_fields(&mut config, model)?.insert("label".into(), UserFieldConfig::default());
    Ok(EphemeralStore::new(Arc::new(config)))
}

pub(super) fn configured_reader(
    writer: &EphemeralStore,
    model: &str,
    trace: &Events,
) -> AuthResult<EphemeralStore> {
    let mut config = (*writer.config).clone();
    let input_trace = trace.clone();
    let output_trace = trace.clone();
    let fields = configured_fields(&mut config, model)?;
    *fields = [
        (
            "id".into(),
            UserFieldConfig {
                field_name: Some("old_id".into()),
                ..Default::default()
            },
        ),
        (
            "label".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        record(
                            &input_trace,
                            json!(["input", "label", required(value.json()?)?]),
                        )?;
                        Ok(value)
                    })),
                    output: Some(UserFieldTransform::new(move |value| {
                        record(
                            &output_trace,
                            json!(["output", "label", required(value.json()?)?]),
                        )?;
                        Ok(value)
                    })),
                }),
                ..Default::default()
            },
        ),
    ]
    .into();
    fresh_reader(writer, Arc::new(config))
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract rejects unrelated table mutations while propagating snapshot errors."
)]
pub(super) fn core_memory(store: &EphemeralStore) -> AuthResult<JsonValue> {
    let state = store.operation(|operation| operation.capture_state())?;
    let mut result = serde_json::Map::new();
    for model in state.keys() {
        let rows = state.fixture_table(&model).snapshot()?;
        if ["user", "session", "account", "verification"].contains(&model.as_str()) {
            let rows = rows
                .into_iter()
                .map(|row| observe(row, false))
                .collect::<AuthResult<Vec<_>>>()?;
            let _ = result.insert(model, json!(rows));
        } else {
            assert!(rows.is_empty(), "Unexpected write to {model}");
        }
    }
    Ok(result.into())
}

pub(super) fn revive_fields(value: &JsonValue) -> AuthResult<FieldMap> {
    required(value.as_object())?
        .iter()
        .map(|(name, value)| {
            let value = match value.get("type").and_then(JsonValue::as_str) {
                Some("undefined") => Value::Undefined,
                Some("date") => {
                    date(required(value.get("value").and_then(JsonValue::as_str))?)?.into()
                }
                _ => Value::from_json(value.clone())?,
            };
            Ok((name.clone(), value))
        })
        .collect()
}

async fn create_record(
    store: &EphemeralStore,
    model: &str,
    fields: FieldMap,
) -> AuthResult<FieldMap> {
    match model {
        "user" => required(store.create_user_fields_optional(fields).await?)?.field_values(),
        "account" => required(
            store
                .create_account_optional(CreateAccount {
                    field_order: fields.keys().cloned().collect(),
                    additional_fields: fields,
                    ..Default::default()
                })
                .await?,
        )?
        .field_values(),
        "verification" => required(
            store
                .create_verification_optional(CreateVerification {
                    field_order: fields.keys().cloned().collect(),
                    additional_fields: fields,
                    ..Default::default()
                })
                .await?,
        )?
        .field_values(),
        _ => Err(AuthError::internal("Unknown core ID alias seed model")),
    }
}

async fn seed(writer: &EphemeralStore, model: &str, expected: &JsonValue) -> AuthResult<String> {
    let input = &expected["input"];
    let seed_model = required(input["model"].as_str())?;
    let data = revive_fields(&input["data"])?;
    let observed_data = observe(data.clone(), false)?;
    let observed_input = if model == "account" && seed_model == "user" {
        json!({"model":seed_model,"forceAllowId":true,"data":observed_data})
    } else {
        json!({"model":seed_model,"data":observed_data})
    };
    let before = core_memory(writer)?;
    let result = create_record(writer, seed_model, data).await?;
    let id = required(result.get("id").and_then(Value::as_str))?.to_owned();
    let after = core_memory(writer)?;
    assert_eq!(
        json!({"input":observed_input,"before":before,"result":observe(result, false)?,"after":after}),
        *expected
    );
    Ok(id)
}

async fn verify_case(expected: &JsonValue) -> AuthResult<()> {
    let model = required(expected["model"].as_str())?;
    let operation = required(expected["operation"].as_str())?;
    let serial = required(expected["serial"].as_bool())?;
    assert_eq!(expected["idFieldName"], "old_id");
    let writer = configured_writer(model, serial)?;
    let setup = required(expected["setup"].as_array())?;
    assert_eq!(setup.len(), if model == "account" { 2 } else { 1 });
    let mut selected = None;
    for expected in setup {
        selected = Some(seed(&writer, model, expected).await?);
    }
    let id = required(selected)?;
    let trace = Events::default();
    let reader = configured_reader(&writer, model, &trace)?;
    let steps = required(expected["steps"].as_array())?;
    assert_eq!(steps.len(), 2);
    for (index, expected) in steps.iter().enumerate() {
        let (method, input) = operations::request(model, operation, &id)?;
        let before = core_memory(&writer)?;
        let result = operations::execute(&reader, model, operation, &id).await?;
        let after = core_memory(&writer)?;
        let observed_events = std::mem::take(
            &mut *trace
                .lock()
                .map_err(|_| AuthError::internal("Core ID alias event lock poisoned"))?,
        );
        assert_eq!(expected["attempt"], index + 1);
        assert_eq!(expected["method"], method);
        assert_eq!(expected["input"], input);
        assert_eq!(expected["before"], before);
        assert_eq!(expected["after"], after);
        assert_eq!(expected["events"], json!(observed_events));
        if model != "verification" {
            assert_eq!(expected["result"], result);
        }
        // Verification's public delete returns unit. The fixture retains the upstream helper's null/undefined result.
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The source fixture identifies all twenty-four public query and ID-generation combinations."
)]
async fn core_queries_preserve_first_id_aliases_and_list_count_binding_order() -> AuthResult<()> {
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/core-query-id-alias-1.7.6.json"
    )))?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["backend"], "memory");
    let cases = required(fixture["cases"].as_array())?;
    let identities: Vec<_> = cases
        .iter()
        .map(|case| json!([case["model"], case["operation"], case["serial"]]))
        .collect();
    let expected: Vec<_> = OPERATIONS
        .into_iter()
        .flat_map(|(model, operation)| {
            [false, true].map(|serial| json!([model, operation, serial]))
        })
        .collect();
    assert_eq!(identities, expected);
    for case in cases {
        verify_case(case).await?;
    }
    Ok(())
}
