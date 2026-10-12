#![expect(
    clippy::expect_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]

use super::*;

fn query_reader(writer: &EphemeralStore, model: Model, events: &Events) -> EphemeralStore {
    let input_events = events.clone();
    let output_events = events.clone();
    let mut reader = writer.clone();
    let fields = crate::plugin_runtime::ModelFields::default();
    fields
        .bind_execution_gate(reader.operations.clone())
        .expect("Fresh fields must bind to the reader's Memory gate");
    reader.model_fields = fields;
    reader.model_fields.register(
        model.role(),
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
                    (
                        "label".into(),
                        UserFieldConfig {
                            transform: Some(FieldTransforms {
                                input: Some(UserFieldTransform::new(move |value| {
                                    record(
                                        &input_events,
                                        json!(["input", "label", required(value.json()?)?]),
                                    )?;
                                    Ok(value)
                                })),
                                output: Some(UserFieldTransform::new(move |value| {
                                    record(
                                        &output_events,
                                        json!(["output", "label", required(value.json()?)?]),
                                    )?;
                                    Ok(value)
                                })),
                            }),
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
            ),
        },
    );
    reader
}

async fn query(
    model: Model,
    reader: &EphemeralStore,
    operation: &str,
    id: &str,
) -> AuthResult<JsonValue> {
    let id = id.into();
    let record = match operation {
        "findOne" => match model {
            Model::Jwk => reader.get_jwk_record(&id).await?,
            Model::Wallet => reader.get_wallet_address_record(&id).await?,
        },
        "update" => {
            let update = [("label".into(), "updated".into())].into();
            match model {
                Model::Jwk => reader.update_jwk_record(&id, update).await?,
                Model::Wallet => reader.update_wallet_address_record(&id, update).await?,
            }
        }
        "delete" => {
            match model {
                Model::Jwk => reader.delete_jwk_record(&id).await?,
                Model::Wallet => reader.delete_wallet_address_record(&id).await?,
            }
            return Ok(json!({"type":"undefined"}));
        }
        _ => return Err(AuthError::internal("Unknown ID alias fixture operation")),
    };
    record
        .map(|record| observe_fields(record, false))
        .transpose()
        .map(|value| value.unwrap_or(JsonValue::Null))
}

async fn capture_query_alias(model: Model, serial: bool, operation: &str) -> AuthResult<JsonValue> {
    let mut config = AuthConfig::default();
    config.advanced.database.generate_id = Some(if serial {
        IdGeneration::Serial
    } else {
        IdGeneration::Custom(IdGenerator::new(|request| {
            Ok(Some(format!("{}-query-id", request.model)))
        }))
    });
    let mut writer = EphemeralStore::new(Arc::new(config));
    writer.model_fields.register(
        model.role(),
        UserConfig {
            additional_fields: Some([("label".into(), UserFieldConfig::default())].into()),
        },
    );
    let mut setup = Vec::new();
    if matches!(model, Model::Wallet) {
        setup.push(seed_owner(&writer, serial).await?);
    }
    let owner = if serial { "1" } else { "ordinary-owner" };
    let input = model.request("selected", owner)?;
    let before = observe_memory(&writer)?;
    let seeded = model.create(&writer, "selected", owner).await?;
    setup.push(
        json!({"input":input,"before":before,"result":seeded,"after":observe_memory(&writer)?}),
    );
    let id = required(seeded.get("id").and_then(JsonValue::as_str))?;
    let events = Events::default();
    let reader = query_reader(&writer, model, &events);
    let mut steps = Vec::new();
    for attempt in [1, 2] {
        let input = if operation == "update" {
            json!({"model":model.name(),"where":[{"field":"id","value":id}],"update":{"label":"updated"}})
        } else {
            json!({"model":model.name(),"where":[{"field":"id","value":id}]})
        };
        let before = observe_memory(&writer)?;
        let result = query(model, &reader, operation, id).await?;
        let after = observe_memory(&writer)?;
        let events = std::mem::take(&mut *events_lock(&events)?);
        steps.push(json!({"attempt":attempt,"input":input,"before":before,"result":result,"events":events,"after":after}));
    }
    Ok(
        json!({"model":model.name(),"serial":serial,"operation":operation,"idFieldName":"old_id","setup":setup,"steps":steps}),
    )
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract compares every setup operation, field callback, returned value, and complete database snapshot."
)]
async fn plugin_queries_retain_first_id_alias_across_fresh_runtimes() -> AuthResult<()> {
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/adapter-query-id-alias-1.7.6.json"
    )))?;
    let mut cases = Vec::new();
    for model in [Model::Jwk, Model::Wallet] {
        for serial in [false, true] {
            for operation in ["findOne", "update", "delete"] {
                cases.push(capture_query_alias(model, serial, operation).await?);
            }
        }
    }
    assert_eq!(
        json!({"version":"1.7.6","backend":"memory","cases":cases}),
        fixture
    );
    Ok(())
}
