#![expect(
    clippy::indexing_slicing,
    reason = "Fixture indexing must fail when an expected record or property is missing."
)]

use super::*;
use crate::user_fields::{UserFieldReference, UserFieldType};

fn configured_cleanup(scenario: &JsonValue, events: &Events) -> AuthResult<EphemeralStore> {
    let mut store = configured_writer("apikey", required(scenario["serial"].as_bool())?);
    let input_events = events.clone();
    let output_events = events.clone();
    let declaration = UserFieldConfig {
        field_type: match required(scenario["type"].as_str())? {
            "date" => UserFieldType::Date,
            "json" => UserFieldType::Json,
            _ => return Err(AuthError::internal("Unknown cleanup field type")),
        },
        required: Some(false),
        field_name: Some("stored_expiry".into()),
        references: required(scenario["reference"].as_bool())?.then(|| UserFieldReference {
            model: "user".into(),
            field: "id".into(),
            ..Default::default()
        }),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                record(
                    &input_events,
                    json!(["input", "expiresAt", observe_value(&value)?]),
                )?;
                Ok(value)
            })),
            output: Some(UserFieldTransform::new(move |value| {
                record(
                    &output_events,
                    json!(["output", "expiresAt", observe_value(&value)?]),
                )?;
                Ok(value)
            })),
        }),
        ..Default::default()
    };
    store.model_fields.register(
        EntityRole::ApiKey,
        UserConfig {
            additional_fields: Some([("expiresAt".into(), declaration)].into()),
        },
    );
    Ok(store)
}

async fn verify_cleanup_case(expected: &JsonValue, current: &crate::FieldDate) -> AuthResult<()> {
    let trace = Events::default();
    let store = configured_cleanup(&expected["scenario"], &trace)?;
    let setup = required(expected["setup"].as_array())?;
    assert_eq!(setup.len(), 3);
    for expected in setup {
        let fields = revive_fields(&expected["input"]["data"])?;
        let input = json!({"model":"apikey","forceAllowId":true,"data":observe_fields(fields.clone(), false)?});
        let before = observe_model_memory(&store, "apikey")?;
        let result = create_record(&store, "apikey", fields).await?;
        let after = observe_model_memory(&store, "apikey")?;
        let observed_events = std::mem::take(&mut *events_lock(&trace)?);
        assert_eq!(
            json!({"input":input,"before":before,"result":observe_fields(result, false)?,"events":observed_events,"after":after}),
            *expected
        );
    }
    let steps = required(expected["steps"].as_array())?;
    assert_eq!(steps.len(), 2);
    for (index, expected) in steps.iter().enumerate() {
        let input = json!({"model":"apikey","where":[
            {"field":"expiresAt","operator":"lt","value":observe_value(&current.clone().into())?},
            {"field":"expiresAt","operator":"ne","value":null},
        ]});
        let before = observe_model_memory(&store, "apikey")?;
        let result = store
            .delete_expired_api_keys_before(current.clone())
            .await?;
        let after = observe_model_memory(&store, "apikey")?;
        let observed_events = std::mem::take(&mut *events_lock(&trace)?);
        assert_eq!(
            json!({"attempt":index + 1,"method":"deleteMany","input":input,"before":before,"result":result,"events":observed_events,"after":after}),
            *expected
        );
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The frozen source fixture covers mapped Date, JSON, and serial-reference cleanup with full storage and callbacks."
)]
async fn api_key_cleanup_uses_shared_field_bindings() -> AuthResult<()> {
    let fixture: JsonValue = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/api-key-cleanup-fields-1.7.6.json"
    )))?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["backend"], "memory");
    let current: crate::FieldDate = required(fixture["current"]["value"].as_str())?
        .parse::<DateTime<Utc>>()
        .map(Into::into)
        .map_err(|error| AuthError::internal(format!("Invalid cleanup fixture date: {error}")))?;
    let cases = required(fixture["cases"].as_array())?;
    let scenarios: Vec<_> = cases.iter().map(|case| case["scenario"].clone()).collect();
    assert_eq!(
        scenarios,
        vec![
            json!({"name":"mapped-date","type":"date","serial":false,"reference":false}),
            json!({"name":"mapped-json","type":"json","serial":false,"reference":false}),
            json!({"name":"mapped-serial-reference","type":"date","serial":true,"reference":true}),
        ]
    );
    for case in cases {
        verify_cleanup_case(case, &current).await?;
    }
    Ok(())
}
