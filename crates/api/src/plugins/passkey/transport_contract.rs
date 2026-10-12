#![expect(
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "Pinned native contracts must fail on missing fixture fields and exact behavior mismatches."
)]
use super::*;
use crate::plugins::passkey::transport_method_fixture::{CASES, Transport};
use better_auth_core::user_fields::{
    FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform,
};

async fn replay_transport_case(case: &Json) -> AuthResult<Json> {
    let name = CASES
        .into_iter()
        .find(|name| case["scenario"]["method"] == *name)
        .unwrap();
    let transport = Transport::new(name)?;
    let state = Arc::new(State {
        original: transport.original.clone(),
        original_body: FieldValue::Undefined,
        callback_failure: false,
        verification: Mutex::default(),
        logs: Mutex::default(),
    });
    let plugin = PasskeyPlugin::new()
        .rp_id(RP_ID)
        .rp_name("Native errors")
        .authentication(PasskeyAuthenticationOptions {
            after_verification: Some(Arc::new(Callback(state.clone()))),
            ..Default::default()
        });
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.telemetry.enabled = false;
    config.session.disable_session_refresh = Some(true);
    let generated = AtomicUsize::new(0);
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            let sequence = generated.fetch_add(1, Ordering::Relaxed) + 1;
            Ok(Some(format!("{}-{sequence}", request.model)))
        })));
    config.logger = better_auth_core::LoggerConfig {
        level: Some(LogLevel::Error),
        log: Some(Arc::new(Logger(state.clone()))),
        ..Default::default()
    }
    .into();
    let now = chrono::DateTime::from_timestamp_millis(NOW).unwrap();
    let interceptions = StoreInterceptions {
        session_overrides: FieldMap::from([
            (
                "token".into(),
                case["input"]["sessionToken"].as_str().unwrap().into(),
            ),
            ("createdAt".into(), now.into()),
            ("updatedAt".into(), now.into()),
            (
                "expiresAt".into(),
                (now + config.session.expires_in()).into(),
            ),
        ]),
        ..Default::default()
    };
    let config = Arc::new(config);
    let store = Arc::new(EphemeralStore::from_storage(config.clone(), tables(case)?)?);
    let database = Arc::new(TestStore::new(store.clone(), interceptions));
    let mut context = test_helpers::initialize_test_context(config.clone(), database, &[&plugin])
        .await?
        .with_clock(|| chrono::DateTime::from_timestamp_millis(NOW).unwrap());
    let mut fields = better_auth_core::plugin_runtime::ModelFields::default();
    AuthPlugin::<StatelessSchema>::schema(&plugin, &mut fields)?;
    let receiver = transport.receiver.clone();
    fields.register_model_fields(
        EntityRole::Passkey,
        UserConfig {
            additional_fields: Some(
                [(
                    "transports".into(),
                    UserFieldConfig {
                        required: Some(false),
                        transform: Some(FieldTransforms {
                            input: None,
                            output: Some(UserFieldTransform::new(move |_| {
                                Ok(receiver.as_ref().clone())
                            })),
                        }),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        },
    )?;
    context.database = context.database.with_runtime(config, Vec::new(), fields)?;
    context
        .extensions
        .insert(Arc::new(EndpointDispatcher::<StatelessSchema>::new(
            Arc::new(Vec::new()),
            Default::default(),
            AuthPlugin::<StatelessSchema>::routes(&plugin),
        )));
    let before = stored(&store)?;
    let mut request = AuthRequest::new(HttpMethod::Post, "/passkey/verify-authentication");
    request.headers = case["input"]["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|header| {
            (
                header[0].as_str().unwrap().into(),
                header[1].as_str().unwrap().into(),
            )
        })
        .collect();
    request.set_endpoint_body(ValidatedBody::unvalidated_native(
        FieldMap::from([(
            "response".into(),
            observation::revive(&case["input"]["response"])?,
        )])
        .into(),
    ));
    let result = native_session::dispatch_plugin(&request, &context, &plugin).await;
    transport.assert_calls(name);
    let outcome = match result {
        Ok(response) => {
            let response = response
                .ok_or_else(|| AuthError::internal("The Passkey route must return a response"))?;
            assert_eq!(response.status, 200);
            json!({
                "returned":true,
                "result":NativeObservation::default().observe(&response.body.field_value()?)?,
                "error":null,
                "sameOriginal":false,
                "coreAPIError":false,
            })
        }
        Err(error) => {
            let value = error.raw_value().unwrap();
            json!({
                "returned":false,
                "result":{"type":"undefined"},
                "error":observation::error(value)?,
                "sameOriginal":value.strict_equals(&transport.original),
                "coreAPIError":error.is_api_error_instance(ApiErrorClass::BetterAuth),
            })
        }
    };
    Ok(json!({
        "before":before,
        "events":*transport.events.lock().unwrap(),
        "verification":*state.verification.lock().unwrap(),
        "logs":*state.logs.lock().unwrap(),
        "outcome":outcome,
        "after":stored(&store)?,
    }))
}

#[tokio::test]
async fn transport_methods_replay_complete_native_results_and_persistence() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/passkey-transport-methods-1.7.6.json"),
        )
        .unwrap(),
    )?;
    assert_eq!(fixture["contract"], "passkey-transport-methods");
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["backend"], "memory");
    let cases = fixture["cases"].as_array().unwrap();
    let scenarios = CASES
        .into_iter()
        .flat_map(|method| {
            [false, true].map(move |valid| json!({
        "name":format!("{method}-{}-signature", if valid { "valid" } else { "invalid" }),
        "method":method,
        "validSignature":valid,
    }))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        cases
            .iter()
            .map(|case| case["scenario"].clone())
            .collect::<Vec<_>>(),
        scenarios
    );
    let mut failures = ReplayFailures::default();
    for case in cases {
        let actual = replay_transport_case(case).await?;
        let mut expected = case["runtime"].clone();
        expected["logs"] = observation::source_logs(&expected["logs"]);
        let name = case["name"].as_str().unwrap();
        failures.record(name, || {
            observation::assert_replay(&actual, &expected, name)
        });
    }
    failures.finish();
    Ok(())
}
