use super::*;
use better_auth_core::utils::password::ScryptPasswordHasher;

struct BoundaryHasher {
    trace: Arc<Trace>,
    default: bool,
    throws: bool,
    original: FieldValue,
}

#[async_trait]
impl PasswordHasher for BoundaryHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        self.trace.hash(password).await
    }

    async fn verify(&self, _: &str, _: &str) -> AuthResult<bool> {
        Err(AuthError::internal(
            "The fixture must reach the native verifier",
        ))
    }

    async fn verify_native(&self, hash: &FieldValue, password: &str) -> AuthResult<FieldValue> {
        if self.default {
            return ScryptPasswordHasher.verify_native(hash, password).await;
        }
        let result = self.trace.verify_native(hash, password).await?;
        if self.throws {
            return Err(AuthError::from_thrown(self.original.clone()));
        }
        Ok(result)
    }
}

fn verifier_result(case: &Json) -> AuthResult<FieldValue> {
    if case["operation"] != "verify" {
        return Ok(true.into());
    }
    Ok(match case["result"].as_str().unwrap() {
        "true" => true.into(),
        "false" => false.into(),
        "object" => FieldMap::from([
            ("accepted".into(), false.into()),
            ("ownUndefined".into(), FieldValue::Undefined),
        ])
        .into(),
        "array" => Vec::<FieldValue>::new().into(),
        "false-string" => "false".into(),
        "zero" => 0.into(),
        "undefined" | "throws" => FieldValue::Undefined,
        _ => return Err(AuthError::internal("Unknown captured verifier result")),
    })
}

fn projected_hash(
    case: &Json,
    trace: &Arc<Trace>,
    original: &FieldValue,
) -> AuthResult<FieldValue> {
    let projected = hash(case["hash"].as_str().unwrap(), trace)?;
    if case["operation"] != "default" || case["split"] == "missing" {
        return Ok(projected);
    }
    let split = if case["split"] == "non-callable" {
        false.into()
    } else {
        let trace = Arc::downgrade(trace);
        let original = original.clone();
        let shape = case["split"].as_str().unwrap().to_owned();
        FieldFunction::contextual(move |receiver, arguments| {
            let trace = trace.upgrade().ok_or_else(|| {
                AuthError::internal("The password trace must outlive its callback")
            })?;
            let projected = trace.projected.lock().unwrap().clone();
            trace
                .native
                .lock()
                .unwrap()
                .call("hash.split", receiver, &projected, arguments)?;
            assert!(receiver.strict_equals(&projected));
            assert_eq!(arguments, [FieldValue::from(":")]);
            Ok(match shape.as_str() {
                "throws" => return Err(AuthError::from_thrown(original.clone())),
                "empty" => Vec::<FieldValue>::new().into(),
                "string" => "ab".into(),
                "number-key" => vec![FieldValue::from("salt"), 17.into()].into(),
                "number-salt" => vec![FieldValue::from(17), "wrong-key".into()].into(),
                "array" => vec![FieldValue::from("salt"), "wrong-key".into()].into(),
                _ => return Err(AuthError::internal("Unknown captured split result")),
            })
        })
        .into()
    };
    projected.as_object().unwrap().set("split", split)?;
    Ok(projected)
}

async fn native_case(case: &Json, host_errors: &Json) -> AuthResult<()> {
    let mut config = config();
    let store = Arc::new(EphemeralStore::from_storage(
        Arc::new(config.clone()),
        tables(false),
    )?);
    let raw =
        test_helpers::initialize_test_context(Arc::new(config.clone()), store.clone(), &[]).await?;
    let trace = Arc::new(Trace {
        native: Mutex::new(NativeObservation::default()),
        projected: Mutex::new(FieldValue::Undefined),
        projections: AtomicUsize::new(0),
        second_false: false,
        verified: verifier_result(case)?,
        mutation: None,
        database: raw.database,
        store: store.clone(),
    });
    let original = FieldMap::from([
        ("reason".into(), "verification callback failed".into()),
        ("ownUndefined".into(), FieldValue::Undefined),
        (
            "nested".into(),
            FieldMap::from([("retained".into(), true.into())]).into(),
        ),
    ])
    .into();
    *trace.projected.lock().unwrap() = projected_hash(case, &trace, &original)?;
    install_projection(&mut config, &trace);
    let email = EmailPasswordPlugin::new().password_hasher(Arc::new(BoundaryHasher {
        trace: trace.clone(),
        default: case["operation"] == "default",
        throws: case["result"] == "throws",
        original: original.clone(),
    }));
    let password = PasswordManagementPlugin::new();
    let two_factor = TwoFactorPlugin::new()
        .allow_passwordless(true)
        .totp_disabled(true);
    let plugins: [&dyn AuthPlugin<StatelessSchema>; 3] = [&email, &password, &two_factor];
    let context = test_helpers::initialize_test_context(Arc::new(config), store, &plugins).await?;
    let (plugin, path, body): (&dyn AuthPlugin<StatelessSchema>, _, _) =
        if case["operation"] == "require" {
            (&two_factor, "/two-factor/enable", json!({}))
        } else {
            (&password, "/verify-password", json!({"password":PASSWORD}))
        };
    let request = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        path,
        Some("session-token"),
        Some(body),
    );
    let result = plugin
        .on_request(
            &request,
            context.initialize_request_context().await?.as_ref(),
        )
        .await
        .and_then(|response| {
            response.ok_or_else(|| {
                AuthError::internal("The password fixture route must return a response")
            })
        })
        .and_then(|response| response.body.field_value());
    let stored = trace.storage()?;
    let mut native = trace.native.lock().unwrap();
    let projected = native.observe(&trace.projected.lock().unwrap())?;
    let outcome = runtime::outcome(result, &mut native, Some(&original))?;
    let actual = json!({"projected":projected, "outcome":outcome, "events":native.events,
        "functionIds":native.function_ids(), "errorFunctions":[], "stored":native.observe(&stored)?,
        "verifierResult":native.observe(&trace.verified)?});
    let mut expected = runtime::query_expected(case)?;
    expected["verifierResult"] = runtime::snapshot(&case["verifierResult"])?;
    assert_runtime_and_host_errors(&actual, &expected, case, host_errors);
    Ok(())
}

fn assert_runtime_and_host_errors(actual: &Json, expected: &Json, case: &Json, host_errors: &Json) {
    let name = case["name"].as_str().unwrap();
    let Some(host_error) = host_errors.get(name) else {
        assert_replay(actual, expected, name);
        return;
    };
    let source_error = &expected["outcome"]["error"];
    let rust_error = &actual["outcome"]["error"];
    // Keep each host's complete error under a separate assertion. These errors are not equivalent.
    assert_replay(
        source_error,
        &host_error["source"],
        &format!("{name}/source-error"),
    );
    assert_replay(
        rust_error,
        &host_error["rust"],
        &format!("{name}/rust-error"),
    );
    assert_replay(
        &rust_error["name"],
        &source_error["name"],
        &format!("{name}/error/name"),
    );
    if host_error["messageCompared"] == true {
        assert_replay(
            &rust_error["message"],
            &source_error["message"],
            &format!("{name}/error/message"),
        );
    }
    let mut actual_business = actual.clone();
    let mut expected_business = expected.clone();
    let _ = actual_business["outcome"]
        .as_object_mut()
        .unwrap()
        .shift_remove("error");
    let _ = expected_business["outcome"]
        .as_object_mut()
        .unwrap()
        .shift_remove("error");
    assert_replay(&actual_business, &expected_business, name);
}

#[tokio::test]
async fn native_boundary_fixture_replays_runtime_and_retains_host_error_gaps() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(include_str!(
        "../../../../../../../tests/fixtures/password-native-boundary-1.7.6.json"
    ))?;
    let coverage: Json = serde_json::from_str(include_str!(
        "../../../../../../../tests/fixtures/password-native-boundary-runtime-coverage.json"
    ))?;
    assert_eq!(fixture["version"], "1.7.6");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 24);
    assert_eq!(coverage["hostErrors"].as_object().unwrap().len(), 4);
    for name in coverage["hostErrors"].as_object().unwrap().keys() {
        assert!(cases.iter().any(|case| case["name"] == *name));
    }
    for case in cases {
        native_case(case, &coverage["hostErrors"]).await?;
    }
    Ok(())
}
