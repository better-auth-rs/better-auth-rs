use super::*;

#[tokio::test]
async fn public_rate_limit_denial_preserves_complete_response_and_storage() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/api-key-rate-limit-public-1.7.6.json"
    )))?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["contract"], "api-key-rate-limit-public");
    let cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Public rate-limit cases missing"))?;
    let [case] = cases.as_slice() else {
        return Err(AuthError::internal("Expected one public rate-limit case"));
    };
    assert_eq!(case["name"], "secondary-deny");
    let mut fields = seed();
    let _ = fields.insert("requestCount".into(), 3.0.into());
    let cache = Arc::new(Cache::with_seed(fields)?);
    let logs = Arc::new(Mutex::new(Vec::<FieldValue>::new()));
    let mut config = AuthConfig::default();
    config.logger = FieldMap::from([
        ("level".into(), "error".into()),
        (
            "log".into(),
            FieldFunction::contextual({
                let logs = logs.clone();
                move |_, arguments| {
                    let [level, message, remaining @ ..] = arguments else {
                        return Err(AuthError::internal(
                            "Expected complete API Key log arguments",
                        ));
                    };
                    lock(&logs)?.push(
                        FieldMap::from([
                            ("level".into(), level.clone()),
                            ("message".into(), message.clone()),
                            ("arguments".into(), remaining.to_vec().into()),
                        ])
                        .into(),
                    );
                    Ok(FieldValue::Undefined)
                }
            })
            .into(),
        ),
    ])
    .into();
    let config = Arc::new(config);
    let raw = Arc::new(EphemeralStore::from_storage(
        config.clone(),
        ["user", "session", "account", "verification", "apikey"]
            .map(|name| (name.into(), Vec::new())),
    )?);
    let now = clock()?;
    let context = AuthContext::new(config, raw.clone())?.with_clock(move || now);
    let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(cache.clone()),
        disable_key_hashing: true,
        ..Default::default()
    });
    let snapshot = || -> AuthResult<FieldValue> {
        Ok(FieldMap::from([
            ("database".into(), database_snapshot(&raw)?),
            ("cache".into(), cache.snapshot()?),
        ])
        .into())
    };
    let mut graph = PropertyGraph::default();
    graph.assert_snapshot(&snapshot()?, &case["before"], "/public/before")?;
    let result = plugin
        .verify_api_key(
            &crate::plugins::api_key::VerifyApiKey {
                key: "usage-secret",
                config_id: None,
                permissions: None,
            },
            &context,
        )
        .await;
    let error = result
        .err()
        .ok_or_else(|| AuthError::internal("Expected public rate-limit denial"))?;
    let response = error.into_response()?;
    graph.assert_snapshot(
        &response.body.field_value()?,
        &case["result"],
        "/public/result",
    )?;
    graph.assert_snapshot(&snapshot()?, &case["after"], "/public/after")?;
    graph.assert_snapshot(
        &lock(&cache.events)?.clone().into(),
        &case["storageEvents"],
        "/public/storageEvents",
    )?;
    graph.assert_snapshot(&lock(&logs)?.clone().into(), &case["logs"], "/public/logs")?;
    assert!(graph.finish(None, "/public").is_empty());
    Ok(())
}
