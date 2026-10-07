use super::*;
use better_auth_core::{
    observability::LogLevel,
    store::{MemoryCacheAdapter, SecondaryStorage},
};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};

struct Cache {
    inner: MemoryCacheAdapter,
    entries: Mutex<serde_json::Map<String, Value>>,
    events: Events,
}

impl Cache {
    fn new(events: Events) -> Self {
        Self {
            inner: MemoryCacheAdapter::new(),
            entries: Mutex::default(),
            events,
        }
    }

    async fn snapshot(&self) -> TestResult<Vec<Value>> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| "Cache recorder poisoned")?
            .clone();
        let mut result = Vec::new();
        for (key, entry) in entries {
            let stored = SecondaryStorage::get(&self.inner, &key).await?;
            assert_eq!(stored.as_ref(), entry.get("value"));
            result.push(json!({"key":key,"value":entry["value"],"ttl":entry["ttl"]}));
        }
        Ok(result)
    }
}

#[async_trait::async_trait]
impl SecondaryStorage for Cache {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        let value = SecondaryStorage::get(&self.inner, key).await?;
        self.events
            .push(json!({"kind":"secondary.get","key":key,"value":value}))?;
        Ok(value)
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> AuthResult<()> {
        SecondaryStorage::set(&self.inner, key, value, ttl).await?;
        self.events
            .push(json!({"kind":"secondary.set","key":key,"value":value,"ttl":ttl}))?;
        let _ = self
            .entries
            .lock()
            .map_err(|_| AuthError::internal("Cache recorder poisoned"))?
            .insert(key.into(), json!({"value":value,"ttl":ttl}));
        Ok(())
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        SecondaryStorage::delete(&self.inner, key).await?;
        self.events
            .push(json!({"kind":"secondary.delete","key":key}))?;
        let _ = self
            .entries
            .lock()
            .map_err(|_| AuthError::internal("Cache recorder poisoned"))?
            .remove(key);
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        let value = SecondaryStorage::get_and_delete(&self.inner, key).await?;
        self.events
            .push(json!({"kind":"secondary.getAndDelete","key":key,"value":value}))?;
        let _ = self
            .entries
            .lock()
            .map_err(|_| AuthError::internal("Cache recorder poisoned"))?
            .remove(key);
        Ok(value)
    }
}

fn table_presence(snapshot: &Value, sqlite: bool) -> Value {
    ["user", "session", "account", "verification"]
        .into_iter()
        .map(|model| {
            let present = if model == "verification" && !sqlite {
                // EphemeralStore has a fixed Verification collection; its public snapshot exposes only the queried models.
                true
            } else {
                snapshot.get(model).is_some_and(|rows| !rows.is_null())
            };
            (model.to_owned(), Value::Bool(present))
        })
        .collect::<serde_json::Map<_, _>>()
        .into()
}

fn verify_cache(
    events: &[Value],
    cache: &[Value],
    anchors: &observe::Anchors,
    end: i64,
) -> TestResult {
    let calls: Vec<_> = events
        .iter()
        .filter(|event| {
            event["kind"]
                .as_str()
                .is_some_and(|kind| kind.starts_with("secondary."))
        })
        .collect();
    assert_eq!(calls.len(), 3, "Complete secondary calls: {calls:#?}");
    assert_eq!(
        calls[0],
        &json!({"kind":"secondary.get","key":"active-sessions-undefined","value":null})
    );
    let index = calls[1];
    let envelope = calls[2];
    assert_eq!(index["kind"], "secondary.set");
    assert_eq!(index["key"], "active-sessions-undefined");
    assert_eq!(envelope["kind"], "secondary.set");
    assert_eq!(envelope["key"].as_str(), anchors.token.as_deref());
    let ttl = index["ttl"].as_u64().ok_or("Expected integer cache TTL")?;
    assert!(ttl > 0 && ttl <= 3600);
    assert!(i64::try_from(ttl)? >= (anchors.session_dates["expiresAt"] - end).div_euclid(1000));
    assert_eq!(envelope["ttl"], index["ttl"]);
    assert_eq!(
        serde_json::from_str::<Value>(index["value"].as_str().ok_or("Expected raw cache string")?)?,
        json!([{
            "token":anchors.token,"expiresAt":anchors.session_dates["expiresAt"],
        }])
    );
    let stored: Value = serde_json::from_str(
        envelope["value"]
            .as_str()
            .ok_or("Expected raw cache string")?,
    )?;
    let issued = observe::hook(events, "session", "before").ok_or("Missing Session before hook")?;
    assert_eq!(
        stored,
        json!({"session":values::revive(issued)?.json()?,"user":null})
    );
    assert!(stored["session"].get("userId").is_none());
    assert_eq!(
        stored
            .as_object()
            .ok_or("Expected cached envelope")?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["session", "user"]
    );
    assert_eq!(
        cache,
        calls
            .iter()
            .skip(1)
            .map(|event| json!({"key":event["key"],"value":event["value"],"ttl":event["ttl"]}))
            .collect::<Vec<_>>()
    );
    Ok(())
}

fn normalize_cache(entry: &mut Value, anchors: &observe::Anchors) -> TestResult {
    let token = anchors.token.as_deref().ok_or("Missing Session token")?;
    let id = anchors.session_id.as_deref().ok_or("Missing Session ID")?;
    if entry["key"] == token {
        entry["key"] = json!("<session-token>");
    }
    let mut raw = entry["value"]
        .as_str()
        .ok_or("Expected raw cache string")?
        .to_owned();
    raw = raw
        .replace(token, "<session-token>")
        .replace(id, "<session-id>");
    for (field, millis) in &anchors.session_dates {
        let date = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(*millis)
            .ok_or("Session timestamp is out of range")?
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        raw = raw.replace(
            &format!("\"{field}\":\"{date}\""),
            &format!("\"{field}\":\"<session.{field}>\""),
        );
    }
    raw = raw.replace(
        &format!("\"expiresAt\":{}", anchors.session_dates["expiresAt"]),
        "\"expiresAt\":\"<session.expiresAt.milliseconds>\"",
    );
    entry["value"] = json!(raw);
    entry["ttl"] = json!("<session-ttl>");
    Ok(())
}

fn paired_expected(case: &Case) -> Vec<Value> {
    let adapter: Vec<_> = case
        .events
        .iter()
        .filter(|event| {
            event["kind"]
                .as_str()
                .is_some_and(|kind| kind.starts_with("adapter."))
        })
        .cloned()
        .collect();
    assert_eq!(
        adapter,
        vec![
            json!({"kind":"adapter.findOne.call","input":{"model":"user","where":[{"field":"id","value":{"type":"undefined"}}]}}),
            json!({"kind":"adapter.findOne.return","value":null}),
        ]
    );
    // Rust exposes query spans, hooks, and secondary writes, but has no adapter call/return observer.
    // Preserve these upstream observations without manufacturing equivalent Rust events.
    println!(
        "Unpaired observation boundary: {}/joins={} adapter.findOne.call/return; compare the actual query and cached User result.",
        case.backend, case.joins
    );
    case.events
        .iter()
        .filter(|event| {
            !event["kind"]
                .as_str()
                .is_some_and(|kind| kind.starts_with("adapter."))
        })
        .cloned()
        .collect()
}

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    database: Option<&DatabaseConnection>,
    scenario: &Scenario,
    case: &Case,
) -> TestResult {
    storage::seed(raw.as_ref(), scenario).await?;
    let before = storage::snapshot(raw.as_ref(), database, &[]).await?;
    storage::assert_snapshot(&before, &case.before, database.is_some(), case);
    let events = Events::default();
    let cache = Arc::new(Cache::new(events.clone()));
    let captured = case
        .observations
        .as_ref()
        .ok_or("Missing secondary observations")?;
    let presence = table_presence(&before, database.is_some());
    assert_eq!(
        json!({"tablePresence":presence,"cache":cache.snapshot().await?}),
        captured["before"]
    );
    let mut options = config::configured(scenario, case.joins, Some(&events))?;
    options.session.store_session_in_database = Some(false);
    options.verification.store_in_database = true;
    options.logger.disabled = Some(false);
    options.logger.level = Some(LogLevel::Error);
    options.logger.log = Some(Arc::new(email::Logger(events.clone())));
    let store = raw.with_runtime(
        Arc::new(options.clone()),
        vec![Arc::new(hooks::Hooks(events.clone()))],
        Default::default(),
    )?;
    let harness =
        http::auth_with_secondary(store, options, scenario, &events, Some(cache.clone())).await?;
    assert!(harness.flow.is_none());
    let start = chrono::Utc::now().timestamp_millis();
    let response = http::request(harness.auth, &case.request)
        .with_subscriber(tracing_subscriber::registry().with(events.clone()))
        .await?;
    let end = chrono::Utc::now().timestamp_millis();
    let mut observed = events.take()?;
    let tokens = observe::issued_tokens(&observed)?;
    let mut after = storage::snapshot(raw.as_ref(), database, &tokens).await?;
    assert_eq!(table_presence(&after, database.is_some()), presence);
    assert_eq!(after["user"], before["user"]);
    assert_eq!(after["session"], before["session"]);
    let anchors = observe::verify_dynamic(&observed, &after, case, start, end)?;
    let mut cached = cache.snapshot().await?;
    verify_cache(&observed, &cached, &anchors, end)?;
    for event in &mut observed {
        if event["kind"] == "secondary.set" {
            normalize_cache(event, &anchors)?;
        }
    }
    for entry in &mut cached {
        normalize_cache(entry, &anchors)?;
    }
    assert_eq!(
        json!({"tablePresence":presence,"cache":cached}),
        captured["after"]
    );
    observe::normalize(&mut observed, &mut after, &anchors)?;
    observe::assert_events(&observed, &paired_expected(case), case)?;
    storage::assert_snapshot(&after, &case.after, database.is_some(), case);
    http::assert_response(response, &case.response, &anchors)?;
    assert_eq!(
        case.checked,
        json!({
            "noNetwork":true,"completeStorage":true,"pureSecondarySession":true,"completeSecondaryCalls":true,
            "admissionIdIsUndefined":true,"sessionOwnerIsOwnUndefined":true,"adapterLookupValueIsOwnUndefined":true,
            "sqliteUndefinedLookupObserved":database.is_some(),"lookupOutcome":"return",
            "preservedCanonicalAccountOwner":true,"sessionDatesWithinRequest":true,"exactSharedTtl":true,
            "sessionCookieMatchesToken":true,
        })
    );
    Ok(())
}

#[tokio::test]
async fn memory_array_owner_pure_secondary_matches_upstream_http() -> TestResult {
    let fixture = Fixture::read_secondary()?;
    for case in fixture.cases.iter().filter(|case| case.backend == "memory") {
        let raw = Arc::new(EphemeralStore::new(Arc::new(config::baseline())));
        contract(raw, None, fixture.scenario(&case.scenario)?, case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_array_owner_pure_secondary_matches_upstream_http() -> TestResult {
    let fixture = Fixture::read_secondary()?;
    for case in fixture.cases.iter().filter(|case| case.backend == "sqlite") {
        let scenario = fixture.scenario(&case.scenario)?;
        let database = storage::sqlite(scenario).await?;
        let _ = database
            .execute_raw(Statement::from_string(
                DbBackend::Sqlite,
                "DROP TABLE session",
            ))
            .await?;
        let raw = Arc::new(SeaOrmStore::<models::Core>::new(
            config::baseline(),
            database.clone(),
        ));
        contract(raw, Some(&database), scenario, case).await?;
    }
    Ok(())
}
