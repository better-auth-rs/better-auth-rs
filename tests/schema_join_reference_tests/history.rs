use super::*;
use better_auth_core::plugin_runtime::ModelFields;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    version: String,
    cases: Vec<Sequence>,
    transactions: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sequence {
    backend: String,
    joins: bool,
    name: String,
    mode: String,
    observations: Vec<Observation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    scope: String,
    operation: String,
    events: Vec<Value>,
    result: Value,
}

fn configured(sequence: &Sequence, events: &Events) -> AuthConfig {
    let mut config = AuthConfig::default();
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.advanced.database.joins = Some(sequence.joins);
    for name in ["id", "image"] {
        let mut field = output(
            if name == "id" {
                "user.id"
            } else {
                "user.image"
            },
            events,
        );
        field.references = Some(reference("account"));
        let _ = config.user.fields_mut().insert(name.into(), field);
    }
    let _ = config
        .user
        .fields_mut()
        .insert("name".into(), output("user.name", events));
    let _ = config
        .account
        .additional_fields
        .insert("accountId".into(), output("account.accountId", events));
    if sequence.mode == "invalid-target" {
        let _ = config.account.additional_fields.insert(
            "userId".into(),
            UserFieldConfig {
                references: Some(UserFieldReference {
                    model: "user".into(),
                    field: "missingUserField".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    } else {
        assert_eq!(sequence.mode, "duplicate");
    }
    config
}

async fn verify<S: AuthSchema>(
    store: &impl AuthStore<S>,
    config: AuthConfig,
    sequence: &Sequence,
    events: &Events,
) -> AuthResult<()> {
    for expected in &sequence.observations {
        let fresh;
        let active: &dyn AuthStore<S> = match expected.scope.as_str() {
            "parent" => store,
            "fresh" => {
                fresh = store.with_runtime(
                    Arc::new(config.clone()),
                    Vec::new(),
                    ModelFields::default(),
                )?;
                fresh.as_ref()
            }
            scope => {
                return Err(AuthError::internal(format!(
                    "Unpaired history scope: {scope}"
                )));
            }
        };
        let result: AuthResult<Value> = async {
            match expected.operation.as_str() {
                "owner" => Ok(active
                    .get_account_owner("provider", "external-owner")
                    .await?
                    .map_or(Value::Null, |row| {
                        let user = match row.user {
                            JoinValue::One(user) => json!(user),
                            JoinValue::Many(users) => json!(users),
                        };
                        json!({"account": row.account, "user": user})
                    })),
                "accounts" => Ok(active
                    .get_user_with_accounts("owner@join-history.test")
                    .await?
                    .map_or(Value::Null, |row| {
                        let accounts = match row.accounts {
                            JoinValue::One(account) => json!(account),
                            JoinValue::Many(accounts) => json!(accounts),
                        };
                        json!({"user": row.user, "accounts": accounts})
                    })),
                "read-user" => Ok(serde_json::to_value(
                    active
                        .get_user_by_email("missing@join-history.test")
                        .await?,
                )?),
                operation => Err(AuthError::internal(format!(
                    "Unpaired history operation: {operation}"
                ))),
            }
        }
        .with_subscriber(tracing_subscriber::registry().with(events.clone()))
        .await;
        let result = match result {
            Ok(value) => value,
            Err(error) => json!({"error": error.instrumentation_message()}),
        };
        assert_eq!(
            result, expected.result,
            "{}/{}/joins={}/{}/{}",
            sequence.backend, sequence.name, sequence.joins, expected.scope, expected.operation
        );
        // The business owner lookup uses findMany to reject duplicate account identities.
        // The upstream adapter probe uses findOne; no other trace event is changed.
        let expected_events: Vec<_> = expected
            .events
            .iter()
            .map(|event| {
                if expected.operation == "owner" && *event == json!(["query", "findOne", "account"])
                {
                    json!(["query", "findMany", "account"])
                } else {
                    event.clone()
                }
            })
            .collect();
        assert_eq!(
            events.take(),
            expected_events,
            "{}/{}/joins={}/{}/{}",
            sequence.backend,
            sequence.name,
            sequence.joins,
            expected.scope,
            expected.operation
        );
    }
    Ok(())
}

async fn contract() -> AuthResult<()> {
    let fixture: History = serde_json::from_str(include_str!(
        "../fixtures/schema-join-reference-history-1.7.6.json"
    ))?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.cases.len(), 48);
    assert_eq!(fixture.transactions.len(), 32);
    let mut paired = 0;
    let mut unpaired = Vec::new();
    for sequence in fixture.cases {
        if sequence.backend == "boundary"
            || matches!(
                sequence.name.as_str(),
                "empty-where-null-read" | "unknown-where-field" | "primary-id-alias"
            )
        {
            unpaired.push(sequence);
            continue;
        }
        assert!(matches!(
            sequence.name.as_str(),
            "repeated-owner" | "reversed-order" | "ordinary-missing-read" | "failed-join-warmup"
        ));
        let events = Events::default();
        let config = configured(&sequence, &events);
        match sequence.backend.as_str() {
            "memory" => {
                let store = EphemeralStore::new(Arc::new(config.clone()));
                verify(&store, config, &sequence, &events).await?;
            }
            "sqlite" => {
                let database = Database::connect("sqlite::memory:")
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                migrator::run_migrations(&database)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                let store = SeaOrmStore::<BundledSchema>::new(config.clone(), database);
                verify(&store, config, &sequence, &events).await?;
            }
            backend => {
                return Err(AuthError::internal(format!(
                    "Unknown history backend: {backend}"
                )));
            }
        }
        paired += 1;
    }
    assert_eq!(paired, 16);
    assert_eq!(unpaired.len(), 32);
    assert_eq!(
        unpaired
            .iter()
            .filter(|case| case.backend == "boundary")
            .count(),
        20
    );
    for name in [
        "empty-where-null-read",
        "unknown-where-field",
        "primary-id-alias",
    ] {
        assert_eq!(
            unpaired
                .iter()
                .filter(|case| case.backend != "boundary" && case.name == name)
                .count(),
            4,
            "{name} remains outside the public business-store contract"
        );
    }
    Ok(())
}

#[tokio::test]
async fn join_schema_history_survives_reads_and_errors_but_resets_with_the_adapter()
-> AuthResult<()> {
    contract().await
}
