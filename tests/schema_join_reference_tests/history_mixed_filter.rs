use super::*;
use better_auth_core::ListUsersParams;

enum Probe {
    List(ListUsersParams),
    Verify,
}

struct Case {
    name: &'static str,
    probe: Probe,
    warmed: bool,
    fails: bool,
}

fn cases() -> Vec<Case> {
    let invalid_filter = ListUsersParams {
        filter_field: Some("missingUserField".into()),
        filter_value: Some(json!("missing")),
        ..Default::default()
    };
    vec![
        Case {
            name: "valid-search-before-invalid-filter",
            probe: Probe::List(ListUsersParams {
                search_field: Some("email".into()),
                search_value: Some("missing".into()),
                ..invalid_filter.clone()
            }),
            warmed: true,
            fails: true,
        },
        Case {
            name: "empty-search-before-invalid-filter",
            probe: Probe::List(ListUsersParams {
                search_value: Some(String::new()),
                ..invalid_filter
            }),
            warmed: false,
            fails: true,
        },
        Case {
            name: "empty-search-without-filter",
            probe: Probe::List(ListUsersParams {
                search_value: Some(String::new()),
                ..Default::default()
            }),
            warmed: false,
            fails: false,
        },
        Case {
            name: "empty-search-field-uses-email",
            probe: Probe::List(ListUsersParams {
                search_field: Some(String::new()),
                search_value: Some("missing".into()),
                ..Default::default()
            }),
            warmed: true,
            fails: false,
        },
        Case {
            name: "empty-filter-field-uses-email",
            probe: Probe::List(ListUsersParams {
                filter_field: Some(String::new()),
                filter_value: Some(json!("missing")),
                ..Default::default()
            }),
            warmed: true,
            fails: false,
        },
        Case {
            name: "atomic-verification-retains-adapter-history",
            probe: Probe::Verify,
            warmed: true,
            fails: false,
        },
    ]
}

fn config(joins: bool, events: &Events) -> AuthConfig {
    let mut config = AuthConfig::default();
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.advanced.database.joins = Some(joins);
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
    config
}

async fn owner<S: AuthSchema>(store: &impl AuthStore<S>) -> Value {
    match store.get_account_owner("provider", "missing").await {
        Ok(None) => Value::Null,
        Ok(Some(row)) => json!({"account": row.account, "user": row.user}),
        Err(error) => json!({"error": error.instrumentation_message()}),
    }
}

async fn check<S: AuthSchema>(
    store: &impl AuthStore<S>,
    case: &Case,
    events: &Events,
) -> AuthResult<()> {
    let duplicate = json!({"error":"Multiple foreign keys found for model user and base model account while performing join operation. Only one foreign key is supported."});
    assert_eq!(owner(store).await, duplicate, "{} before", case.name);
    assert!(events.take().is_empty(), "{} before events", case.name);

    match &case.probe {
        Probe::List(params) => {
            let actual = match store.list_users(params.clone()).await {
                Ok((users, total)) => json!({"users":users, "total":total}),
                Err(error) => json!({"error":error.instrumentation_message()}),
            };
            let expected = if case.fails {
                json!({"error":"Field missingUserField not found in model user"})
            } else {
                json!({"users":[], "total":0})
            };
            assert_eq!(actual, expected, "{} list", case.name);
            let expected_events = if case.fails {
                Vec::new()
            } else {
                vec![
                    json!(["query", "findMany", "user"]),
                    json!(["query", "count", "user"]),
                ]
            };
            assert_eq!(events.take(), expected_events, "{} list events", case.name);
        }
        Probe::Verify => {
            assert!(
                store
                    .verify_user_and_revoke_unproven_access("missing")
                    .await?
                    .is_none(),
                "{} result",
                case.name
            );
            assert_eq!(
                events.take(),
                [json!(["query", "findOne", "user"])],
                "{} verification events",
                case.name
            );
        }
    }

    assert_eq!(
        owner(store).await,
        if case.warmed { Value::Null } else { duplicate },
        "{} after",
        case.name
    );
    let expected_events = if case.warmed {
        vec![json!(["query", "findMany", "account"])]
    } else {
        Vec::new()
    };
    assert_eq!(events.take(), expected_events, "{} after events", case.name);
    Ok(())
}

async fn contract() -> AuthResult<()> {
    for joins in [false, true] {
        for case in cases() {
            let events = Events::default();
            let memory = EphemeralStore::new(Arc::new(config(joins, &events)));
            check(&memory, &case, &events)
                .with_subscriber(tracing_subscriber::registry().with(events.clone()))
                .await?;

            let database = Database::connect("sqlite::memory:")
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            migrator::run_migrations(&database)
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            let sqlite = SeaOrmStore::<BundledSchema>::new(config(joins, &events), database);
            check(&sqlite, &case, &events)
                .with_subscriber(tracing_subscriber::registry().with(events.clone()))
                .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn query_failures_and_atomic_verification_preserve_adapter_schema_history() -> AuthResult<()>
{
    contract().await
}
