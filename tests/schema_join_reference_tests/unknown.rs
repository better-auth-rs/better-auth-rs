use super::*;
use better_auth_core::{
    plugin_runtime::ModelFields,
    store::{
        AccountOwner, UserAccounts,
        schema::{EntityRole, SchemaConfiguration},
    },
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BoundaryCase {
    name: String,
    #[serde(default)]
    account_references: Vec<(String, String)>,
    #[serde(default)]
    user_references: Vec<(String, String)>,
    #[serde(default)]
    reference_fields_first: bool,
    unknown_model: Option<String>,
    error_operation: Option<Operation>,
    #[serde(default)]
    secondary_storage: bool,
    joins: bool,
    operation: Operation,
    events: Vec<Value>,
    result: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundaryFixture {
    version: String,
    cases: Vec<BoundaryCase>,
}

fn configuration(config: AuthConfig, secondary_storage: bool) -> SchemaConfiguration {
    SchemaConfiguration {
        config: Arc::new(config),
        plugins: Vec::new(),
        metadata: Default::default(),
        secondary_storage,
        database_rate_limit: false,
    }
}

fn boundary_result(result: AuthResult<()>) -> Value {
    match result {
        Ok(()) => Value::Null,
        Err(error) => json!({ "error": error.instrumentation_message() }),
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract asserts all captured results while propagating fixture I/O and decoding errors."
)]
fn unknown_reference_resolution_matches_the_pinned_adapter_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: BoundaryFixture = serde_json::from_slice(&std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/schema-join-reference-unknown-1.7.6.json"),
    )?)?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.cases.len(), 36);
    for case in fixture.cases {
        let mut config = AuthConfig::default();
        config.advanced.database.joins = Some(case.joins);
        config.session.store_session_in_database = Some(false);
        config.verification.store_in_database = false;
        if !case.reference_fields_first {
            let _ = config
                .user
                .fields_mut()
                .insert("name".into(), UserFieldConfig::default());
        }
        for (name, model) in &case.account_references {
            let _ = config.account.additional_fields.insert(
                name.clone(),
                UserFieldConfig {
                    references: Some(reference(model)),
                    ..Default::default()
                },
            );
        }
        for (name, model) in &case.user_references {
            let _ = config.user.fields_mut().insert(
                name.clone(),
                UserFieldConfig {
                    references: Some(reference(model)),
                    ..Default::default()
                },
            );
        }
        let settings = configuration(config, case.secondary_storage);
        let mut fields = ModelFields::default();
        fields.set_schema_configuration(&settings);
        let table_matches = |role, candidate: &str| match role {
            EntityRole::User => candidate == "auth_users",
            EntityRole::Account => candidate == "auth_accounts",
            EntityRole::Session => candidate == "auth_sessions",
            EntityRole::Verification => candidate == "auth_verifications",
            _ => false,
        };
        let actual = match case.operation {
            Operation::Accounts => {
                UserAccounts::validate_schema(&settings.config, &fields, table_matches)
            }
            Operation::Owner => {
                AccountOwner::validate_schema(&settings.config, &fields, table_matches)
            }
        };
        assert_eq!(
            boundary_result(actual),
            case.result,
            "{} {:?}",
            case.name,
            case.operation
        );
        let invalid = case.unknown_model.is_some()
            && case
                .error_operation
                .is_none_or(|operation| operation == case.operation);
        if invalid {
            assert!(case.events.is_empty());
        } else {
            assert_eq!(case.events.len(), 1);
            assert_eq!(
                case.events.first().and_then(|event| event.get(0)),
                Some(&json!("findOne"))
            );
        }
    }
    Ok(())
}

async fn check_runtime<S: AuthSchema>(
    store: &impl AuthStore<S>,
    joins: bool,
    account_references: &[(&str, &str)],
    user_references: &[(&str, &str)],
    secondary_storage: bool,
    unknown_models: (Option<&str>, Option<&str>),
) -> AuthResult<()> {
    let events = Events::default();
    let mut config = AuthConfig::default();
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.advanced.database.joins = Some(joins);
    config.session.store_session_in_database = Some(false);
    config.verification.store_in_database = false;
    for (name, model) in user_references {
        let mut field = output("user.reference", &events);
        field.references = Some(reference(model));
        let _ = config.user.fields_mut().insert((*name).into(), field);
    }
    let _ = config
        .user
        .fields_mut()
        .entry("name".into())
        .or_insert_with(|| output("user.name", &events));
    let _ = config
        .account
        .additional_fields
        .insert("accountId".into(), output("account.accountId", &events));
    for (name, model) in account_references {
        let mut field = output("account.reference", &events);
        field.references = Some(reference(model));
        let _ = config
            .account
            .additional_fields
            .insert((*name).into(), field);
    }
    let settings = configuration(config, secondary_storage);
    let mut fields = ModelFields::default();
    fields.set_schema_configuration(&settings);
    let store = store.with_runtime(settings.config, Vec::new(), fields)?;
    for operation in [Operation::Accounts, Operation::Owner] {
        let result = async {
            match operation {
                Operation::Accounts => store
                    .get_user_with_accounts(EMAIL)
                    .await
                    .map(|row| row.is_some()),
                Operation::Owner => store
                    .get_account_owner("provider", "external-owner")
                    .await
                    .map(|row| row.is_some()),
            }
        }
        .with_subscriber(tracing_subscriber::registry().with(events.clone()))
        .await;
        let observed = events.take();
        let unknown = match operation {
            Operation::Accounts => unknown_models.0,
            Operation::Owner => unknown_models.1,
        };
        if let Some(model) = unknown {
            assert_eq!(
                boundary_result(result.map(|_| ())),
                json!({ "error": format!("Model \"{model}\" not found in schema") })
            );
            assert!(
                observed.is_empty(),
                "Reference errors must precede reads and output callbacks"
            );
        } else {
            assert!(result?);
            assert!(observed.iter().any(|event| event[0] == "query"));
            assert!(observed.iter().any(|event| event[0] == "output"));
        }
    }
    Ok(())
}

async fn real_paths<S: AuthSchema>(
    store: &impl AuthStore<S>,
    session_table: &str,
) -> AuthResult<()> {
    let _ = store
        .create_user(CreateUser {
            id: Some("owner".into()),
            name: Some("Owner".into()).into(),
            email: Some(EMAIL.into()),
            email_verified: Some(true),
            image: Some("owner-image".into()).into(),
            ..Default::default()
        })
        .await?;
    let _ = store
        .create_account(CreateAccount {
            id: "account".into(),
            user_id: "owner".into(),
            account_id: "external-owner".into(),
            provider_id: "provider".into(),
            access_token: Some("original-access".into()).into(),
            ..Default::default()
        })
        .await?;
    for joins in [false, true] {
        check_runtime(
            store,
            joins,
            &[("accessToken", "missingAfterValid")],
            &[],
            false,
            (Some("missingAfterValid"), Some("missingAfterValid")),
        )
        .await?;
        check_runtime(
            store,
            joins,
            &[
                ("accessToken", "user"),
                ("refreshToken", "missingAfterDuplicate"),
            ],
            &[],
            false,
            (Some("missingAfterDuplicate"), Some("missingAfterDuplicate")),
        )
        .await?;
        check_runtime(
            store,
            joins,
            &[],
            &[("image", "missingUser")],
            false,
            (None, Some("missingUser")),
        )
        .await?;
        check_runtime(
            store,
            joins,
            &[],
            &[("image", "missingImage"), ("name", "missingName")],
            false,
            (None, Some("missingName")),
        )
        .await?;
        check_runtime(
            store,
            joins,
            &[("accessToken", session_table)],
            &[],
            false,
            (None, None),
        )
        .await?;
        check_runtime(
            store,
            joins,
            &[("accessToken", session_table)],
            &[],
            true,
            (Some(session_table), Some(session_table)),
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn unknown_reference_errors_precede_reads_in_real_stores() -> AuthResult<()> {
    real_paths(
        &EphemeralStore::new(Arc::new(AuthConfig::default())),
        "session",
    )
    .await?;
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    migrator::run_migrations(&database)
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    real_paths(
        &SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database),
        "sessions",
    )
    .await
}
