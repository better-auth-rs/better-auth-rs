use super::*;
use better_auth_core::plugin_runtime::ModelFields;

#[derive(Clone, Copy, Debug)]
enum Scenario {
    MissingUserField,
    MissingForwardAccountField,
    MissingReverseAccountField,
    MultipleBeforeMissingField,
    UndeclaredPluginField,
    UnvisitedUnrelatedField,
    PrimaryId,
    PrimaryIdAlias,
}

fn field_reference(model: &str, field: &str) -> UserFieldConfig {
    UserFieldConfig {
        references: Some(UserFieldReference {
            model: model.into(),
            field: field.into(),
        }),
        ..Default::default()
    }
}

fn configured(scenario: Scenario, joins: bool, events: &Events) -> AuthConfig {
    let mut config = AuthConfig::default();
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    config.advanced.database.joins = Some(joins);
    let _ = config
        .user
        .fields_mut()
        .insert("name".into(), output("user.name", events));
    let _ = config
        .account
        .additional_fields
        .insert("accountId".into(), output("account.accountId", events));
    match scenario {
        Scenario::MissingUserField | Scenario::MultipleBeforeMissingField => {
            let _ = config
                .account
                .additional_fields
                .insert("userId".into(), field_reference("user", "missingUserField"));
            if matches!(scenario, Scenario::MultipleBeforeMissingField) {
                let _ = config
                    .account
                    .additional_fields
                    .insert("accessToken".into(), field_reference("user", "id"));
            }
        }
        Scenario::MissingForwardAccountField | Scenario::MissingReverseAccountField => {
            let _ = config.user.fields_mut().insert(
                "image".into(),
                field_reference("account", "missingAccountField"),
            );
            if matches!(scenario, Scenario::MissingReverseAccountField) {
                let _ = config
                    .account
                    .additional_fields
                    .insert("userId".into(), UserFieldConfig::default());
            }
        }
        Scenario::UndeclaredPluginField => {
            let _ = config
                .account
                .additional_fields
                .insert("userId".into(), field_reference("user", "username"));
        }
        Scenario::UnvisitedUnrelatedField => {
            let _ = config.account.additional_fields.insert(
                "accessToken".into(),
                field_reference("session", "missingSessionField"),
            );
        }
        Scenario::PrimaryId | Scenario::PrimaryIdAlias => {
            let field = if matches!(scenario, Scenario::PrimaryId) {
                "id"
            } else {
                "_id"
            };
            let _ = config
                .account
                .additional_fields
                .insert("userId".into(), field_reference("user", field));
        }
    }
    config
}

fn expected_error(scenario: Scenario, operation: Operation) -> Option<String> {
    match scenario {
        Scenario::MissingUserField => Some("Field missingUserField not found in model user".into()),
        Scenario::MissingForwardAccountField if operation == Operation::Accounts => None,
        Scenario::MissingForwardAccountField | Scenario::MissingReverseAccountField => {
            Some("Field missingAccountField not found in model account".into())
        }
        Scenario::MultipleBeforeMissingField => {
            let (model, base) = match operation {
                Operation::Accounts => ("account", "user"),
                Operation::Owner => ("user", "account"),
            };
            Some(format!(
                "Multiple foreign keys found for model {model} and base model {base} while performing join operation. Only one foreign key is supported."
            ))
        }
        Scenario::UndeclaredPluginField => Some("Field username not found in model user".into()),
        Scenario::UnvisitedUnrelatedField | Scenario::PrimaryId | Scenario::PrimaryIdAlias => None,
    }
}

async fn verify<S: AuthSchema>(store: &impl AuthStore<S>) -> AuthResult<()> {
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
    for scenario in [
        Scenario::MissingUserField,
        Scenario::MissingForwardAccountField,
        Scenario::MissingReverseAccountField,
        Scenario::MultipleBeforeMissingField,
        Scenario::UndeclaredPluginField,
        Scenario::UnvisitedUnrelatedField,
        Scenario::PrimaryId,
        Scenario::PrimaryIdAlias,
    ] {
        for joins in [false, true] {
            let events = Events::default();
            let view = store.with_runtime(
                Arc::new(configured(scenario, joins, &events)),
                Vec::new(),
                ModelFields::default(),
            )?;
            for operation in [Operation::Accounts, Operation::Owner] {
                let result = async {
                    match operation {
                        Operation::Accounts => view.get_user_with_accounts(EMAIL).await.map(|row| row.map(|joined| {
                            let account = |account: &AccountView| json!({"id": account.id, "userId": account.user_id});
                            let accounts = match joined.accounts {
                                JoinValue::One(row) => row.as_ref().map_or(Value::Null, account),
                                JoinValue::Many(rows) => json!(rows.iter().map(account).collect::<Vec<_>>()),
                            };
                            json!({"user": joined.user.id, "accounts": accounts})
                        })),
                        Operation::Owner => view.get_account_owner("provider", "external-owner").await.map(|row| row.map(|joined| {
                            let owner = match joined.user {
                                JoinValue::One(user) => json!(user.map(|user| user.id)),
                                JoinValue::Many(users) => json!(users.into_iter().map(|user| user.id).collect::<Vec<_>>()),
                            };
                            json!({"account": joined.account.id, "userId": joined.account.user_id, "owner": owner})
                        })),
                    }
                }.with_subscriber(tracing_subscriber::registry().with(events.clone())).await;
                let observed = events.take();
                if let Some(error) = expected_error(scenario, operation) {
                    assert_eq!(
                        result.err().map(|error| error.instrumentation_message()),
                        Some(error),
                        "{scenario:?}/{operation:?}/joins={joins}"
                    );
                    assert!(
                        observed.is_empty(),
                        "Reference field errors must precede all queries and callbacks"
                    );
                } else {
                    let expected = match operation {
                        Operation::Accounts => {
                            json!({"user": "owner", "accounts": [{"id": "account", "userId": "owner"}]})
                        }
                        Operation::Owner => {
                            json!({"account": "account", "userId": "owner", "owner": "owner"})
                        }
                    };
                    assert_eq!(
                        result?,
                        Some(expected),
                        "{scenario:?}/{operation:?}/joins={joins}"
                    );
                    assert!(
                        observed
                            .iter()
                            .any(|event| event.get(0) == Some(&json!("query")))
                    );
                    assert!(
                        observed
                            .iter()
                            .any(|event| event.get(0) == Some(&json!("output")))
                    );
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn reference_field_resolution_precedes_reads_and_preserves_owner_bindings() -> AuthResult<()>
{
    verify(&EphemeralStore::new(Arc::new(AuthConfig::default()))).await?;
    let database = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    migrator::run_migrations(&database)
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    verify(&SeaOrmStore::<BundledSchema>::new(
        AuthConfig::default(),
        database,
    ))
    .await
}
