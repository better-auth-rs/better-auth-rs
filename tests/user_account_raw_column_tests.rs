#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::panic_in_result_fn,
    reason = "The paired SQL contract must fail on malformed cases or changed join shapes"
)]

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, CreateAccount, CreateUser, FieldMap,
    store::{AccountStore, JoinValue, UserStore},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[path = "support/user_runtime_output_contract.rs"]
#[expect(
    dead_code,
    reason = "The shared contract also supplies Memory output and cache helpers"
)]
mod contract;

type Events = Arc<Mutex<Vec<Value>>>;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn config(cases: &Value, joins: bool, reject: bool, events: &Events) -> AuthConfig {
    let mut config = AuthConfig::default();
    config.advanced.database.joins = Some(joins);
    for field in cases["fields"].as_array().unwrap() {
        let model = field["model"].as_str().unwrap();
        let name = field["name"].as_str().unwrap();
        let label = format!("{model}.{name}");
        let replacement = field.get("replacement").cloned();
        let events = events.clone();
        let declaration = UserFieldConfig {
            field_type: match field["type"].as_str().unwrap() {
                "boolean" => UserFieldType::Boolean,
                "date" => UserFieldType::Date,
                _ => UserFieldType::String,
            },
            required: Some(false),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    events
                        .lock()
                        .unwrap()
                        .push(json!([label, contract::observe(&value)?]));
                    if reject && label == "account.accessTokenExpiresAt" {
                        return Err(AuthError::internal("raw-column-stop"));
                    }
                    replacement
                        .as_ref()
                        .map(contract::revive)
                        .unwrap_or(Ok(value))
                })),
                ..Default::default()
            }),
            ..Default::default()
        };
        let _ = if model == "user" {
            config.user.fields_mut().insert(name.into(), declaration)
        } else {
            config
                .account
                .additional_fields
                .insert(name.into(), declaration)
        };
    }
    config
}

async fn seed(database: &DatabaseConnection) -> TestResult {
    let writer = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database.clone());
    let _ = writer
        .create_user(CreateUser {
            id: Some(contract::OWNER.into()),
            ..CreateUser::new()
                .with_name("Owner")
                .with_email(contract::EMAIL)
        })
        .await?;
    let _ = writer
        .create_account(CreateAccount {
            id: "runtime-account".into(),
            user_id: contract::OWNER.into(),
            provider_id: "provider".into(),
            account_id: "subject".into(),
            access_token: Some("stored-token".into()).into(),
            password: Some("stored-password".into()).into(),
            ..Default::default()
        })
        .await?;
    let _ = database
        .execute_unprepared(
            "UPDATE users SET email_verified = 'stored-boolean', created_at = 'not-a-date'",
        )
        .await?;
    let _ = database
        .execute_unprepared("UPDATE accounts SET access_token_expires_at = 'not-a-date'")
        .await?;
    Ok(())
}

async fn snapshot(database: &DatabaseConnection) -> TestResult<Value> {
    let mut rows = Vec::new();
    for sql in [
        "SELECT json_object('count', COUNT(*), 'id', id, 'email', email, 'emailVerified', email_verified, 'createdAt', created_at) AS snapshot FROM users",
        "SELECT json_object('count', COUNT(*), 'id', id, 'userId', user_id, 'accessToken', access_token, 'accessTokenExpiresAt', access_token_expires_at, 'password', password) AS snapshot FROM accounts",
    ] {
        let row = database
            .query_one_raw(Statement::from_string(DbBackend::Sqlite, sql))
            .await?
            .unwrap();
        rows.push(serde_json::from_str::<Value>(
            &row.try_get::<String>("", "snapshot")?,
        )?);
    }
    Ok(rows.into())
}

async fn read(
    store: &SeaOrmStore<BundledSchema>,
    operation: &str,
) -> AuthResult<Vec<(&'static str, FieldMap)>> {
    Ok(match operation {
        "user" => vec![(
            "user",
            FieldMap::from(store.get_user_by_id(contract::OWNER).await?.unwrap()),
        )],
        "account" => vec![(
            "account",
            store
                .get_account("provider", "subject")
                .await?
                .unwrap()
                .internal_fields()?,
        )],
        "owner" => {
            let owner = store
                .get_account_owner("provider", "subject")
                .await?
                .unwrap();
            let JoinValue::One(Some(user)) = owner.user else {
                panic!("The Account must have one User owner");
            };
            vec![
                ("account", owner.account.internal_fields()?),
                ("user", user.into()),
            ]
        }
        "accounts" => {
            let joined = store
                .get_user_with_accounts(contract::EMAIL)
                .await?
                .unwrap();
            let JoinValue::Many(accounts) = joined.accounts else {
                panic!("The User must return its Account page");
            };
            assert_eq!(accounts.len(), 1);
            vec![
                ("user", joined.user.into()),
                ("account", accounts[0].internal_fields()?),
            ]
        }
        _ => panic!("Unknown raw-column operation"),
    })
}

#[tokio::test]
async fn sqlite_raw_user_and_account_columns_reach_callbacks_before_any_typed_decode() -> TestResult
{
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/user-account-raw-column-cases.json"))?;
    for joins in [false, true] {
        let database = Database::connect("sqlite::memory:").await?;
        migrator::run_migrations(&database).await?;
        seed(&database).await?;
        let before = snapshot(&database).await?;
        for reject in [false, true] {
            let events = Events::default();
            let store = SeaOrmStore::<BundledSchema>::new(
                config(&cases, joins, reject, &events),
                database.clone(),
            );
            for operation in cases["operations"].as_array().unwrap() {
                events.lock().unwrap().clear();
                let name = operation["name"].as_str().unwrap();
                let result = read(&store, name).await;
                let mut expected_events = Vec::new();
                let mut failed = false;
                for model in operation["models"].as_array().unwrap() {
                    for field in cases["fields"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|field| field["model"] == *model)
                    {
                        let label = format!(
                            "{}.{}",
                            model.as_str().unwrap(),
                            field["name"].as_str().unwrap()
                        );
                        expected_events.push(json!([label, field["raw"]]));
                        if reject && label == "account.accessTokenExpiresAt" {
                            failed = true;
                            break;
                        }
                    }
                    if failed {
                        break;
                    }
                }
                assert_eq!(
                    *events.lock().unwrap(),
                    expected_events,
                    "joins={joins}, reject={reject}, {name}"
                );
                if failed {
                    assert_eq!(
                        result.unwrap_err().instrumentation_message(),
                        "raw-column-stop"
                    );
                } else {
                    for (model, record) in result? {
                        for field in cases["fields"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .filter(|field| field["model"] == model)
                        {
                            assert_eq!(
                                contract::observe(&record[field["name"].as_str().unwrap()])?,
                                field["expected"],
                                "joins={joins}, {name}, {model}"
                            );
                        }
                    }
                }
                assert_eq!(
                    snapshot(&database).await?,
                    before,
                    "joins={joins}, reject={reject}, {name}"
                );
            }
        }
    }
    Ok(())
}
