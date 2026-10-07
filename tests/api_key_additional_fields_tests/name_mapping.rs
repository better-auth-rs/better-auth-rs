use super::{contract, fixture, name_mapping_contract};
use better_auth::__private_core::{AuthResult, store::EphemeralStore};
use better_auth::seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use contract::Scenario;
use name_mapping_contract::NameMapping;
use serde_json::{Value, json};
use std::sync::Arc;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[expect(
    clippy::expect_used,
    reason = "The paired contract requires the complete captured backend, mapping, and operation inventory"
)]
fn expected(fixture: &Value, backend: &str, mapping: NameMapping) -> Value {
    assert_eq!(fixture.get("version"), Some(&json!("1.7.6")));
    let backends = fixture
        .get("backends")
        .and_then(Value::as_array)
        .expect("captured backends");
    assert_eq!(
        backends
            .iter()
            .map(|entry| entry.get("backend").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        [Some("memory"), Some("sqlite")]
    );
    let cases = backends
        .iter()
        .find(|entry| entry.get("backend").and_then(Value::as_str) == Some(backend))
        .expect("captured backend")
        .get("cases")
        .and_then(Value::as_array)
        .expect("captured mappings");
    assert_eq!(
        cases
            .iter()
            .map(|entry| entry.get("mapping").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        [Some("default"), Some("empty"), Some("renamed")]
    );
    let selected = cases
        .iter()
        .find(|entry| entry.get("mapping").and_then(Value::as_str) == Some(mapping.label()))
        .expect("selected mapping");
    let operations = selected
        .get("operations")
        .and_then(Value::as_array)
        .expect("captured operations");
    assert_eq!(
        operations
            .iter()
            .map(|entry| entry.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        contract::OPERATIONS.map(Some)
    );
    let failures = selected
        .get("failures")
        .and_then(Value::as_array)
        .expect("captured failures");
    let failure_names = Scenario::all()
        .filter_map(|scenario| match scenario {
            Scenario::Operations => None,
            Scenario::Failure { operation, phase } => Some(format!(
                "{operation}-{}-error",
                if phase == 1 { "input" } else { "output" }
            )),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        failures
            .iter()
            .map(|entry| entry
                .get("name")
                .and_then(Value::as_str)
                .expect("failure name"))
            .collect::<Vec<_>>(),
        failure_names
    );
    selected.clone()
}

#[expect(
    clippy::expect_used,
    reason = "Each operation sequence and original callback failure must match its complete captured observation"
)]
fn compare(observed: &Value, expected: &Value, scenario: Scenario) {
    let expected = match scenario {
        Scenario::Operations => expected.get("operations").expect("captured operations"),
        Scenario::Failure { operation, phase } => {
            let name = format!(
                "{operation}-{}-error",
                if phase == 1 { "input" } else { "output" }
            );
            expected
                .get("failures")
                .and_then(Value::as_array)
                .expect("captured failures")
                .iter()
                .find(|failure| failure.get("name").and_then(Value::as_str) == Some(name.as_str()))
                .expect("captured failure")
        }
    };
    assert_eq!(observed, expected);
}

#[expect(
    clippy::expect_used,
    reason = "Every mapped observation must retain the callback-free final storage rows"
)]
async fn physical_name(
    database: &DatabaseConnection,
    mapping: NameMapping,
    observed: &Value,
) -> TestResult {
    let columns = database
        .query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            "PRAGMA table_info(ordinary_api_key_fields)".to_owned(),
        ))
        .await?;
    let names = columns
        .iter()
        .map(|column| column.try_get::<String>("", "name"))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(names.iter().any(|name| name == mapping.column()));
    if mapping.label() == "renamed" {
        assert!(!names.iter().any(|name| name == "name"));
    }
    let last = match observed.as_array() {
        Some(operations) => operations.last().expect("complete operation sequence"),
        None => observed,
    };
    let expected = last
        .get("stored")
        .and_then(Value::as_array)
        .expect("complete stored rows");
    let rows = database.query_all_raw(Statement::from_string(DbBackend::Sqlite, format!(
        "SELECT \"{}\" AS stored_name, stored_key, stored_owner FROM ordinary_api_key_fields", mapping.column()
    ))).await?;
    assert_eq!(rows.len(), expected.len());
    for (row, expected) in rows.iter().zip(expected) {
        assert_eq!(
            json!(row.try_get::<Option<String>>("", "stored_name")?),
            *expected.get("name").expect("stored name")
        );
        assert_eq!(
            row.try_get::<String>("", "stored_key")?,
            "ordinary-stored-hash"
        );
        assert_eq!(row.try_get::<String>("", "stored_owner")?, "ordinary-owner");
    }
    Ok(())
}

#[tokio::test]
async fn memory_api_key_name_mappings_match_complete_upstream_operations_and_errors()
-> AuthResult<()> {
    let fixture =
        serde_json::from_str(include_str!("../fixtures/api-key-name-mapping-1.7.6.json"))?;
    for mapping in NameMapping::ALL {
        let expected = expected(&fixture, "memory", mapping);
        for scenario in Scenario::all() {
            let observed = name_mapping_contract::observe_name_mapping(
                Arc::new(EphemeralStore::new(Arc::new(contract::config()))),
                mapping,
                scenario,
            )
            .await?;
            compare(&observed, &expected, scenario);
        }
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_api_key_name_mappings_match_complete_upstream_operations_and_errors() -> TestResult
{
    let captured =
        serde_json::from_str(include_str!("../fixtures/api-key-name-mapping-1.7.6.json"))?;
    for mapping in NameMapping::ALL {
        let expected = expected(&captured, "sqlite", mapping);
        for scenario in Scenario::all() {
            let (observed, database) = if mapping.label() == "renamed" {
                let (store, database) =
                    fixture::sqlite_for::<fixture::renamed::Model>(contract::config()).await;
                (
                    name_mapping_contract::observe_name_mapping(Arc::new(store), mapping, scenario)
                        .await?,
                    database,
                )
            } else {
                let (store, database) = fixture::sqlite(contract::config()).await;
                (
                    name_mapping_contract::observe_name_mapping(Arc::new(store), mapping, scenario)
                        .await?,
                    database,
                )
            };
            compare(&observed, &expected, scenario);
            physical_name(&database, mapping, &observed).await?;
            database.close().await?;
        }
    }
    Ok(())
}
