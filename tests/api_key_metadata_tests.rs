#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    reason = "contract fixtures fail immediately on invalid setup"
)]
#[path = "api_key_metadata/fixture.rs"]
mod fixture;
use better_auth::server_api::EndpointInput;
use better_auth_core::HttpMethod;
use better_auth_seaorm::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
use fixture::Fixture;
use serde_json::{Value, json};
#[tokio::test]
async fn legacy_metadata_database_and_cache_match_pinned_contracts() {
    let expected: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/api-key-metadata-upstream.json")).unwrap();
    for endpoint in ["get", "list", "update", "verify"] {
        for backend in ["database", "fallback", "cache"] {
            for (scheduling, result) in [
                ("default", "resolve"),
                ("default", "reject"),
                ("handler", "resolve"),
                ("handler", "reject"),
                ("handler-throw", "reject"),
            ] {
                let fixture = Fixture::new(
                    backend,
                    scheduling,
                    Database::connect("sqlite::memory:").await.unwrap(),
                )
                .await;
                if result == "reject" {
                    let _ = fixture.db.execute_unprepared("CREATE TRIGGER reject_metadata BEFORE UPDATE OF metadata ON api_keys WHEN NEW.metadata <> OLD.metadata BEGIN SELECT RAISE(FAIL,'migration-error'); END").await.unwrap();
                }
                let before = fixture.snapshot().await;
                let metadata = fixture.operation(endpoint).await;
                let tasks = fixture.finish().await;
                let after = fixture.snapshot().await;
                let logs = fixture.state.logs.lock().unwrap().clone();
                let actual = json!({"endpoint":endpoint,"backend":backend,"scheduling":scheduling,"result":result,
                    "metadata":metadata,"before":before,"after":after,"taskStates":tasks,
                    "migrationWarnings":logs.iter().filter(|log|*log=="migration-warning").count(),
                    "handlerWarnings":logs.iter().filter(|log|*log=="Failed to run background task:").count()});
                let wanted = expected
                    .iter()
                    .find(|item| {
                        item.get("endpoint").unwrap() == endpoint
                            && item.get("backend").unwrap() == backend
                            && item.get("scheduling").unwrap() == scheduling
                            && item.get("result").unwrap() == result
                    })
                    .unwrap();
                assert_eq!(
                    &actual, wanted,
                    "{endpoint}/{backend}/{scheduling}/{result}"
                );
            }
        }
    }
}

#[tokio::test]
async fn list_pages_schedule_once_and_only_repair_the_returned_legacy_page() {
    for scenario in ["empty", "current", "page", "mixed-cache"] {
        let fixture = Fixture::new(
            if scenario == "mixed-cache" {
                scenario
            } else {
                "database"
            },
            "handler",
            Database::connect("sqlite::memory:").await.unwrap(),
        )
        .await;
        match scenario {
            "empty" => {
                let _ = fixture
                    .db
                    .execute_unprepared("DELETE FROM api_keys")
                    .await
                    .unwrap();
            }
            "current" => {
                for (index, (id, _)) in fixture.keys.iter().enumerate() {
                    let name = if index == 0 { "one" } else { "two" };
                    let _ = fixture
                        .db
                        .execute_raw(Statement::from_sql_and_values(
                            DbBackend::Sqlite,
                            "UPDATE api_keys SET metadata=? WHERE id=?",
                            [json!({"legacy":name}).to_string().into(), id.clone().into()],
                        ))
                        .await
                        .unwrap();
                }
            }
            _ => {}
        }
        let response = fixture
            .auth
            .call_endpoint(
                HttpMethod::Get,
                "/api-key/list",
                EndpointInput {
                    headers: Some([("cookie".into(), fixture.cookie.clone())].into()),
                    query: Some(match scenario {
                        "page" => json!({"offset":"1","limit":"1","sortBy":"name"}),
                        "mixed-cache" => json!({"configId":"cache"}),
                        _ => json!({}),
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(fixture.finish().await, vec!["fulfilled"]);
        let response: Value = serde_json::from_slice(&response.body).unwrap();
        let metadata: Vec<_> = response
            .get("apiKeys")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.get("metadata").unwrap().clone())
            .collect();
        assert_eq!(
            metadata,
            match scenario {
                "empty" => vec![],
                "page" => vec![json!({"legacy":"two"})],
                _ => vec![json!({"legacy":"one"}), json!({"legacy":"two"})],
            }
        );
        let snapshot = fixture.snapshot().await;
        if scenario == "page" {
            assert_eq!(
                snapshot.get("database").unwrap().clone(),
                json!([json!({"legacy":"one"}).to_string(),{"legacy":"two"}])
            );
        }
        if scenario == "mixed-cache" {
            assert_eq!(snapshot.get("database").unwrap().clone(), json!([]));
            assert_eq!(
                snapshot.get("cache").unwrap().clone(),
                json!([
                    json!({"legacy":"one"}).to_string(),
                    json!({"legacy":"two"}).to_string()
                ])
            );
            // Upstream adapter.update returns null for a missing migration target.
            assert!(fixture.state.logs.lock().unwrap().is_empty());
        }
    }
}
