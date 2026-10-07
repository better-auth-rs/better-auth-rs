use super::{Case, Fixture, load_fixture, references};
use better_auth_core::{AuthError, AuthResult};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn inventory(serial: bool) -> BTreeMap<String, Value> {
    let prefix = if serial { "serial" } else { "default" };
    let owner = if serial { "1" } else { "ordinary-owner" };
    let miss = if serial { "2" } else { "other-owner" };
    let mut cases = BTreeMap::new();
    let mut add = |suffix: &str, operator: &str, physical: bool, value: Value| {
        assert!(
            cases
                .insert(
                    format!("{prefix}-reference-{suffix}"),
                    json!({
                        "field": if physical { "stored_ownerRef" } else { "ownerRef" },
                        "operator": operator,
                        "value": value,
                    }),
                )
                .is_none()
        );
    };
    for (suffix, operator, physical, value) in [
        ("in-owner", "in", false, json!([owner])),
        ("in-miss", "in", true, json!([miss])),
        ("in-empty", "in", false, json!([])),
        ("in-owner-null", "in", true, json!([owner, null])),
        ("not-in-owner", "not_in", false, json!([owner])),
        ("not-in-miss", "not_in", true, json!([miss])),
        ("not-in-empty", "not_in", false, json!([])),
        ("not-in-miss-null", "not_in", true, json!([miss, null])),
        ("in-transaction-commit", "in", false, json!([owner])),
        ("not-in-transaction-rollback", "not_in", true, json!([miss])),
    ] {
        add(suffix, operator, physical, value);
    }
    if !serial {
        for operator in ["in", "not_in"] {
            for guard in ["id", "deviceCode", "clientId", "userId", "status"] {
                add(
                    &format!("{operator}-{guard}-mismatch"),
                    operator,
                    operator == "not_in",
                    json!([if operator == "in" { owner } else { miss }]),
                );
            }
        }
    }
    cases
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The pairing must retain all captured candidates and independent native guards"
)]
pub(crate) fn load_reference_sets(
    backend: &str,
) -> Result<Fixture, Box<dyn std::error::Error + Send + Sync>> {
    let mut fixture = load_fixture(backend, "device-reference-sets")?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.backend, backend);
    assert!(fixture.id_generation.is_none());
    assert_eq!(
        fixture
            .groups
            .iter()
            .map(|group| group.serial)
            .collect::<Vec<_>>(),
        [false, true]
    );
    for group in &mut fixture.groups {
        let expected = inventory(group.serial);
        assert_eq!(group.cases.len(), if group.serial { 10 } else { 20 });
        assert_eq!(
            group
                .cases
                .iter()
                .map(|case| case.name.as_str())
                .collect::<std::collections::BTreeSet<_>>(),
            expected.keys().map(String::as_str).collect()
        );
        let mut paired = Vec::new();
        for case in std::mem::take(&mut group.cases) {
            references::validate_storage(&case)?;
            assert_eq!(case.condition.get(1), expected.get(&case.name));
            let query = case
                .condition
                .get(1)
                .ok_or("The captured reference set must exist")?;
            let entry = match query.get("operator").and_then(Value::as_str) {
                Some("in") => references::Entry::FieldIn,
                Some("not_in") => references::Entry::FieldNotIn,
                _ => return Err("The captured reference must use in or not_in".into()),
            };
            paired.push(Case {
                entry,
                ..case.clone()
            });
            paired.push(case);
        }
        assert_eq!(paired.len(), if group.serial { 20 } else { 40 });
        group.cases = paired;
    }
    Ok(fixture)
}

pub(super) const MYSQL_SYNTAX_PREFIX: &str = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '";

pub(super) fn compare_mysql_syntax_error(case: &str, upstream: &str, rust: &str) -> AuthResult<()> {
    let message = rust
        .strip_prefix("Query Error: error returned from database: 1064 (42000): ")
        .ok_or_else(|| {
            AuthError::internal(format!(
                "{case} must retain the MySQL 1064 diagnostic: {rust}"
            ))
        })?;
    let near = |message: &str| {
        message
            .strip_prefix(MYSQL_SYNTAX_PREFIX)
            .and_then(|message| message.strip_suffix("' at line 1"))
            .filter(|fragment| fragment.starts_with(')'))
            .map(str::to_owned)
            .ok_or_else(|| {
                AuthError::internal(format!(
                    "{case} must retain the complete empty-set syntax diagnostic: {message}"
                ))
            })
    };
    let upstream_near = near(upstream)?;
    let rust_near = near(message)?;
    // SQLx prepares placeholders; mysql2 interpolates values before the server parses the SQL.
    eprintln!(
        "{}",
        json!({
            "contract": "device-reference-sets",
            "case": case,
            "backend": "mysql",
            "unpaired": "SQL near fragments retain different query text and are not compared byte for byte",
            "upstream": upstream,
            "rust": rust,
            "upstreamNear": upstream_near,
            "rustNear": rust_near,
        })
    );
    Ok(())
}
