use super::{Case, load_fixture, visible};
use better_auth_core::{
    AuthError, AuthResult, AuthSchema, AuthStore, DeviceCode, DeviceCodeOwnership,
    store::transaction,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Default)]
pub(super) enum Entry {
    #[default]
    Where,
    FieldEquals,
    FieldIn,
    FieldNotIn,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Rollback {
    result: Value,
    after_consume: Vec<Value>,
    original_error: bool,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Storage {
    before: BTreeMap<String, Vec<Value>>,
    after: BTreeMap<String, Vec<Value>>,
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract must reject incomplete fixture inventories and storage observations"
)]
pub(crate) fn load_references(
    backend: &str,
) -> Result<Vec<Case>, Box<dyn std::error::Error + Send + Sync>> {
    let fixture = load_fixture(backend, "device-where-references")?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.backend, backend);
    assert_eq!(fixture.id_generation.as_deref(), Some("default"));
    assert_eq!(fixture.groups.len(), 1);
    let group = fixture
        .groups
        .into_iter()
        .next()
        .ok_or("The reference fixture must contain its default-ID group")?;
    assert!(!group.serial);
    let expected = ["logical", "physical"]
        .into_iter()
        .flat_map(|prefix| {
            [
                "success",
                "owner-mismatch",
                "transaction-commit",
                "rollback",
                "id-mismatch",
                "deviceCode-mismatch",
                "clientId-mismatch",
                "userId-mismatch",
                "status-mismatch",
            ]
            .map(|suffix| format!("{prefix}-reference-{suffix}"))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(group.cases.len(), 18);
    assert_eq!(
        group
            .cases
            .iter()
            .map(|case| case.name.clone())
            .collect::<BTreeSet<_>>(),
        expected
    );
    for case in &group.cases {
        validate_storage(case)?;
        let query = case
            .condition
            .get(1)
            .ok_or("The captured reference condition must exist")?;
        let value = query
            .get("value")
            .and_then(Value::as_str)
            .ok_or("The captured reference equality must retain its string")?;
        assert_eq!(
            query,
            &json!({"field": if case.name.starts_with("physical-") {
                "stored_ownerRef"
            } else {
                "ownerRef"
            }, "operator": "eq", "value": value})
        );
    }
    eprintln!(
        "Device reference pairing compares all Device field values and callbacks, plus the complete owner view. The public store cannot enumerate raw User, Session, Account, Verification, or transaction Device tables; those complete table snapshots remain upstream-only."
    );
    Ok(group
        .cases
        .into_iter()
        .flat_map(|case| {
            let equals = Case {
                entry: Entry::FieldEquals,
                ..case.clone()
            };
            [case, equals]
        })
        .collect())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The paired contract must retain every table, transaction, and rollback observation"
)]
pub(super) fn validate_storage(
    case: &Case,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let storage = case
        .storage
        .as_ref()
        .ok_or("Each reference case must retain all upstream storage observations")?;
    let tables = ["account", "deviceCode", "session", "user", "verification"];
    assert_eq!(
        storage
            .before
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        tables
    );
    assert_eq!(
        storage.after.keys().map(String::as_str).collect::<Vec<_>>(),
        tables
    );
    assert_eq!(storage.before.get("deviceCode"), Some(&case.before));
    assert_eq!(storage.after.get("deviceCode"), Some(&case.after));
    for model in ["user", "session", "account", "verification"] {
        assert_eq!(storage.after.get(model), storage.before.get(model));
    }
    assert_eq!(case.rollback.is_some(), case.name.ends_with("-rollback"));
    assert_eq!(
        case.transaction,
        case.name.ends_with("-transaction-commit") || case.rollback.is_some()
    );
    Ok(())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Every captured native binding must remain a separate consumption guard"
)]
fn expected_bindings(case: &Case, seeded: &DeviceCode) -> AuthResult<DeviceCode> {
    let reference_field = case
        .condition
        .get(1)
        .and_then(|query| query.get("field"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AuthError::internal("The captured ownership condition must name its field")
        })?;
    assert!(matches!(reference_field, "ownerRef" | "stored_ownerRef"));
    assert_eq!(
        case.condition
            .iter()
            .map(|query| query.get("field").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        [
            "id",
            reference_field,
            "deviceCode",
            "clientId",
            "userId",
            "status"
        ]
        .map(Some)
    );
    let mut expected = seeded.clone();
    for query in &case.condition {
        let field = query
            .get("field")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::internal("The captured binding must name its field"))?;
        if field == reference_field {
            let operator = query
                .get("operator")
                .and_then(Value::as_str)
                .ok_or_else(|| AuthError::internal("The captured ownership operator must exist"))?;
            assert!(matches!(operator, "eq" | "ne" | "in" | "not_in"));
            let value = query
                .get("value")
                .ok_or_else(|| AuthError::internal("The captured ownership operand must exist"))?;
            assert_eq!(
                query,
                &json!({"field": field, "operator": operator, "value": value})
            );
            continue;
        }
        let value = query
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::internal("The captured binding must retain its string"))?;
        assert_eq!(query, &json!({"field": field, "value": value}));
        match field {
            "id" => {
                expected.id = if value == "<device-id>" {
                    seeded.id.clone()
                } else {
                    value.to_owned().into()
                };
            }
            "deviceCode" => expected.device_code = value.into(),
            "clientId" => expected.client_id = Some(value.to_owned()).into(),
            "userId" => expected.user_id = Some(value.to_owned()).into(),
            "status" => expected.status = value.into(),
            _ => return Err(AuthError::internal("Unexpected native Device guard")),
        }
    }
    Ok(expected)
}

pub(super) async fn consume<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    case: &Case,
    seeded: &DeviceCode,
    ownership: DeviceCodeOwnership,
) -> AuthResult<Option<DeviceCode>> {
    let expected = expected_bindings(case, seeded)?;
    if !case.transaction {
        return store.consume_device_code(&expected, &ownership).await;
    }
    let rollback = case.rollback.clone();
    let seeded = seeded.clone();
    let message = case.error.as_ref().map(|error| error.message.clone());
    let allocation = message.as_ref().map(|message| message.as_ptr().addr());
    let outcome = transaction(store, move |tx| {
        Box::pin(async move {
            let consumed = tx.consume_device_code(&expected, &ownership).await?;
            if let Some(rollback) = rollback {
                let row = consumed.as_ref().ok_or_else(|| {
                    AuthError::internal("Rollback must follow successful Device consumption")
                })?;
                assert_eq!(visible(row, &seeded)?, rollback.result);
                assert!(rollback.original_error);
                assert!(rollback.after_consume.is_empty());
                assert!(
                    tx.get_device_code_by_device_code(seeded.device_code.typed()?)
                        .await?
                        .is_none()
                );
                assert!(
                    tx.get_device_code_by_user_code(seeded.user_code.typed()?)
                        .await?
                        .is_none()
                );
                return Err(AuthError::Internal(message.ok_or_else(|| {
                    AuthError::internal("The rollback fixture must capture its error")
                })?));
            }
            Ok(consumed)
        })
    })
    .await;
    if case.rollback.is_some() {
        let Err(AuthError::Internal(message)) = &outcome else {
            return Err(AuthError::internal(format!(
                "Rollback must preserve the original error, received {outcome:?}"
            )));
        };
        assert_eq!(Some(message.as_ptr().addr()), allocation);
    }
    outcome
}
