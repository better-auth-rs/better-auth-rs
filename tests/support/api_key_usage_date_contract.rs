use super::{Fixture, adapter_value, policies, take};
use better_auth::__private_core::{
    ApiKey, AuthError, AuthResult, AuthSchema, AuthStore, FieldDate, FieldValue, UpdateApiKey,
    store::ApiKeyUsageWrite,
};
use better_auth::seaorm::sea_orm::entity::prelude::DateTimeUtc;
use serde_json::{Value, json};
use std::sync::Arc;

const OPERATIONS: [&str; 10] = [
    "create",
    "seed-dates",
    "refill-some-equal",
    "refill-some-miss",
    "refill-from-readback",
    "start-window-equal",
    "increment-window-equal-miss",
    "increment-window-after",
    "last-request",
    "updated-at",
];

fn timestamp(input: &Value, name: &str) -> AuthResult<DateTimeUtc> {
    input
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| AuthError::internal(format!("Missing usage Date input: {name}")))?
        .parse()
        .map_err(|error| AuthError::internal(format!("Invalid usage Date {name}: {error}")))
}

#[expect(
    clippy::expect_used,
    clippy::panic_in_result_fn,
    reason = "The paired contract verifies complete identity and Date values before normalizing creation clocks"
)]
fn visible(row: &ApiKey, seed: &ApiKey, updated: (&FieldDate, Option<&str>)) -> AuthResult<Value> {
    assert_eq!(row.id, seed.id);
    assert_eq!(row.created_at, seed.created_at);
    assert_eq!(&row.updated_at, updated.0);
    let mut value = adapter_value(row)?;
    let object = value.as_object_mut().expect("complete API Key record");
    let _ = object.insert("id".into(), json!("<api-key-id>"));
    let _ = object.insert("createdAt".into(), json!("<created-at>"));
    if let Some(label) = updated.1 {
        let _ = object.insert("updatedAt".into(), json!(label));
    }
    Ok(value)
}

#[expect(
    clippy::expect_used,
    clippy::panic_in_result_fn,
    reason = "The contract requires every pinned operation and checks guarded writes before comparing complete observations"
)]
pub(crate) async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let captured: Value =
        serde_json::from_str(include_str!("../fixtures/api-key-date-usage-1.7.6.json"))?;
    assert_eq!(captured.get("version"), Some(&json!("1.7.6")));
    let backends = captured
        .get("backends")
        .and_then(Value::as_array)
        .expect("captured backends");
    let expected = backends
        .iter()
        .find(|backend| backend.get("backend") == Some(&json!("sqlite")))
        .and_then(|backend| backend.get("operations"))
        .and_then(Value::as_array)
        .expect("captured SQLite operations");
    assert_eq!(
        expected
            .iter()
            .map(|operation| operation.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        OPERATIONS.map(Some),
    );
    let fixture = Fixture::new(raw, false, policies).await?;
    let mut seed: Option<ApiKey> = None;
    let mut updated: Option<FieldDate> = None;
    let mut updated_label = Some("<created-at>");
    let mut observations = Vec::new();
    for operation in expected {
        let name = operation
            .get("name")
            .and_then(Value::as_str)
            .expect("operation name");
        let mut input = operation.get("input").expect("operation input").clone();
        let rows = if name == "create" {
            fixture.execute("create", None).await?
        } else {
            let seed = seed.as_ref().expect("created API Key");
            let row = if name == "seed-dates" {
                fixture
                    .store
                    .update_api_key_optional(
                        &seed.id,
                        UpdateApiKey {
                            last_refill_at: Some(Some(timestamp(&input, "lastRefillAt")?.into())),
                            last_request: Some(Some(timestamp(&input, "lastRequest")?.into())),
                            ..Default::default()
                        },
                    )
                    .await?
            } else {
                if name == "refill-from-readback" {
                    let readback = fixture
                        .reader
                        .get_api_key_by_id(seed.id.typed()?)
                        .await?
                        .expect("persisted API Key");
                    let previous = readback.last_refill_at.expect("persisted refill Date");
                    let previous = FieldValue::Date(previous)
                        .json()?
                        .expect("persisted refill Date JSON");
                    let _ = input
                        .as_object_mut()
                        .expect("operation input object")
                        .insert("previous".into(), previous);
                }
                let at = timestamp(&input, "at")?;
                let write = match name {
                    "refill-some-equal" | "refill-some-miss" | "refill-from-readback" => {
                        ApiKeyUsageWrite::Refill {
                            previous: Some(timestamp(&input, "previous")?),
                            remaining: input
                                .get("remaining")
                                .and_then(Value::as_f64)
                                .expect("refill amount"),
                            at,
                        }
                    }
                    "start-window-equal" => ApiKeyUsageWrite::StartWindow {
                        previous_before: Some(timestamp(&input, "previousBefore")?),
                        at,
                    },
                    "increment-window-equal-miss" | "increment-window-after" => {
                        ApiKeyUsageWrite::IncrementWindow {
                            previous_after: timestamp(&input, "previousAfter")?,
                            maximum: input
                                .get("maximum")
                                .and_then(Value::as_f64)
                                .expect("window maximum"),
                            at,
                        }
                    }
                    "last-request" => ApiKeyUsageWrite::LastRequest(at),
                    "updated-at" => {
                        updated = Some(at.into());
                        updated_label = None;
                        ApiKeyUsageWrite::UpdatedAt(at)
                    }
                    _ => return Err(AuthError::internal("Unknown API Key usage Date operation")),
                };
                fixture.store.write_api_key_usage(&seed.id, write).await?
            };
            row.into_iter().collect()
        };
        assert_eq!(rows.len(), usize::from(!name.ends_with("-miss")), "{name}");
        if name == "create" {
            let created = rows.first().expect("created API Key").clone();
            assert_eq!(created.updated_at, created.created_at);
            updated = Some(created.updated_at.clone());
            seed = Some(created);
        } else if name == "seed-dates" {
            let row = rows.first().expect("updated API Key");
            assert!(row.updated_at.milliseconds() >= row.created_at.milliseconds());
            updated = Some(row.updated_at.clone());
            updated_label = Some("<ordinary-updated-at>");
        }
        let seed = seed.as_ref().expect("created API Key");
        let updated = (
            updated.as_ref().expect("expected update Date"),
            updated_label,
        );
        let result = rows
            .iter()
            .map(|row| visible(row, seed, updated))
            .collect::<AuthResult<Vec<_>>>()?;
        let events = take(&fixture.events);
        let stored = fixture
            .reader
            .find_api_keys_by_reference("ordinary-owner", None)
            .await?;
        assert_eq!(stored.len(), 1);
        let stored = stored
            .iter()
            .map(|row| visible(row, seed, updated))
            .collect::<AuthResult<Vec<_>>>()?;
        observations.push(
            json!({"name":name,"input":input,"events":events,"result":result,"stored":stored}),
        );
    }
    assert_eq!(&observations, expected);
    Ok(())
}
