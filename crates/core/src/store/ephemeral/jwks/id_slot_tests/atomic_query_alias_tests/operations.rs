#![expect(
    clippy::indexing_slicing,
    reason = "Fixture indexing must fail when an expected record or property is missing."
)]

use super::*;
use crate::store::ApiKeyUsageWrite;

pub(super) enum Outcome {
    Record(JsonValue),
    Matched(bool),
    Unit,
}

impl Outcome {
    pub(super) fn verify(self, step: &JsonValue, operation: &str, model: &str) {
        match self {
            Self::Record(value) => assert_eq!(value, step["result"]),
            Self::Matched(value) if operation == "status-delete" => {
                assert_eq!(step["result"], json!({"type":"undefined"}));
                assert_eq!(value, step["before"][model] != step["after"][model]);
            }
            Self::Matched(value) => assert_eq!(value, !step["result"].is_null()),
            Self::Unit if operation == "reset-expired" => {
                // This business API discards the adapter record. The runner compares actual callbacks and storage instead.
            }
            Self::Unit => assert_eq!(step["result"], json!({"type":"undefined"})),
        }
    }
}

pub(super) fn request(
    model: &str,
    operation: &str,
    id: &str,
    owner: &str,
) -> AuthResult<(&'static str, JsonValue)> {
    let selected = json!({"field":"id", "value":id});
    Ok(match operation {
        "findOne" => ("findOne", json!({"model":model, "where":[selected]})),
        "decrement" => (
            "incrementOne",
            json!({
                "model":model,
                "where":[selected, {"field":"remaining", "operator":"gt", "value":0}],
                "increment":{"remaining":-1},
            }),
        ),
        "last-request" => (
            "update",
            json!({
                "model":model, "where":[selected],
                "update":{"lastRequest":observe_value(&date()?.into())?},
            }),
        ),
        "backup-codes" => (
            "incrementOne",
            json!({
                "model":model,
                "where":[selected, {"field":"backupCodes", "value":"ordinary-encrypted-codes"}],
                "increment":{}, "set":{"backupCodes":"ordinary-replaced-codes"},
            }),
        ),
        "record-failure" | "reset-failures" => {
            let method = if operation == "record-failure" {
                "record-failure"
            } else {
                "reset-failures"
            };
            (
                method,
                json!({"model":model,"twoFactor":{"id":id},"now":observe_value(&date()?.into())?}),
            )
        }
        "reset-expired" => (
            "incrementOne",
            json!({
                "model":model,
                "where":[selected, {"field":"lockedUntil", "operator":"lte", "value":observe_value(&deadline()?.into())?}],
                "increment":{}, "set":{"failedVerificationCount":0,"lockedUntil":null},
            }),
        ),
        "claim" => (
            "incrementOne",
            json!({
                "model":model,
                "where":[selected, {"field":"status","value":"pending"}, {"field":"userId","value":null}],
                "increment":{}, "set":{"userId":owner},
            }),
        ),
        "status-update" => (
            "update",
            json!({
                "model":model, "where":[selected, {"field":"status","value":"pending"}],
                "update":{"status":"approved"},
            }),
        ),
        "status-delete" => (
            "delete",
            json!({
                "model":model, "where":[selected, {"field":"status","value":"pending"}],
            }),
        ),
        _ => return Err(AuthError::internal("Unknown atomic ID alias request")),
    })
}

fn deadline() -> AuthResult<crate::FieldDate> {
    Ok((required(date()?.to_datetime()?)? + chrono::Duration::minutes(15)).into())
}

fn record_outcome(value: Option<impl AuthRecordFields>) -> AuthResult<Outcome> {
    Ok(Outcome::Record(
        value
            .map(|value| observe_fields(value.field_values()?, false))
            .transpose()?
            .unwrap_or(JsonValue::Null),
    ))
}

pub(super) async fn execute(
    store: &EphemeralStore,
    operation: &str,
    id: &str,
    owner: &str,
) -> AuthResult<Outcome> {
    let selected = id.to_owned().into();
    match operation {
        "findOne" => record_outcome(store.get_passkey_by_id(id).await?),
        "decrement" => record_outcome(
            store
                .write_api_key_usage(&selected, ApiKeyUsageWrite::Decrement)
                .await?,
        ),
        "last-request" => record_outcome(
            store
                .write_api_key_usage(
                    &selected,
                    ApiKeyUsageWrite::LastRequest(required(date()?.to_datetime()?)?),
                )
                .await?,
        ),
        "backup-codes" => Ok(Outcome::Matched(
            store
                .compare_exchange_two_factor_backup_codes(
                    &selected,
                    &"ordinary-encrypted-codes".into(),
                    "ordinary-replaced-codes".into(),
                )
                .await?,
        )),
        "record-failure" => {
            store
                .record_two_factor_failure(&selected, 1, &deadline)
                .await?;
            Ok(Outcome::Unit)
        }
        "reset-failures" | "reset-expired" => {
            let cutoff = if operation == "reset-expired" {
                Some(deadline()?)
            } else {
                None
            };
            store.reset_two_factor_failures(&selected, cutoff).await?;
            Ok(Outcome::Unit)
        }
        "claim" => Ok(Outcome::Matched(
            store
                .claim_device_code(&selected, &owner.to_owned().into())
                .await?,
        )),
        "status-update" => Ok(Outcome::Matched(
            store
                .update_device_code_if_status(
                    &selected,
                    "pending",
                    crate::UpdateDeviceCode {
                        status: Some("approved".into()),
                        ..Default::default()
                    },
                )
                .await?,
        )),
        "status-delete" => Ok(Outcome::Matched(
            store
                .delete_device_code_if_status(&selected, "pending")
                .await?,
        )),
        _ => Err(AuthError::internal("Unknown atomic ID alias operation")),
    }
}
