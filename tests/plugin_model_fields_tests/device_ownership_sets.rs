#![expect(
    clippy::expect_used,
    reason = "The paired contract must fail on changed identities, incomplete observations, or fixture drift"
)]

use super::*;
use better_auth::plugins::{
    DeviceAuthorizationPlugin,
    device_authorization::{
        DeviceCodeOwnership, DeviceCodeRedemptionAuthorization, redeem_device_code,
    },
    endpoint_context::EndpointContext,
};
use better_auth_core::{
    CreateDeviceCode, DeviceCode, UpdateDeviceCode,
    store::{AuthTransaction, DeviceCodeStore, transaction},
    wire::UserView,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

const CASES: [(&str, &str); 13] = [
    ("scope-in-match-after-prepare", "direct"),
    ("tenant-alias-in-mismatch-after-prepare", "direct"),
    ("tenant-not-in-match-after-prepare", "direct"),
    ("tenant-not-in-mismatch-after-prepare", "direct"),
    ("revision-in-numbers", "direct"),
    ("revision-in-numeric-strings", "direct"),
    ("revision-not-in-numeric-strings", "direct"),
    ("revision-in-mixed-strings", "direct"),
    ("tenant-in-empty", "direct"),
    ("tenant-not-in-empty", "direct"),
    ("tenant-null-not-in", "direct"),
    ("scope-in-match-after-prepare", "transaction"),
    ("tenant-alias-in-mismatch-after-prepare", "transaction"),
];

#[derive(Deserialize, Serialize)]
struct OwnershipWhere {
    field: String,
    operator: SetOperator,
    value: Vec<Value>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SetOperator {
    In,
    NotIn,
}

impl OwnershipWhere {
    fn condition(&self) -> DeviceCodeOwnership {
        match self.operator {
            SetOperator::In => DeviceCodeOwnership::FieldIn {
                field: self.field.clone(),
                values: self.value.clone(),
            },
            SetOperator::NotIn => DeviceCodeOwnership::FieldNotIn {
                field: self.field.clone(),
                values: self.value.clone(),
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    mode: String,
    ownership_where: OwnershipWhere,
}

struct Observation {
    seeded: DeviceCode,
    owner: UserView,
    decoy: DeviceCode,
    decoy_owner: UserView,
    started_at: DateTime<Utc>,
    events: Mutex<Vec<Value>>,
    inside_remaining: Mutex<Option<Value>>,
}

impl Observation {
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The contract asserts Device identity and timestamps while propagating serialization errors."
    )]
    fn device(&self, row: &DeviceCode) -> AuthResult<Value> {
        let decoy = row.id == self.decoy.id;
        let (source, owner, id, owner_id) = if decoy {
            (
                &self.decoy,
                &self.decoy_owner,
                "<decoy-device-id>",
                "<decoy-owner-id>",
            )
        } else {
            (&self.seeded, &self.owner, "<device-id>", "<owner-id>")
        };
        assert_eq!(row.id, source.id);
        assert_eq!(row.user_id.as_deref(), Some(owner.id.typed()?.as_str()));
        let mut value = serde_json::to_value(row)?;
        let object = value.as_object_mut().expect("complete Device object");
        let _ = object.insert("id".into(), json!(id));
        let _ = object.insert("userId".into(), json!(owner_id));
        if let Some(polled) = row.last_polled_at {
            assert!(polled.timestamp_millis() >= self.started_at.timestamp_millis());
            assert!(polled.timestamp_millis() <= Utc::now().timestamp_millis());
            assert!(object.get("lastPolledAt").is_some_and(Value::is_string));
            let _ = object.insert("lastPolledAt".into(), json!("<polled-at>"));
        } else {
            assert_eq!(object.get("lastPolledAt"), Some(&Value::Null));
        }
        // JavaScript JSON has one numeric type. Preserve values with JavaScript's integral spelling.
        for key in ["pollingInterval", "revision"] {
            let number = object
                .get(key)
                .and_then(Value::as_f64)
                .expect("declared numeric Device field");
            let _ = object.insert(key.into(), serde_json::from_str(&number.to_string())?);
        }
        Ok(value)
    }

    #[expect(
        clippy::panic_in_result_fn,
        reason = "The contract asserts owner identity while propagating serialization errors."
    )]
    fn user(&self, row: &UserView) -> AuthResult<Value> {
        assert_eq!(row.id, self.owner.id);
        let mut value = serde_json::to_value(row)?;
        let _ = value
            .as_object_mut()
            .expect("complete owner object")
            .insert("id".into(), json!("<owner-id>"));
        Ok(value)
    }

    async fn remaining(&self, store: &dyn DeviceCodeStore) -> AuthResult<Value> {
        let mut remaining = Vec::new();
        for code in [&self.decoy.device_code, &self.seeded.device_code] {
            if let Some(row) = store.get_device_code_by_device_code(code).await? {
                remaining.push(self.device(&row)?);
            }
        }
        Ok(json!(remaining))
    }
}

fn ownership_fields() -> UserConfig {
    UserConfig {
        additional_fields: Some(
            [
                (
                    "tenantKey".into(),
                    UserFieldConfig {
                        field_name: Some("stored_tenant".into()),
                        required: Some(false),
                        ..Default::default()
                    },
                ),
                (
                    "revision".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Number,
                        field_name: Some("stored_revision".into()),
                        required: Some(false),
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        ),
    }
}

fn owner_input(name: &str, email: &str) -> CreateUser {
    let time = "2030-01-01T00:00:00Z"
        .parse::<DateTime<Utc>>()
        .expect("fixed owner timestamp");
    CreateUser {
        name: Some(name.into()).into(),
        email: Some(email.into()),
        email_verified: Some(false),
        image: None.into(),
        created_at: Some(time),
        updated_at: Some(time),
        ..CreateUser::new()
    }
}

fn device_input(
    owner: &UserView,
    prefix: &str,
    scope: &str,
    tenant: &str,
    revision: Value,
) -> AuthResult<CreateDeviceCode> {
    Ok(CreateDeviceCode {
        device_code: format!("{prefix}-device"),
        user_code: format!("{prefix}-user"),
        user_id: Some(owner.id.typed()?.clone()),
        expires_at: "2100-01-01T00:00:00Z".parse().expect("fixed Device expiry"),
        status: "approved".into(),
        last_polled_at: None,
        polling_interval: Some(5000.0),
        client_id: Some(format!("{prefix}-client")),
        scope: Some(scope.into()).into(),
        additional_fields: [
            ("tenantKey".into(), json!(tenant)),
            ("revision".into(), revision),
        ]
        .into_iter()
        .collect(),
    })
}

async fn setup<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    name: &str,
) -> AuthResult<(BetterAuth<S>, Arc<Observation>)> {
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(DeviceAuthorizationPlugin::new())
        .plugin(Fields(vec![(EntityRole::DeviceCode, ownership_fields())]))
        .build()
        .await?;
    let owner = auth
        .store()
        .create_user(owner_input(
            "Device ownership owner",
            "owner@device-ownership.test",
        ))
        .await?;
    let decoy_owner = auth
        .store()
        .create_user(owner_input(
            "Decoy ownership owner",
            "decoy@device-ownership.test",
        ))
        .await?;
    let (decoy_tenant, decoy_revision) = match name {
        "tenant-alias-in-mismatch-after-prepare" | "tenant-not-in-mismatch-after-prepare" => {
            ("tenant-before", json!(2.5))
        }
        "revision-not-in-numeric-strings" => ("tenant-after", json!(4)),
        _ => ("tenant-after", json!(2.5)),
    };
    let decoy = auth
        .store()
        .create_device_code(device_input(
            &decoy_owner,
            "decoy",
            "prepared",
            decoy_tenant,
            decoy_revision,
        )?)
        .await?;
    let seeded = auth
        .store()
        .create_device_code(device_input(
            &owner,
            "ordinary",
            "initial",
            "tenant-before",
            json!(1),
        )?)
        .await?;
    for id in [&owner.id, &decoy_owner.id, &seeded.id, &decoy.id] {
        assert!(!id.typed()?.is_empty());
    }
    assert_ne!(owner.id, decoy_owner.id);
    assert_ne!(seeded.id, decoy.id);
    Ok((
        auth,
        Arc::new(Observation {
            seeded,
            owner,
            decoy,
            decoy_owner,
            started_at: Utc::now(),
            events: Mutex::new(Vec::new()),
            inside_remaining: Mutex::new(None),
        }),
    ))
}

async fn redeem<S: AuthSchema>(
    context: &AuthContext<S>,
    transaction: Option<&dyn AuthTransaction<S>>,
    observation: Arc<Observation>,
    ownership: DeviceCodeOwnership,
    prepared_tenant: Value,
) -> AuthResult<Value> {
    let mut endpoint = EndpointContext::native(None, None, Value::Null, context);
    endpoint.transaction = transaction;
    let store: &dyn DeviceCodeStore = match transaction {
        Some(transaction) => transaction,
        None => context.database.as_ref(),
    };
    let authorize = observation.clone();
    let prepare = observation.clone();
    let result = redeem_device_code(
        &endpoint,
        &observation.seeded.device_code,
        move |row, _| {
            Box::pin(async move {
                authorize
                    .events
                    .lock()
                    .expect("Device trace lock")
                    .push(json!({
                        "type": "authorize", "row": authorize.device(row)?,
                    }));
                Ok(DeviceCodeRedemptionAuthorization {
                    ownership,
                    context: json!({"issuer": "ordinary-issuer"}),
                })
            })
        },
        move |row, authorization, endpoint| {
            Box::pin(async move {
                prepare
                    .events
                    .lock()
                    .expect("Device trace lock")
                    .push(json!({
                        "type": "prepare", "row": prepare.device(row)?,
                        "authorizationContext": authorization,
                    }));
                let store: &dyn DeviceCodeStore = match endpoint.transaction {
                    Some(transaction) => transaction,
                    None => endpoint.auth.database.as_ref(),
                };
                let prepared = store
                    .update_device_code(
                        &row.id,
                        UpdateDeviceCode {
                            scope: Some("prepared".into()).into(),
                            additional_fields: [
                                ("tenantKey".into(), prepared_tenant),
                                ("revision".into(), json!(2.5)),
                            ]
                            .into_iter()
                            .collect(),
                            ..Default::default()
                        },
                    )
                    .await?;
                prepare
                    .events
                    .lock()
                    .expect("Device trace lock")
                    .push(json!({
                        "type": "prepared", "row": prepare.device(&prepared)?,
                    }));
                Ok(json!({"issuedFor": authorization.get("issuer").expect("authorization issuer")}))
            })
        },
    )
    .await;
    let remaining = observation.remaining(store).await?;
    *observation
        .inside_remaining
        .lock()
        .expect("Device remaining lock") = Some(remaining);
    let result = result?;
    Ok(json!({
        "claimedDeviceCode": observation.device(&result.claimed_device_code)?,
        "authorizationContext": result.authorization_context,
        "redemptionContext": result.redemption_context,
        "user": observation.user(&result.user)?,
    }))
}

async fn observe<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>, case: &Case) -> AuthResult<Value> {
    let (auth, observation) = setup(raw, &case.name).await?;
    let before = observation.device(&observation.seeded)?;
    let before_rows = json!([observation.device(&observation.decoy)?, before]);
    let ownership = case.ownership_where.condition();
    let prepared_tenant = if case.name == "tenant-null-not-in" {
        Value::Null
    } else {
        json!("tenant-after")
    };
    let result = if case.mode == "transaction" {
        let context = auth.context().clone();
        let active = observation.clone();
        transaction(auth.store().as_ref(), move |transaction| {
            Box::pin(async move {
                redeem(
                    &context,
                    Some(transaction),
                    active,
                    ownership,
                    prepared_tenant,
                )
                .await
            })
        })
        .await
    } else {
        redeem(
            auth.context(),
            None,
            observation.clone(),
            ownership,
            prepared_tenant,
        )
        .await
    };
    let (result, error) = match result {
        Ok(value) => (value, Value::Null),
        Err(error @ AuthError::Response(_)) => {
            let response = error.to_auth_response();
            assert_eq!(response.status, 400);
            let body: Value = serde_json::from_slice(&response.body)?;
            (
                Value::Null,
                json!({"status": "BAD_REQUEST", "statusCode": response.status, "body": body}),
            )
        }
        Err(error) => return Err(error),
    };
    let remaining = observation.remaining(auth.store().as_ref()).await?;
    Ok(json!({
        "name": case.name, "mode": case.mode,
        "ownershipWhere": case.ownership_where,
        "before": before, "beforeRows": before_rows,
        "events": observation.events.lock().expect("Device trace lock").clone(),
        "result": result, "error": error,
        "insideRemaining": observation.inside_remaining.lock().expect("Device remaining lock")
            .clone().expect("captured transaction state"),
        "remaining": remaining,
    }))
}

fn semantic_observation(mut expected: Value, condition: &OwnershipWhere) -> Value {
    let result = expected.get("result").expect("captured redemption result");
    let consumed = if result.is_null() {
        Value::Null
    } else {
        result
            .get("claimedDeviceCode")
            .expect("captured claimed Device")
            .clone()
    };
    let events = expected
        .get_mut("events")
        .and_then(Value::as_array_mut)
        .expect("complete upstream trace");
    assert_eq!(
        events
            .iter()
            .map(|event| event.get("type").and_then(Value::as_str))
            .collect::<Vec<_>>(),
        [
            Some("authorize"),
            Some("prepare"),
            Some("prepared"),
            Some("consumeOne"),
            Some("consumeOneResult")
        ]
    );
    assert_eq!(
        events.get(3),
        Some(&json!({
            "type": "consumeOne", "input": {"model": "deviceCode", "where": [
                {"field": "id", "value": "<device-id>"},
                condition,
                {"field": "status", "value": "approved"},
            ]},
        }))
    );
    assert_eq!(
        events.get(4),
        Some(&json!({"type": "consumeOneResult", "row": consumed}))
    );
    // Rust exposes typed consumption. Bun checks both adapter-only events against the complete fixture.
    // Preserve every semantic callback, result, error, and storage value in the paired comparison.
    events.truncate(3);
    expected
}

async fn contract(backend: &str) -> AuthResult<()> {
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/device-ownership-set-1.7.6.json"))?;
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
        .expect("selected backend")
        .get("cases")
        .and_then(Value::as_array)
        .expect("captured cases");
    let parsed: Vec<Case> = cases
        .iter()
        .cloned()
        .map(serde_json::from_value)
        .collect::<Result<_, _>>()?;
    assert_eq!(
        parsed
            .iter()
            .map(|case| (case.name.as_str(), case.mode.as_str()))
            .collect::<Vec<_>>(),
        CASES
    );
    for (case, expected) in parsed.iter().zip(cases) {
        let observed = if backend == "memory" {
            observe(memory(), case).await?
        } else {
            let (store, _) = device_fixture::sqlite(config()).await;
            observe(Arc::new(store), case).await?
        };
        assert_eq!(
            observed,
            semantic_observation(expected.clone(), &case.ownership_where),
            "{backend}/{}/{}",
            case.name,
            case.mode
        );
    }
    Ok(())
}

#[tokio::test]
async fn memory_device_ownership_sets_match_upstream() -> AuthResult<()> {
    contract("memory").await
}

#[tokio::test]
async fn sqlite_device_ownership_sets_match_upstream() -> AuthResult<()> {
    contract("sqlite").await
}
