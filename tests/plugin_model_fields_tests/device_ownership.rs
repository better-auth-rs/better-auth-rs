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
    user_fields::UserFieldReference,
    wire::UserView,
};
use chrono::{DateTime, Utc};

const CASES: [(&str, &str, &str); 4] = [
    ("tenant-match-after-prepare", "direct", "tenant-after"),
    ("tenant-match-after-prepare", "transaction", "tenant-after"),
    ("tenant-mismatch-after-prepare", "direct", "tenant-before"),
    (
        "tenant-mismatch-after-prepare",
        "transaction",
        "tenant-before",
    ),
];

struct Observation {
    seeded: DeviceCode,
    owner: UserView,
    started_at: DateTime<Utc>,
    events: Mutex<Vec<Value>>,
    inside_remaining: Mutex<Option<Value>>,
}

impl Observation {
    fn device(&self, row: &DeviceCode) -> AuthResult<Value> {
        assert_eq!(row.id, self.seeded.id);
        assert_eq!(
            row.user_id.as_deref(),
            Some(self.owner.id.typed()?.as_str())
        );
        let mut value = serde_json::to_value(row)?;
        value["id"] = json!("<device-id>");
        value["userId"] = json!("<owner-id>");
        value["lastPolledAt"] = match row.last_polled_at {
            Some(polled) => {
                assert!(polled.timestamp_millis() >= self.started_at.timestamp_millis());
                assert!(polled.timestamp_millis() <= Utc::now().timestamp_millis());
                json!("<polled-at>")
            }
            None => Value::Null,
        };
        if let Some(interval) = row.polling_interval {
            // JSON has one numeric type; preserve the value with JavaScript's integral spelling.
            value["pollingInterval"] = serde_json::from_str(&interval.to_string())?;
        }
        Ok(value)
    }

    fn user(&self, row: &UserView) -> AuthResult<Value> {
        assert_eq!(row.id, self.owner.id);
        let mut value = serde_json::to_value(row)?;
        value["id"] = json!("<owner-id>");
        Ok(value)
    }

    async fn remaining(&self, store: &dyn DeviceCodeStore) -> AuthResult<Value> {
        let row = store
            .get_device_code_by_device_code(&self.seeded.device_code)
            .await?;
        Ok(json!(
            row.as_ref()
                .map(|row| self.device(row))
                .transpose()?
                .into_iter()
                .collect::<Vec<_>>()
        ))
    }
}

fn ownership_fields() -> UserConfig {
    fields(
        "tenantKey",
        UserFieldConfig {
            field_name: Some("stored_tenant".into()),
            required: Some(false),
            ..Default::default()
        },
    )
}

async fn setup<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    model_fields: UserConfig,
) -> AuthResult<(BetterAuth<S>, Arc<Observation>)> {
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(DeviceAuthorizationPlugin::new())
        .plugin(Fields(vec![(EntityRole::DeviceCode, model_fields)]))
        .build()
        .await?;
    let owner_time = "2030-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let owner = auth
        .store()
        .create_user(CreateUser {
            name: Some("Device ownership owner".into()).into(),
            email: Some("owner@device-ownership.test".into()),
            email_verified: Some(false),
            image: None.into(),
            created_at: Some(owner_time),
            updated_at: Some(owner_time),
            ..CreateUser::new()
        })
        .await?;
    let seeded = auth
        .store()
        .create_device_code(CreateDeviceCode {
            device_code: "ordinary-device".into(),
            user_code: "ordinary-user".into(),
            user_id: Some(owner.id.typed()?.clone()),
            expires_at: "2100-01-01T00:00:00Z".parse().unwrap(),
            status: "approved".into(),
            last_polled_at: None,
            polling_interval: Some(5000.0),
            client_id: Some("ordinary-client".into()),
            scope: Some("initial".into()).into(),
            additional_fields: [("tenantKey".into(), json!("tenant-before"))].into(),
        })
        .await?;
    assert!(!owner.id.typed()?.is_empty());
    assert!(!seeded.id.typed()?.is_empty());
    Ok((
        auth,
        Arc::new(Observation {
            seeded,
            owner,
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
    target: &'static str,
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
                let visible = authorize.device(row)?;
                authorize.events.lock().unwrap().push(json!({
                    "type": "authorize", "row": visible,
                }));
                Ok(DeviceCodeRedemptionAuthorization {
                    ownership: DeviceCodeOwnership::FieldEquals {
                        field: "tenantKey".into(),
                        value: json!(target),
                    },
                    context: json!({"issuer": "ordinary-issuer"}),
                })
            })
        },
        move |row, authorization, endpoint| {
            Box::pin(async move {
                let visible = prepare.device(row)?;
                prepare.events.lock().unwrap().push(json!({
                    "type": "prepare", "row": visible,
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
                            additional_fields: [("tenantKey".into(), json!("tenant-after"))].into(),
                            ..Default::default()
                        },
                    )
                    .await?;
                let visible = prepare.device(&prepared)?;
                prepare.events.lock().unwrap().push(json!({
                    "type": "prepared", "row": visible,
                }));
                Ok(json!({"issuedFor": authorization["issuer"]}))
            })
        },
    )
    .await;
    let remaining = observation.remaining(store).await?;
    *observation.inside_remaining.lock().unwrap() = Some(remaining);
    let result = result?;
    Ok(json!({
        "claimedDeviceCode": observation.device(&result.claimed_device_code)?,
        "authorizationContext": result.authorization_context,
        "redemptionContext": result.redemption_context,
        "user": observation.user(&result.user)?,
    }))
}

async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
    (name, mode, target): (&'static str, &'static str, &'static str),
) -> AuthResult<()> {
    let (auth, observation) = setup(raw, ownership_fields()).await?;
    let before = observation.device(&observation.seeded)?;
    let result = if mode == "transaction" {
        let context = auth.context().clone();
        let active = observation.clone();
        transaction(auth.store().as_ref(), move |transaction| {
            Box::pin(async move { redeem(&context, Some(transaction), active, target).await })
        })
        .await
    } else {
        redeem(auth.context(), None, observation.clone(), target).await
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
    let observed = json!({
        "name": name, "mode": mode,
        "ownershipWhere": {"field": "tenantKey", "value": target},
        "before": before,
        "events": observation.events.lock().unwrap().clone(),
        "result": result, "error": error,
        "insideRemaining": observation.inside_remaining.lock().unwrap().clone().unwrap(),
        "remaining": remaining,
    });
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/device-ownership-1.7.6.json"))?;
    assert_eq!(fixture["version"], "1.7.6");
    let mut expected = fixture["backends"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["backend"] == backend)
        .unwrap()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == name && item["mode"] == mode)
        .unwrap()
        .clone();
    let events = expected["events"].as_array_mut().unwrap();
    assert_eq!(
        events
            .iter()
            .map(|event| event["type"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "authorize",
            "prepare",
            "prepared",
            "consumeOne",
            "consumeOneResult"
        ]
    );
    // Rust exposes typed consumption. Bun compares both adapter-only events against the complete 14-case fixture.
    // Keep every semantic callback, result, error and storage value in this paired comparison.
    events.truncate(3);
    assert_eq!(observed, expected, "{backend}/{name}/{mode}");
    Ok(())
}

#[tokio::test]
async fn memory_device_ownership_equality_matches_upstream() -> AuthResult<()> {
    for case in CASES {
        contract(memory(), "memory", case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_device_ownership_equality_matches_upstream() -> AuthResult<()> {
    for case in CASES {
        let (store, _) = device_fixture::sqlite(config()).await;
        contract(Arc::new(store), "sqlite", case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn memory_device_ownership_change_before_commit_preserves_external_record() -> AuthResult<()>
{
    let (auth, observation) = setup(memory(), ownership_fields()).await?;
    let context = auth.context().clone();
    let store = auth.store().clone();
    let active = observation.clone();
    let (consumed, consumption) = oneshot::channel();
    let (resume, continuation) = oneshot::channel();
    let pending = tokio::spawn(async move {
        transaction(store.as_ref(), move |transaction| {
            Box::pin(async move {
                let result = redeem(&context, Some(transaction), active, "tenant-after").await?;
                consumed.send(()).unwrap();
                continuation.await.unwrap();
                Ok(result)
            })
        })
        .await
    });
    consumption.await.unwrap();
    assert_eq!(
        observation.inside_remaining.lock().unwrap().as_ref(),
        Some(&json!([]))
    );
    let external = auth
        .store()
        .update_device_code(
            &observation.seeded.id,
            UpdateDeviceCode {
                additional_fields: [("tenantKey".into(), json!("tenant-external"))].into(),
                ..Default::default()
            },
        )
        .await?;
    resume.send(()).unwrap();
    original_error(
        pending.await.unwrap().unwrap_err(),
        "Device code changed before transaction commit",
    );
    let mut expected = observation.device(&observation.seeded)?;
    expected["tenantKey"] = json!("tenant-external");
    assert_eq!(observation.device(&external)?, expected);
    assert_eq!(
        observation.remaining(auth.store().as_ref()).await?,
        json!([expected])
    );
    Ok(())
}

#[tokio::test]
async fn unsupported_device_ownership_conditions_leave_the_entire_record_stored() -> AuthResult<()>
{
    let mut policies = ownership_fields();
    let fields = policies.additional_fields.as_mut().unwrap();
    let _ = fields.insert(
        "activatedAt".into(),
        UserFieldConfig {
            field_type: UserFieldType::Date,
            field_name: Some("stored_activation".into()),
            required: Some(false),
            ..Default::default()
        },
    );
    let _ = fields.insert(
        "referenceKey".into(),
        UserFieldConfig {
            references: Some(UserFieldReference {
                model: "user".into(),
                field: "id".into(),
            }),
            required: Some(false),
            ..Default::default()
        },
    );
    let (auth, observation) = setup(memory(), policies).await?;
    let before = auth
        .store()
        .get_device_code_by_device_code(&observation.seeded.device_code)
        .await?
        .unwrap();
    let unsupported_type = "DeviceCode FieldEquals supports only declared string, number, and boolean fields without references";
    let non_scalar =
        "DeviceCode FieldEquals requires a scalar null, string, number, or boolean value";
    for (field, value, message) in [
        (
            "unregistered",
            json!("tenant-before"),
            "DeviceCode ownership field unregistered is not registered",
        ),
        ("tenantKey", json!(["tenant-before"]), non_scalar),
        ("tenantKey", json!({"value": "tenant-before"}), non_scalar),
        (
            "activatedAt",
            json!("2030-01-01T00:00:00.000Z"),
            unsupported_type,
        ),
        (
            "referenceKey",
            json!(observation.owner.id.typed()?),
            unsupported_type,
        ),
    ] {
        let error = auth
            .store()
            .consume_device_code(
                &before,
                &DeviceCodeOwnership::FieldEquals {
                    field: field.into(),
                    value,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(error, AuthError::Config(ref actual) if actual == message));
        assert_eq!(
            auth.store()
                .get_device_code_by_device_code(&before.device_code)
                .await?,
            Some(before.clone()),
            "Rejected ownership condition {field} must preserve the complete stored record"
        );
    }
    Ok(())
}
