use super::*;
use better_auth::plugins::{
    DeviceAuthorizationPlugin,
    device_authorization::{
        DeviceCodeOwnership, DeviceCodeRedemptionAuthorization, redeem_device_code,
    },
    endpoint_context::EndpointContext,
};
use better_auth_core::{
    CreateDeviceCode,
    store::{AuthTransaction, transaction},
};

#[path = "../support/device_redemption_contract.rs"]
mod redemption_contract;
use chrono as contract_chrono;
use redemption_contract::observe;

async fn contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>, backend: &str) -> AuthResult<()> {
    let auth = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(DeviceAuthorizationPlugin::new())
        .build()
        .await?;
    let owner = owner(raw.as_ref(), "redemption-owner").await?;
    let mut cases = Vec::new();
    for mode in ["success", "authorization error", "preparation error"] {
        cases.push(observe(auth.context(), None, mode, &owner).await?);
    }
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/device-redemption-1.7.6.json"))?;
    let expected = required(
        fixture.get("backends").and_then(Value::as_array),
        "Expected captured redemption backends",
    )?
    .iter()
    .find(|item| item.get("backend") == Some(&json!(backend)))
    .ok_or_else(|| AuthError::internal("Missing captured redemption backend"))?;
    assert_eq!(
        &json!(cases),
        required(expected.get("cases"), "Expected captured redemption cases")?
    );

    let context = auth.context().clone();
    let observed = transaction(auth.store().as_ref(), move |transaction| {
        Box::pin(async move { observe(&context, Some(transaction), "success", &owner).await })
    })
    .await?;
    assert_eq!(
        &observed,
        required(cases.first(), "Expected the successful redemption case")?
    );
    assert!(
        auth.store()
            .get_device_code_by_device_code("ordinary-device:success")
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn memory_server_device_redemption_matches_upstream() -> AuthResult<()> {
    contract(memory(), "memory").await
}

#[tokio::test]
async fn sqlite_server_device_redemption_matches_upstream() -> AuthResult<()> {
    contract(sqlite().await?, "sqlite").await
}

async fn polling_truthiness_contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    supports_nan: bool,
) -> AuthResult<()> {
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(DeviceAuthorizationPlugin::new())
        .build()
        .await?;
    let owner = owner(auth.store().as_ref(), "polling-owner").await?;
    let intervals = [
        ("zero", 0.0, false),
        ("negative-zero", -0.0, false),
        ("positive", 5000.0, true),
        ("fractional", 1.5, true),
    ];
    let mut intervals = intervals.to_vec();
    if supports_nan {
        intervals.push(("nan", f64::NAN, false));
    }
    for (name, interval, blocks_future) in intervals {
        for future in [false, true] {
            let token = format!("polling-{name}-{future}");
            let started = chrono::Utc::now();
            let last_polled_at = started
                + if future {
                    chrono::Duration::hours(1)
                } else {
                    -chrono::Duration::hours(1)
                };
            let seeded = auth
                .store()
                .create_device_code(CreateDeviceCode {
                    additional_fields: Default::default(),
                    device_code: token.clone(),
                    user_code: token.clone(),
                    user_id: Some(owner.clone()),
                    expires_at: (started + chrono::Duration::hours(2)).into(),
                    status: "approved".into(),
                    last_polled_at: Some(last_polled_at.into()),
                    polling_interval: Some(interval),
                    client_id: Some("ordinary-client".into()),
                    scope: Some("read".into()).into(),
                })
                .await?;
            if interval.is_nan() {
                assert!(seeded.polling_interval.typed()?.is_some_and(f64::is_nan));
            }
            let endpoint = EndpointContext::native(None, None, FieldValue::Null, auth.context());
            let events = Arc::new(Mutex::new(Vec::new()));
            let authorize_events = events.clone();
            let prepare_events = events.clone();
            let result = redeem_device_code(
                &endpoint,
                &token,
                move |row, _| {
                    Box::pin(async move {
                        trace_lock(&authorize_events)?
                            .push(("authorize", row.last_polled_at.clone()));
                        Ok(DeviceCodeRedemptionAuthorization {
                            ownership: DeviceCodeOwnership::ClientId("ordinary-client".into()),
                            context: "issuer",
                        })
                    })
                },
                move |row, authorization, _| {
                    Box::pin(async move {
                        assert_eq!(*authorization, "issuer");
                        trace_lock(&prepare_events)?.push(("prepare", row.last_polled_at.clone()));
                        Ok("prepared")
                    })
                },
            )
            .await;
            let remaining = auth.store().get_device_code_by_device_code(&token).await?;
            if future && blocks_future {
                let response =
                    required(result.err(), "A future poll must be throttled")?.to_auth_response();
                assert_eq!(response.status, 400, "{name}");
                assert_eq!(
                    serde_json::from_slice::<Value>(&response.body.bytes()?)?,
                    json!({"error": "slow_down", "error_description": "Polling too frequently"})
                );
                assert_eq!(
                    *trace_lock(&events)?,
                    [("authorize", seeded.last_polled_at.clone())]
                );
                assert_eq!(remaining, Some(seeded));
            } else {
                let redeemed = result?;
                assert_eq!(redeemed.authorization_context, "issuer");
                assert_eq!(redeemed.redemption_context, "prepared");
                assert_eq!(redeemed.claimed_device_code.id, seeded.id);
                assert_eq!(redeemed.claimed_device_code.user_id, seeded.user_id);
                assert_eq!(redeemed.user.id.typed()?, &owner);
                let polled = required(
                    redeemed.claimed_device_code.last_polled_at.typed()?.clone(),
                    "Expected the poll timestamp",
                )?;
                assert!(polled.milliseconds() >= started.timestamp_millis() as f64);
                assert!(polled.milliseconds() <= chrono::Utc::now().timestamp_millis() as f64);
                assert_eq!(
                    *trace_lock(&events)?,
                    [
                        ("authorize", seeded.last_polled_at.clone()),
                        ("prepare", seeded.last_polled_at),
                    ]
                );
                assert!(remaining.is_none());
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn memory_device_redemption_polling_truthiness_preserves_callbacks_and_consumption()
-> AuthResult<()> {
    polling_truthiness_contract(memory(), true).await
}

#[tokio::test]
async fn sqlite_device_redemption_polling_truthiness_preserves_callbacks_and_consumption()
-> AuthResult<()> {
    polling_truthiness_contract(sqlite().await?, false).await
}

async fn redeemed_user<S: AuthSchema>(
    context: &AuthContext<S>,
    transaction: Option<&dyn AuthTransaction<S>>,
    code: &str,
) -> AuthResult<Value> {
    let mut endpoint = EndpointContext::native(None, None, FieldValue::Null, context);
    endpoint.transaction = transaction;
    let result = redeem_device_code(
        &endpoint,
        code,
        |_, _| {
            Box::pin(async {
                Ok(DeviceCodeRedemptionAuthorization {
                    ownership: DeviceCodeOwnership::ClientId("ordinary-client".into()),
                    context: (),
                })
            })
        },
        |_, _, _| Box::pin(async { Ok(()) }),
    )
    .await?;
    Ok(serde_json::to_value(result.user)?)
}

async fn hidden_user_contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let outputs = Arc::new(Mutex::new(Vec::new()));
    let callback_outputs = outputs.clone();
    let mut config = config();
    config.user = fields(
        "name",
        UserFieldConfig {
            returned: Some(false),
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    trace_lock(&callback_outputs)?.push(value.clone());
                    Ok(match value {
                        FieldValue::Undefined => FieldValue::Undefined,
                        value => format!(
                            "{}:out",
                            required(value.as_str(), "Expected a string field callback value")?
                        )
                        .into(),
                    })
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let auth = BetterAuth::new(config)
        .store_arc(raw)
        .plugin(DeviceAuthorizationPlugin::new())
        .build()
        .await?;
    let created_at: FieldDate = "2030-01-01T00:00:00Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|error| AuthError::internal(format!("Invalid fixture timestamp: {error}")))?
        .into();
    let owner = auth
        .store()
        .create_user(CreateUser {
            created_at: Some(created_at.clone()),
            updated_at: Some(created_at),
            image: None.into(),
            ..CreateUser::new()
                .with_name("Hidden owner")
                .with_email("hidden@device-redemption.test")
        })
        .await?;
    for mode in ["direct", "transaction"] {
        let code = format!("hidden-user:{mode}");
        let _ = auth
            .store()
            .create_device_code(CreateDeviceCode {
                device_code: code.clone(),
                user_code: format!("hidden-user-code:{mode}"),
                user_id: Some(owner.id.typed()?.clone()),
                expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
                status: "approved".into(),
                last_polled_at: None,
                polling_interval: None,
                client_id: Some("ordinary-client".into()),
                scope: Default::default(),
                additional_fields: Default::default(),
            })
            .await?;
        trace_lock(&outputs)?.clear();
        let observed = if mode == "transaction" {
            let context = auth.context().clone();
            transaction(auth.store().as_ref(), move |transaction| {
                Box::pin(async move { redeemed_user(&context, Some(transaction), &code).await })
            })
            .await?
        } else {
            redeemed_user(auth.context(), None, &code).await?
        };
        assert_eq!(
            observed,
            json!({
                "id": owner.id,
                "name": "Hidden owner:out",
                "email": "hidden@device-redemption.test",
                "emailVerified": false,
                "image": null,
                "createdAt": "2030-01-01T00:00:00.000Z",
                "updatedAt": "2030-01-01T00:00:00.000Z",
            }),
            "{mode} redemption must preserve the complete internal user schema"
        );
        assert_eq!(
            *trace_lock(&outputs)?,
            [FieldValue::from("Hidden owner")],
            "{mode} redemption must apply the user output callback once"
        );
    }
    Ok(())
}

#[tokio::test]
async fn memory_device_redemption_preserves_hidden_user_fields_without_repeating_output()
-> AuthResult<()> {
    hidden_user_contract(memory()).await
}

#[tokio::test]
async fn sqlite_device_redemption_preserves_hidden_user_fields_without_repeating_output()
-> AuthResult<()> {
    hidden_user_contract(sqlite().await?).await
}
