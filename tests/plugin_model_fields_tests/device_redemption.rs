use super::*;
use better_auth::plugins::{
    DeviceAuthorizationPlugin,
    device_authorization::{
        DeviceCodeOwnership, DeviceCodeRedemptionAuthorization, redeem_device_code,
    },
    endpoint_context::EndpointContext,
};
use better_auth_core::{
    CreateDeviceCode, UpdateDeviceCode,
    store::{AuthTransaction, DeviceCodeStore, transaction},
};

async fn observe<S: AuthSchema>(
    ctx: &AuthContext<S>,
    transaction: Option<&dyn AuthTransaction<S>>,
    mode: &'static str,
    owner: &str,
) -> AuthResult<Value> {
    let mut endpoint = EndpointContext::native(None, None, FieldValue::Null, ctx);
    endpoint.transaction = transaction;
    let store: &dyn DeviceCodeStore = match transaction {
        Some(transaction) => transaction,
        None => ctx.database.as_ref(),
    };
    let token = format!("ordinary-device:{mode}");
    let _ = store
        .create_device_code(CreateDeviceCode {
            additional_fields: Default::default(),
            device_code: token.clone(),
            user_code: format!("ordinary-user:{mode}"),
            user_id: Some(owner.into()),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
            status: "approved".into(),
            last_polled_at: None,
            polling_interval: None,
            client_id: Some("ordinary-client".into()),
            scope: Some("initial".into()).into(),
        })
        .await?;
    let events = Arc::new(Mutex::new(Vec::new()));
    let authorize_events = events.clone();
    let prepare_events = events.clone();
    let result = redeem_device_code(
        &endpoint,
        &token,
        move |row, _endpoint| {
            Box::pin(async move {
                trace_lock(&authorize_events)?.push(format!(
                    "authorize:{}",
                    required(
                        row.scope.typed()?.as_deref(),
                        "Expected the authorization scope"
                    )?
                ));
                if mode == "authorization error" {
                    return Err(AuthError::internal("ordinary authorization error"));
                }
                Ok(DeviceCodeRedemptionAuthorization {
                    ownership: DeviceCodeOwnership::ClientId("ordinary-client".into()),
                    context: "issuer".to_owned(),
                })
            })
        },
        move |row, authorization, endpoint| {
            Box::pin(async move {
                trace_lock(&prepare_events)?.push(format!(
                    "prepare:{}:{authorization}",
                    required(
                        row.scope.typed()?.as_deref(),
                        "Expected the preparation scope"
                    )?
                ));
                if mode == "preparation error" {
                    return Err(AuthError::internal("ordinary preparation error"));
                }
                let store: &dyn DeviceCodeStore = match endpoint.transaction {
                    Some(transaction) => transaction,
                    None => endpoint.auth.database.as_ref(),
                };
                let _ = store
                    .update_device_code(
                        &row.id,
                        UpdateDeviceCode {
                            scope: Some("prepared".into()).into(),
                            ..Default::default()
                        },
                    )
                    .await?;
                Ok(format!("issued:{authorization}"))
            })
        },
    )
    .await;
    let (result, error) = match result {
        Ok(result) => (
            json!({
                "scope": result.claimed_device_code.scope.typed()?,
                "authorizationContext": result.authorization_context,
                "redemptionContext": result.redemption_context,
                "userFound": result.user.id.typed()? == owner,
                "lastPolledAt": result.claimed_device_code.last_polled_at.is_some(),
            }),
            Value::Null,
        ),
        Err(AuthError::Internal(message)) => (Value::Null, json!(message)),
        Err(error) => return Err(error),
    };
    let remaining = store.get_device_code_by_device_code(&token).await?;
    Ok(json!({
        "name": mode,
        "events": *trace_lock(&events)?,
        "result": result,
        "error": error,
        "remaining": remaining.map(|row| json!({
            "scope": row.scope,
            "lastPolledAt": row.last_polled_at.is_some(),
        })),
    }))
}

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
