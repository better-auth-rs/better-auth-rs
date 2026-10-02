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
    let mut endpoint = EndpointContext::native(None, None, Value::Null, ctx);
    endpoint.transaction = transaction;
    let store: &dyn DeviceCodeStore = match transaction {
        Some(transaction) => transaction,
        None => ctx.database.as_ref(),
    };
    let token = format!("ordinary-device:{mode}");
    let _ = store
        .create_device_code(CreateDeviceCode {
            device_code: token.clone(),
            user_code: format!("ordinary-user:{mode}"),
            user_id: Some(owner.into()),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
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
                authorize_events.lock().unwrap().push(format!(
                    "authorize:{}",
                    row.scope.typed()?.as_deref().unwrap()
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
                prepare_events.lock().unwrap().push(format!(
                    "prepare:{}:{authorization}",
                    row.scope.typed()?.as_deref().unwrap()
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
        "events": *events.lock().unwrap(),
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
    let expected = fixture["backends"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["backend"] == backend)
        .unwrap();
    assert_eq!(json!(cases), expected["cases"]);

    let context = auth.context().clone();
    let observed = transaction(auth.store().as_ref(), move |transaction| {
        Box::pin(async move { observe(&context, Some(transaction), "success", &owner).await })
    })
    .await?;
    assert_eq!(observed, cases[0]);
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
