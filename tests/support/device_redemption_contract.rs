use super::contract_chrono as chrono;
use better_auth::{
    __private_core::{
        AuthContext, AuthError, AuthResult, AuthSchema, CreateDeviceCode, FieldValue,
        UpdateDeviceCode,
        store::{AuthTransaction, DeviceCodeStore},
    },
    plugins::{
        device_authorization::{
            DeviceCodeOwnership, DeviceCodeRedemptionAuthorization, redeem_device_code,
        },
        endpoint_context::EndpointContext,
    },
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

fn required<T>(value: Option<T>, context: &str) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal(context))
}

fn trace_lock<T>(trace: &Mutex<T>) -> AuthResult<std::sync::MutexGuard<'_, T>> {
    trace
        .lock()
        .map_err(|_| AuthError::internal("Model field contract trace lock poisoned"))
}

pub(crate) async fn observe<S: AuthSchema>(
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
                "lastPolledAt": result.claimed_device_code.last_polled_at.typed()?.is_some(),
            }),
            Value::Null,
        ),
        Err(AuthError::Internal(message)) => (Value::Null, json!(message)),
        Err(error) => return Err(error),
    };
    let remaining = store.get_device_code_by_device_code(&token).await?;
    let remaining = remaining
        .map(|row| {
            Ok::<_, AuthError>(json!({
                "scope": row.scope,
                "lastPolledAt": row.last_polled_at.typed()?.is_some(),
            }))
        })
        .transpose()?;
    Ok(json!({
        "name": mode,
        "events": *trace_lock(&events)?,
        "result": result,
        "error": error,
        "remaining": remaining,
    }))
}
