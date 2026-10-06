use super::{
    ACCESS_DENIED, AUTHORIZATION_PENDING, DEVICE_STATUS_APPROVED, DEVICE_STATUS_DENIED,
    DEVICE_STATUS_PENDING, EXPIRED_DEVICE_CODE, INVALID_DEVICE_CODE, INVALID_DEVICE_CODE_STATUS,
    POLLING_TOO_FREQUENTLY, USER_NOT_FOUND, device_error_response,
};
use crate::plugins::endpoint_context::EndpointContext;
use better_auth_core::{
    AuthResult, AuthSchema, DeviceCode, DeviceCodeOwnership, UpdateDeviceCode,
    store::DeviceCodeStore, wire::UserView,
};
use chrono::Utc;
use std::{future::Future, pin::Pin};

/// A redemption callback that borrows the device code and active endpoint.
pub type DeviceRedemptionFuture<'a, T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send + 'a>>;

/// The issuer's ownership predicate and state required before token issuance.
pub struct DeviceCodeRedemptionAuthorization<A> {
    /// Additional ownership condition enforced by atomic consumption.
    pub ownership: DeviceCodeOwnership,
    /// Issuer state passed to preparation and returned after consumption.
    pub context: A,
}

/// A consumed device code and the state needed by its token issuer.
pub struct DeviceCodeRedemptionResult<A, R> {
    /// The actual consumed row, including its bound user identifier.
    pub claimed_device_code: DeviceCode,
    /// The state returned by the authorization callback.
    pub authorization_context: A,
    /// The state returned by the preparation callback.
    pub redemption_context: R,
    /// The user projected through the active schema before consumption, including hidden fields.
    pub user: UserView,
}

/// Authorize, prepare, and atomically consume an approved device code.
///
/// Callbacks cannot bypass polling, expiry, denial, or consumption guards.
/// Every database operation uses `endpoint.transaction` when present.
/// Callback errors propagate unchanged; the caller issues credentials only after success.
/// If the caller uses a transaction, issue credentials only after that transaction commits.
pub async fn redeem_device_code<S, A, R, Authorize, Prepare>(
    endpoint: &EndpointContext<'_, S>,
    code: &str,
    authorize: Authorize,
    prepare: Prepare,
) -> AuthResult<DeviceCodeRedemptionResult<A, R>>
where
    S: AuthSchema,
    A: Send + Sync,
    R: Send,
    Authorize: for<'a> FnOnce(
            &'a DeviceCode,
            &'a EndpointContext<'_, S>,
        ) -> DeviceRedemptionFuture<'a, DeviceCodeRedemptionAuthorization<A>>
        + Send,
    Prepare: for<'a> FnOnce(
            &'a DeviceCode,
            &'a A,
            &'a EndpointContext<'_, S>,
        ) -> DeviceRedemptionFuture<'a, R>
        + Send,
{
    let store: &dyn DeviceCodeStore = match endpoint.transaction {
        Some(transaction) => transaction,
        None => endpoint.auth.database.as_ref(),
    };
    let Some(device_code) = store.get_device_code_by_device_code(code).await? else {
        return Err(device_error_response(400, "invalid_grant", INVALID_DEVICE_CODE)?.into());
    };
    let authorization = authorize(&device_code, endpoint).await?;
    if let (Some(last_polled_at), Some(polling_interval)) =
        (device_code.last_polled_at, device_code.polling_interval)
    {
        let elapsed = Utc::now()
            .signed_duration_since(last_polled_at)
            .num_milliseconds();
        if (elapsed as f64) < polling_interval {
            return Err(device_error_response(400, "slow_down", POLLING_TOO_FREQUENTLY)?.into());
        }
    }
    let _ = store
        .update_device_code(
            &device_code.id,
            UpdateDeviceCode {
                last_polled_at: Some(Some(Utc::now())),
                ..Default::default()
            },
        )
        .await?;
    if device_code.expires_at < Utc::now() {
        store.delete_device_code(&device_code.id).await?;
        return Err(device_error_response(400, "expired_token", EXPIRED_DEVICE_CODE)?.into());
    }
    if device_code.status == DEVICE_STATUS_PENDING {
        return Err(
            device_error_response(400, "authorization_pending", AUTHORIZATION_PENDING)?.into(),
        );
    }
    if device_code.status == DEVICE_STATUS_DENIED {
        store.delete_device_code(&device_code.id).await?;
        return Err(device_error_response(400, "access_denied", ACCESS_DENIED)?.into());
    }
    if device_code.status != DEVICE_STATUS_APPROVED {
        return Err(device_error_response(500, "server_error", INVALID_DEVICE_CODE_STATUS)?.into());
    }
    let Some(user_id) = device_code.user_id.as_deref().filter(|id| !id.is_empty()) else {
        return Err(device_error_response(500, "server_error", INVALID_DEVICE_CODE_STATUS)?.into());
    };
    let redemption_context = prepare(&device_code, &authorization.context, endpoint).await?;
    let user = match endpoint.transaction {
        Some(transaction) => transaction.get_user_by_id(user_id).await?,
        None => endpoint.auth.database.get_user_by_id(user_id).await?,
    };
    let Some(user) = user else {
        return Err(device_error_response(500, "server_error", USER_NOT_FOUND)?.into());
    };
    let user = endpoint.auth.internal_user_view(&user).await?;
    let claimed = store
        .consume_device_code(&device_code, &authorization.ownership)
        .await?;
    let Some(claimed_device_code) = claimed.filter(|row| {
        row.user_id
            .as_deref()
            .is_some_and(|user_id| !user_id.is_empty())
    }) else {
        return Err(device_error_response(400, "invalid_grant", INVALID_DEVICE_CODE)?.into());
    };
    Ok(DeviceCodeRedemptionResult {
        claimed_device_code,
        authorization_context: authorization.context,
        redemption_context,
        user,
    })
}
