use chrono::{DateTime, Utc};
use rand::{Rng, distributions::Alphanumeric};
use serde::{Deserialize, Serialize};
use validator::Validate;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthUser, AuthVerification};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSession, CreateVerification,
};

use super::StatusResponse;

#[derive(Debug, Clone, better_auth_core::PluginConfig)]
#[plugin(name = "DeviceAuthorizationPlugin")]
pub struct DeviceAuthorizationConfig {
    #[config(default = false)]
    pub enabled: bool,

    #[config(default = "/device".to_string())]
    pub verification_uri: String,

    #[config(default = 5)]
    pub interval: i64,

    #[config(default = 1800)]
    pub expires_in: i64,
}

pub struct DeviceAuthorizationPlugin {
    config: DeviceAuthorizationConfig,
}

better_auth_core::impl_auth_plugin! {
    DeviceAuthorizationPlugin, "device-flow";
    routes {
        post "/device/code" => handle_code, "device_code";
        post "/device/token" => handle_token, "device_token";
        post "/device/approve" => handle_approve, "device_approve";
        post "/device/deny" => handle_deny, "device_deny";
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceAuthorizationRecord {
    device_code: String,
    user_code: String,
    client_id: String,
    scope: Option<String>,
    status: DeviceStatus,
    user_id: Option<String>,
    expires_at: DateTime<Utc>,
    last_polled_at: Option<DateTime<Utc>>,
    interval: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum DeviceStatus {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredVerification {
    code: String,
    data: DeviceAuthorizationRecord,
}

#[derive(Debug, Deserialize, Validate)]
struct DeviceCodeRequest {
    #[validate(length(min = 1))]
    client_id: String,
    scope: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
struct DeviceTokenRequest {
    device_code: String,
}

#[derive(Debug, Deserialize, Validate)]
struct ApproveRequest {
    #[serde(rename = "userCode")]
    user_code: String,
}

#[derive(Debug, Serialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: i64,
    interval: i64,
}

#[derive(Debug, Serialize)]
struct DeviceTokenResponse {
    access_token: String,
}

fn device_code_identifier(device_code: &str) -> String {
    format!("device_code:{device_code}")
}

fn user_code_identifier(user_code: &str) -> String {
    format!("user_code:{user_code}")
}

async fn store_device_authorization<DB: DatabaseAdapter>(
    identifier: String,
    stored: &StoredVerification,
    ctx: &AuthContext<DB>,
) -> AuthResult<()> {
    ctx.database
        .create_verification(CreateVerification {
            identifier,
            value: serde_json::to_string(stored)?,
            expires_at: stored.data.expires_at,
        })
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Core functions — framework-agnostic business logic
// ---------------------------------------------------------------------------

async fn create_device_code_core<DB: DatabaseAdapter>(
    client_id: String,
    scope: Option<String>,
    ctx: &AuthContext<DB>,
    config: &DeviceAuthorizationConfig,
) -> AuthResult<DeviceCodeResponse> {
    let device_code: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(40)
        .map(char::from)
        .collect();

    let user_code: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect::<String>()
        .to_uppercase();

    let expires_at = Utc::now() + chrono::Duration::seconds(config.expires_in);
    let stored = StoredVerification {
        code: user_code.clone(),
        data: DeviceAuthorizationRecord {
            device_code: device_code.clone(),
            user_code: user_code.clone(),
            client_id,
            scope,
            status: DeviceStatus::Pending,
            user_id: None,
            expires_at,
            last_polled_at: None,
            interval: config.interval,
        },
    };

    store_device_authorization(device_code_identifier(&device_code), &stored, ctx).await?;
    store_device_authorization(user_code_identifier(&user_code), &stored, ctx).await?;

    Ok(DeviceCodeResponse {
        device_code,
        user_code,
        verification_uri: config.verification_uri.clone(),
        expires_in: config.expires_in,
        interval: config.interval,
    })
}

async fn poll_device_token_core<DB: DatabaseAdapter>(
    device_code: String,
    ctx: &AuthContext<DB>,
) -> AuthResult<DeviceTokenResponse> {
    let identifier = device_code_identifier(&device_code);
    let verification = ctx
        .database
        .get_verification_by_identifier(&identifier)
        .await?
        .ok_or_else(|| AuthError::bad_request("invalid_grant"))?;

    let verification_id = verification.id().to_string();
    let raw_value = verification.value().to_string();
    let mut stored: StoredVerification = serde_json::from_str(&raw_value)?;

    match stored.data.status {
        DeviceStatus::Pending => {
            let now = Utc::now();
            if let Some(last) = stored.data.last_polled_at
                && (now - last).num_seconds() < stored.data.interval
            {
                return Err(AuthError::bad_request("slow_down"));
            }

            stored.data.last_polled_at = Some(now);
            ctx.database.delete_verification(&verification_id).await?;
            store_device_authorization(identifier, &stored, ctx).await?;

            Err(AuthError::bad_request("authorization_pending"))
        }
        DeviceStatus::Denied => Err(AuthError::bad_request("access_denied")),
        DeviceStatus::Approved => {
            // Atomically consume to prevent double-redemption from concurrent polls
            if ctx
                .database
                .consume_verification(&identifier, &raw_value)
                .await?
                .is_none()
            {
                return Err(AuthError::bad_request("invalid_grant"));
            }

            let user_id =
                stored.data.user_id.clone().ok_or_else(|| {
                    AuthError::internal("Device authorization missing approved user")
                })?;

            let user = ctx
                .database
                .get_user_by_id(&user_id)
                .await?
                .ok_or_else(|| AuthError::internal("User not found"))?;

            let session = ctx
                .session_manager()
                .create_session(&user, None, None)
                .await?;

            Ok(DeviceTokenResponse {
                access_token: session.token().to_string(),
            })
        }
    }
}

async fn approve_device_core<DB: DatabaseAdapter>(
    user: &DB::User,
    user_code: &str,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusResponse> {
    let verification = ctx
        .database
        .get_verification_by_identifier(&user_code_identifier(user_code))
        .await?
        .ok_or_else(|| AuthError::not_found("Invalid code"))?;

    let verification_id = verification.id().to_string();
    let mut stored: StoredVerification = serde_json::from_str(verification.value())?;

    stored.data.status = DeviceStatus::Approved;
    stored.data.user_id = Some(user.id().to_string());

    let device_identifier = device_code_identifier(&stored.data.device_code);
    if let Some(device_verification) = ctx
        .database
        .get_verification_by_identifier(&device_identifier)
        .await?
    {
        ctx.database
            .delete_verification(device_verification.id())
            .await?;
    }

    ctx.database.delete_verification(&verification_id).await?;
    store_device_authorization(device_identifier, &stored, ctx).await?;

    Ok(StatusResponse { status: true })
}

async fn deny_device_core<DB: DatabaseAdapter>(
    user_code: &str,
    ctx: &AuthContext<DB>,
) -> AuthResult<StatusResponse> {
    let verification = ctx
        .database
        .get_verification_by_identifier(&user_code_identifier(user_code))
        .await?
        .ok_or_else(|| AuthError::not_found("Invalid code"))?;

    let verification_id = verification.id().to_string();
    let mut stored: StoredVerification = serde_json::from_str(verification.value())?;

    stored.data.status = DeviceStatus::Denied;

    let device_identifier = device_code_identifier(&stored.data.device_code);
    if let Some(device_verification) = ctx
        .database
        .get_verification_by_identifier(&device_identifier)
        .await?
    {
        ctx.database
            .delete_verification(device_verification.id())
            .await?;
    }

    ctx.database.delete_verification(&verification_id).await?;
    store_device_authorization(device_identifier, &stored, ctx).await?;

    Ok(StatusResponse { status: true })
}

// ---------------------------------------------------------------------------
// Old handler methods — delegate to core functions
// ---------------------------------------------------------------------------

impl DeviceAuthorizationPlugin {
    async fn handle_code<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        if !self.config.enabled {
            return Err(AuthError::not_found("Not found"));
        }

        let body: DeviceCodeRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let resp = create_device_code_core(body.client_id, body.scope, ctx, &self.config).await?;

        Ok(AuthResponse::json(200, &resp)?)
    }

    async fn handle_token<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        if !self.config.enabled {
            return Err(AuthError::not_found("Not found"));
        }

        let body: DeviceTokenRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let resp = poll_device_token_core(body.device_code, ctx).await?;

        Ok(AuthResponse::json(200, &resp)?)
    }

    async fn handle_approve<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        if !self.config.enabled {
            return Err(AuthError::not_found("Not found"));
        }

        let (user, _) = ctx.require_session(req).await?;

        let body: ApproveRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let resp = approve_device_core(&user, &body.user_code, ctx).await?;

        Ok(AuthResponse::json(200, &resp)?)
    }

    async fn handle_deny<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        if !self.config.enabled {
            return Err(AuthError::not_found("Not found"));
        }

        let _ = ctx.require_session(req).await?;

        let body: ApproveRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let resp = deny_device_core(&body.user_code, ctx).await?;

        Ok(AuthResponse::json(200, &resp)?)
    }
}
