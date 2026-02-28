use std::collections::HashMap;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::{AuthContext, AuthResult, CreateApiKey, UpdateApiKey};

use super::types::*;
use super::ApiKeyPlugin;
use crate::plugins::helpers;

// ---------------------------------------------------------------------------
// Permissions verification helper (RBAC)
// ---------------------------------------------------------------------------

/// Check whether `key_permissions` (JSON object mapping role->actions) covers
/// all of the `required_permissions`.
///
/// Mirrors the TypeScript `role(apiKeyPermissions).authorize(permissions)`
/// implementation. Required actions must be a subset of the API key's actions
/// for each resource/role.
pub(super) fn check_permissions(key_permissions_json: &str, required: &serde_json::Value) -> bool {
    let required_map = match required.as_object() {
        Some(m) => m,
        None => return false,
    };

    let key_map: HashMap<String, Vec<String>> = match serde_json::from_str(key_permissions_json) {
        Ok(v) => v,
        Err(_) => return false,
    };

    for (resource, requested_actions) in required_map {
        // Look up the allowed actions for this resource
        let allowed_actions = match key_map.get(resource) {
            Some(a) => a,
            // Resource not found in key permissions -> fail (matches TS behavior)
            None => return false,
        };

        // The request value can be:
        // 1. An array of action strings -> all must be allowed (AND)
        // 2. An object { actions: [...], connector: "OR"|"AND" }
        if let Some(actions_array) = requested_actions.as_array() {
            // Simple array -> every requested action must exist in allowed actions
            for action_val in actions_array {
                let action = match action_val.as_str() {
                    Some(s) => s,
                    None => return false,
                };
                if !allowed_actions.iter().any(|a| a == action) {
                    return false;
                }
            }
        } else if let Some(obj) = requested_actions.as_object() {
            // Object form: { actions: [...], connector: "OR" | "AND" }
            let actions = match obj.get("actions").and_then(|v| v.as_array()) {
                Some(a) => a,
                None => return false,
            };
            let connector = obj
                .get("connector")
                .and_then(|v| v.as_str())
                .unwrap_or("AND");

            if connector == "OR" {
                // At least one requested action must be allowed
                let any_allowed = actions.iter().any(|action_val| {
                    action_val
                        .as_str()
                        .is_some_and(|action| allowed_actions.iter().any(|a| a == action))
                });
                if !any_allowed {
                    return false;
                }
            } else {
                // AND (default): every requested action must be allowed
                for action_val in actions {
                    let action = match action_val.as_str() {
                        Some(s) => s,
                        None => return false,
                    };
                    if !allowed_actions.iter().any(|a| a == action) {
                        return false;
                    }
                }
            }
        } else {
            // Invalid format
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Core functions -- framework-agnostic business logic
// ---------------------------------------------------------------------------

pub(crate) async fn create_key_core<DB: DatabaseAdapter>(
    body: &CreateKeyRequest,
    user_id: &str,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<DB>,
) -> AuthResult<CreateKeyResponse> {
    // Validations
    plugin.validate_prefix(body.prefix.as_deref())?;
    plugin.validate_name(body.name.as_deref(), true)?;
    plugin.validate_metadata(&body.metadata)?;
    ApiKeyPlugin::validate_refill(body.refill_interval, body.refill_amount)?;

    let effective_expires_in = plugin.validate_expires_in(body.expires_in)?;

    let (full_key, hash, start) = plugin.generate_key(body.prefix.as_deref());

    let expires_at = helpers::expires_in_to_at(effective_expires_in)?;

    let remaining = body.remaining.or(plugin.config.default_remaining);

    let store_start = if plugin.config.store_starting_characters {
        Some(start)
    } else {
        None
    };

    let input = CreateApiKey {
        user_id: user_id.to_string(),
        name: body.name.clone(),
        prefix: body.prefix.clone().or_else(|| plugin.config.prefix.clone()),
        key_hash: hash,
        start: store_start,
        expires_at,
        remaining,
        rate_limit_enabled: body.rate_limit_enabled.unwrap_or(false),
        rate_limit_time_window: body.rate_limit_time_window,
        rate_limit_max: body.rate_limit_max,
        refill_interval: body.refill_interval,
        refill_amount: body.refill_amount,
        permissions: body
            .permissions
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default()),
        metadata: body
            .metadata
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default()),
        enabled: true,
    };

    let api_key = ctx.database.create_api_key(input).await?;

    // Throttled cleanup
    plugin.maybe_delete_expired(ctx).await;

    Ok(CreateKeyResponse {
        key: full_key,
        api_key: ApiKeyView::from_entity(&api_key),
    })
}

pub(crate) async fn get_key_core<DB: DatabaseAdapter>(
    id: &str,
    user_id: &str,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<DB>,
) -> AuthResult<ApiKeyView> {
    let api_key = helpers::get_owned_api_key(ctx, id, user_id).await?;
    plugin.maybe_delete_expired(ctx).await;
    Ok(ApiKeyView::from_entity(&api_key))
}

pub(crate) async fn list_keys_core<DB: DatabaseAdapter>(
    user_id: &str,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<DB>,
) -> AuthResult<Vec<ApiKeyView>> {
    let keys = ctx.database.list_api_keys_by_user(user_id).await?;
    let views: Vec<ApiKeyView> = keys.iter().map(ApiKeyView::from_entity).collect();
    plugin.maybe_delete_expired(ctx).await;
    Ok(views)
}

pub(crate) async fn update_key_core<DB: DatabaseAdapter>(
    body: &UpdateKeyRequest,
    user_id: &str,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<DB>,
) -> AuthResult<ApiKeyView> {
    // Validations
    plugin.validate_name(body.name.as_deref(), false)?;
    plugin.validate_metadata(&body.metadata)?;
    ApiKeyPlugin::validate_refill(body.refill_interval, body.refill_amount)?;

    // Ownership check via shared helper
    let _existing = helpers::get_owned_api_key(ctx, &body.id, user_id).await?;

    // Build expires_at if expiresIn is provided
    let expires_at = if let Some(ms) = body.expires_in {
        let effective_ms = plugin.validate_expires_in(Some(ms))?;
        helpers::expires_in_to_at(effective_ms)?.map(Some)
    } else {
        None
    };

    let update = UpdateApiKey {
        name: body.name.clone(),
        enabled: body.enabled,
        remaining: body.remaining,
        rate_limit_enabled: body.rate_limit_enabled,
        rate_limit_time_window: body.rate_limit_time_window,
        rate_limit_max: body.rate_limit_max,
        refill_interval: body.refill_interval,
        refill_amount: body.refill_amount,
        permissions: body
            .permissions
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default()),
        metadata: body
            .metadata
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default()),
        expires_at,
        last_request: None,
        request_count: None,
        last_refill_at: None,
    };

    let updated = ctx.database.update_api_key(&body.id, update).await?;

    // Invalidate cached rate limiter if rate limit settings changed
    if body.rate_limit_time_window.is_some()
        || body.rate_limit_max.is_some()
        || body.rate_limit_enabled.is_some()
    {
        plugin
            .rate_limiters
            .lock()
            .expect("rate_limiters mutex poisoned")
            .remove(&body.id);
    }

    plugin.maybe_delete_expired(ctx).await;

    Ok(ApiKeyView::from_entity(&updated))
}

pub(crate) async fn delete_key_core<DB: DatabaseAdapter>(
    body: &DeleteKeyRequest,
    user_id: &str,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<DB>,
) -> AuthResult<serde_json::Value> {
    // Ownership check via shared helper
    let _existing = helpers::get_owned_api_key(ctx, &body.id, user_id).await?;

    ctx.database.delete_api_key(&body.id).await?;

    // Evict cached rate limiter for the deleted key
    plugin
        .rate_limiters
        .lock()
        .expect("rate_limiters mutex poisoned")
        .remove(&body.id);

    Ok(serde_json::json!({ "status": true }))
}

pub(crate) async fn verify_key_core<DB: DatabaseAdapter>(
    body: &VerifyKeyRequest,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<DB>,
) -> AuthResult<VerifyKeyResponse> {
    let result = plugin
        .validate_api_key(ctx, &body.key, body.permissions.as_ref())
        .await;

    match result {
        Ok(view) => Ok(VerifyKeyResponse {
            valid: true,
            error: None,
            key: Some(view),
        }),
        Err(validation_err) => {
            let code_str = validation_err.code.as_str().to_string();
            let message = validation_err.message;
            Ok(VerifyKeyResponse {
                valid: false,
                error: Some(VerifyErrorBody {
                    message,
                    code: code_str,
                }),
                key: None,
            })
        }
    }
}

pub(crate) async fn delete_all_expired_core<DB: DatabaseAdapter>(
    _user_id: &str,
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<DB>,
) -> AuthResult<serde_json::Value> {
    let count = ctx.database.delete_expired_api_keys().await?;

    // Best-effort eviction: clear all cached limiters when bulk-deleting.
    if count > 0 {
        plugin
            .rate_limiters
            .lock()
            .expect("rate_limiters mutex poisoned")
            .clear();
    }

    Ok(serde_json::json!({ "deleted": count }))
}
